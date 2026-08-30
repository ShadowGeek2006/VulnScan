"""
Scan-related API routes.
"""
import asyncio
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, HttpUrl

from backend.scanners.headers import audit_headers
from backend.scanners.tls import audit_tls
from backend.core.scoring import compute_overall_score

router = APIRouter(prefix="/api", tags=["scan"])


class ScanRequest(BaseModel):
    url: HttpUrl


def _serialize_checks(checks):
    return [
        {
            "header": c.header,
            "status": c.status.value,
            "points_earned": c.points_earned,
            "points_possible": c.points_possible,
            "detail": c.detail,
        }
        for c in checks
    ]


@router.post("/scan/headers")
async def scan_headers(req: ScanRequest):
    result = await audit_headers(str(req.url))
    if result.error:
        raise HTTPException(status_code=400, detail=result.error)
    return {
        "url": result.url,
        "final_url": result.final_url,
        "score_percentage": result.percentage,
        "points_earned": result.total_earned,
        "points_possible": result.total_possible,
        "checks": _serialize_checks(result.checks),
    }


@router.post("/scan/tls")
def scan_tls(req: ScanRequest):
    result = audit_tls(str(req.url))
    if result.error:
        raise HTTPException(status_code=400, detail=result.error)
    return {
        "hostname": result.hostname,
        "port": result.port,
        "score_percentage": result.percentage,
        "points_earned": result.total_earned,
        "points_possible": result.total_possible,
        "checks": _serialize_checks(result.checks),
    }


@router.post("/scan/full")
async def scan_full(req: ScanRequest):
    """
    Runs the header audit and TLS audit together, then computes an overall
    weighted grade. If one scanner fails (e.g. TLS unreachable because the
    site is HTTP-only), the other still contributes and weights renormalize.
    """
    url_str = str(req.url)

    # Header scan is async (httpx), TLS scan is sync (blocking socket calls) —
    # run TLS in a thread so it doesn't block the event loop.
    headers_task = audit_headers(url_str)
    tls_task = asyncio.to_thread(audit_tls, url_str)
    header_result, tls_result = await asyncio.gather(headers_task, tls_task)

    category_results = {}
    errors = {}

    if header_result.error:
        errors["headers"] = header_result.error
    else:
        category_results["headers"] = header_result

    if tls_result.error:
        errors["tls"] = tls_result.error
    else:
        category_results["tls"] = tls_result

    if not category_results:
        raise HTTPException(
            status_code=400,
            detail=f"All scans failed. headers: {errors.get('headers')}, tls: {errors.get('tls')}",
        )

    overall = compute_overall_score(url_str, category_results, errors=errors)

    response = {
        "target": overall.target,
        "grade": overall.grade,
        "weighted_percentage": overall.weighted_percentage,
        "categories": [
            {"name": c.name, "percentage": c.percentage, "weight": round(c.weight, 2)}
            for c in overall.categories
        ],
        "errors": overall.errors,
    }

    if "headers" in category_results:
        response["headers"] = {
            "final_url": header_result.final_url,
            "score_percentage": header_result.percentage,
            "checks": _serialize_checks(header_result.checks),
        }
    if "tls" in category_results:
        response["tls"] = {
            "hostname": tls_result.hostname,
            "score_percentage": tls_result.percentage,
            "checks": _serialize_checks(tls_result.checks),
        }

    return response