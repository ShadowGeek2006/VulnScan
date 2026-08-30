"""
Scan-related API routes.
"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, HttpUrl

from backend.scanners.headers import audit_headers
from backend.scanners.tls import audit_tls

router = APIRouter(prefix="/api", tags=["scan"])


class ScanRequest(BaseModel):
    url: HttpUrl


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
        "checks": [
            {
                "header": c.header,
                "status": c.status.value,
                "points_earned": c.points_earned,
                "points_possible": c.points_possible,
                "detail": c.detail,
            }
            for c in result.checks
        ],
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
        "checks": [
            {
                "header": c.header,
                "status": c.status.value,
                "points_earned": c.points_earned,
                "points_possible": c.points_possible,
                "detail": c.detail,
            }
            for c in result.checks
        ],
    }
