"""
HTTP Security Header Scanner

Fetches response headers from a target URL and evaluates them against
known security best practices. Each header is scored independently;
the scoring engine (core/scoring.py) aggregates these into an overall grade.

Reference points:
- Mozilla Observatory header scoring: https://github.com/mozilla/http-observatory
- OWASP Secure Headers Project
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import httpx


class Status(str, Enum):
    PASS = "pass"          # header present and well-configured
    WARN = "warn"          # header present but weakly configured
    FAIL = "fail"          # header missing entirely
    NOT_APPLICABLE = "n/a"  # check doesn't apply to this response


@dataclass
class HeaderCheckResult:
    header: str
    status: Status
    points_earned: float
    points_possible: float
    detail: str


@dataclass
class HeaderAuditResult:
    url: str
    final_url: str
    checks: list = field(default_factory=list)
    error: Optional[str] = None

    @property
    def total_earned(self) -> float:
        return sum(c.points_earned for c in self.checks)

    @property
    def total_possible(self) -> float:
        return sum(c.points_possible for c in self.checks)

    @property
    def percentage(self) -> float:
        if self.total_possible == 0:
            return 0.0
        return round((self.total_earned / self.total_possible) * 100, 1)


# Each entry: (header name, max points, evaluator function)
# Evaluator receives the raw header value (or None) and returns (Status, points_earned, detail)

def _eval_hsts(value: Optional[str]):
    if value is None:
        return Status.FAIL, 0, "Missing. Without HSTS, browsers may downgrade to plain HTTP, exposing traffic to interception."
    max_age = 0
    for part in value.split(";"):
        part = part.strip()
        if part.lower().startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                pass
    if max_age >= 31536000:  # 1 year
        return Status.PASS, 15, f"Present with max-age={max_age} (>=1 year). Good."
    elif max_age > 0:
        return Status.WARN, 8, f"Present but max-age={max_age} is short. Recommend >= 31536000 (1 year)."
    else:
        return Status.WARN, 5, "Present but max-age is missing or zero, which defeats the purpose."


def _eval_csp(value: Optional[str]):
    if value is None:
        return Status.FAIL, 0, "Missing. CSP is the strongest defense against XSS and data injection attacks."
    lowered = value.lower()
    if "unsafe-inline" in lowered or "unsafe-eval" in lowered:
        return Status.WARN, 10, "Present but allows 'unsafe-inline' or 'unsafe-eval', which significantly weakens XSS protection."
    if "default-src" in lowered or "script-src" in lowered:
        return Status.PASS, 20, "Present with restrictive source directives. Good."
    return Status.WARN, 10, "Present but appears permissive or incomplete."


def _eval_x_content_type_options(value: Optional[str]):
    if value is None:
        return Status.FAIL, 0, "Missing. Without this, browsers may MIME-sniff responses, enabling certain injection attacks."
    if value.strip().lower() == "nosniff":
        return Status.PASS, 8, "Present and correctly set to 'nosniff'."
    return Status.WARN, 3, f"Present but value '{value}' is non-standard; expected 'nosniff'."


def _eval_x_frame_options(value: Optional[str], csp_value: Optional[str]):
    # Modern CSP frame-ancestors supersedes X-Frame-Options
    if csp_value and "frame-ancestors" in csp_value.lower():
        return Status.PASS, 8, "Clickjacking protection handled via CSP 'frame-ancestors' (modern approach)."
    if value is None:
        return Status.FAIL, 0, "Missing. Site may be vulnerable to clickjacking via iframe embedding."
    if value.strip().upper() in ("DENY", "SAMEORIGIN"):
        return Status.PASS, 8, f"Present and set to '{value.strip()}'."
    return Status.WARN, 3, f"Present but value '{value}' is unusual."


def _eval_referrer_policy(value: Optional[str]):
    safe_values = {
        "no-referrer", "strict-origin", "strict-origin-when-cross-origin",
        "same-origin", "no-referrer-when-downgrade",
    }
    if value is None:
        return Status.WARN, 3, "Missing. Browser default is generally acceptable but explicit policy is better practice."
    if value.strip().lower() in safe_values:
        return Status.PASS, 7, f"Present and set to a privacy-conscious value: '{value.strip()}'."
    return Status.WARN, 4, f"Present but '{value}' may leak more referrer data than necessary."


def _eval_permissions_policy(value: Optional[str]):
    if value is None:
        return Status.WARN, 2, "Missing. Not critical, but restricting browser features (camera, geolocation, etc.) is good hygiene."
    return Status.PASS, 5, "Present, restricting browser feature access."


def _eval_cookies(set_cookie_headers: list):
    if not set_cookie_headers:
        return Status.NOT_APPLICABLE, 0, 0, "No cookies set by this response."
    total_points = 0
    max_points = len(set_cookie_headers) * 9  # 3 pts each for Secure/HttpOnly/SameSite
    issues = []
    for cookie in set_cookie_headers:
        lowered = cookie.lower()
        name = cookie.split("=", 1)[0]
        if "secure" in lowered:
            total_points += 3
        else:
            issues.append(f"'{name}' missing Secure flag")
        if "httponly" in lowered:
            total_points += 3
        else:
            issues.append(f"'{name}' missing HttpOnly flag")
        if "samesite" in lowered:
            total_points += 3
        else:
            issues.append(f"'{name}' missing SameSite attribute")
    status = Status.PASS if not issues else (Status.WARN if total_points > 0 else Status.FAIL)
    detail = "All cookies properly flagged." if not issues else "Issues: " + "; ".join(issues)
    return status, total_points, max_points, detail


async def audit_headers(url: str, timeout: float = 10.0) -> HeaderAuditResult:
    """
    Fetch the given URL and run the full header security audit.
    Follows redirects (so http:// -> https:// upgrades are captured correctly).
    """
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, verify=True) as client:
        try:
            resp = await client.get(url, headers={"User-Agent": "VulnScope/0.1 (+security-audit-tool)"})
        except httpx.RequestError as e:
            return HeaderAuditResult(url=url, final_url=url, error=f"Request failed: {e}")

    h = resp.headers  # case-insensitive dict
    result = HeaderAuditResult(url=url, final_url=str(resp.url))

    status, pts, detail = _eval_hsts(h.get("strict-transport-security"))
    result.checks.append(HeaderCheckResult("Strict-Transport-Security", status, pts, 15, detail))

    csp_value = h.get("content-security-policy")
    status, pts, detail = _eval_csp(csp_value)
    result.checks.append(HeaderCheckResult("Content-Security-Policy", status, pts, 20, detail))

    status, pts, detail = _eval_x_content_type_options(h.get("x-content-type-options"))
    result.checks.append(HeaderCheckResult("X-Content-Type-Options", status, pts, 8, detail))

    status, pts, detail = _eval_x_frame_options(h.get("x-frame-options"), csp_value)
    result.checks.append(HeaderCheckResult("X-Frame-Options", status, pts, 8, detail))

    status, pts, detail = _eval_referrer_policy(h.get("referrer-policy"))
    result.checks.append(HeaderCheckResult("Referrer-Policy", status, pts, 7, detail))

    status, pts, detail = _eval_permissions_policy(h.get("permissions-policy"))
    result.checks.append(HeaderCheckResult("Permissions-Policy", status, pts, 5, detail))

    set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(h, "get_list") else []
    status, pts, max_pts, detail = _eval_cookies(set_cookie_headers)
    if status != Status.NOT_APPLICABLE:
        result.checks.append(HeaderCheckResult("Cookie Flags", status, pts, max_pts, detail))

    return result
