"""
Scoring Engine

Aggregates results from multiple scanner modules (headers, TLS, etc.)
into a single weighted overall score and letter grade.

Category weights reflect real-world security impact:
- Headers matter a lot (XSS/clickjacking/injection surface)
- TLS matters a lot (transport security)
- Future categories (DNS, active scan) will slot in here too
"""
from dataclasses import dataclass, field
from typing import Optional


# Category weight = how much this category counts toward the final grade.
# Must sum to 1.0 across whatever categories are actually present in a given scan.
CATEGORY_WEIGHTS = {
    "headers": 0.5,
    "tls": 0.5,
}

GRADE_BANDS = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
]


@dataclass
class CategoryScore:
    name: str
    percentage: float
    weight: float


@dataclass
class OverallScore:
    target: str
    categories: list = field(default_factory=list)
    weighted_percentage: float = 0.0
    grade: str = "F"
    errors: dict = field(default_factory=dict)  # category_name -> error message, for skipped categories


def _grade_for_percentage(pct: float) -> str:
    for threshold, letter in GRADE_BANDS:
        if pct >= threshold:
            return letter
    return "F"


def compute_overall_score(target: str, category_results: dict, errors: Optional[dict] = None) -> OverallScore:
    """
    category_results: dict like {"headers": <HeaderAuditResult>, "tls": <TlsAuditResult>}
                       Each value must expose a `.percentage` property (0-100).
    errors: dict of category_name -> error string, for categories that failed to scan
            (e.g. TLS scan failed because the site is HTTP-only). These are excluded
            from scoring but reported so the user knows why.
    """
    errors = errors or {}
    present_categories = {k: v for k, v in category_results.items() if k not in errors}

    if not present_categories:
        return OverallScore(target=target, weighted_percentage=0.0, grade="F", errors=errors)

    # Re-normalize weights across only the categories actually present,
    # so a missing category (e.g. TLS scan failed) doesn't unfairly tank the score to zero.
    total_weight = sum(CATEGORY_WEIGHTS.get(k, 0) for k in present_categories)
    if total_weight == 0:
        total_weight = 1.0  # fallback safety

    categories = []
    weighted_sum = 0.0
    for name, result in present_categories.items():
        weight = CATEGORY_WEIGHTS.get(name, 0)
        normalized_weight = weight / total_weight
        categories.append(CategoryScore(name=name, percentage=result.percentage, weight=normalized_weight))
        weighted_sum += result.percentage * normalized_weight

    weighted_percentage = round(weighted_sum, 1)
    grade = _grade_for_percentage(weighted_percentage)

    return OverallScore(
        target=target,
        categories=categories,
        weighted_percentage=weighted_percentage,
        grade=grade,
        errors=errors,
    )