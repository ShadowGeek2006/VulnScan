"""
Tests for the scoring engine.
Run with: pytest tests/test_scoring.py -v
"""
from backend.core.scoring import compute_overall_score, CategoryScore


class FakeResult:
    """Stand-in for HeaderAuditResult/TlsAuditResult in unit tests."""
    def __init__(self, percentage):
        self.percentage = percentage


def test_perfect_scores_yield_grade_a():
    result = compute_overall_score("example.com", {
        "headers": FakeResult(100),
        "tls": FakeResult(100),
    })
    assert result.weighted_percentage == 100.0
    assert result.grade == "A"


def test_mixed_scores_average_correctly():
    result = compute_overall_score("example.com", {
        "headers": FakeResult(80),
        "tls": FakeResult(60),
    })
    # 0.5*80 + 0.5*60 = 70
    assert result.weighted_percentage == 70.0
    assert result.grade == "C"


def test_missing_category_renormalizes_weights():
    # Only headers scanned (TLS failed) — headers alone should determine the grade
    result = compute_overall_score("example.com", {
        "headers": FakeResult(90),
    }, errors={"tls": "Connection refused"})
    assert result.weighted_percentage == 90.0
    assert result.grade == "A"
    assert "tls" in result.errors


def test_zero_scores_yield_grade_f():
    result = compute_overall_score("example.com", {
        "headers": FakeResult(0),
        "tls": FakeResult(0),
    })
    assert result.grade == "F"


def test_grade_boundaries():
    assert compute_overall_score("x", {"headers": FakeResult(90)}).grade == "A"
    assert compute_overall_score("x", {"headers": FakeResult(89.9)}).grade == "B"
    assert compute_overall_score("x", {"headers": FakeResult(70)}).grade == "C"
    assert compute_overall_score("x", {"headers": FakeResult(69.9)}).grade == "D"
    assert compute_overall_score("x", {"headers": FakeResult(59.9)}).grade == "F"