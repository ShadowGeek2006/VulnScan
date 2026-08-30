"""
Tests for the HTTP header security scanner.

Run with: pytest tests/test_headers.py -v
"""
import pytest
from backend.scanners.headers import audit_headers, Status


@pytest.mark.asyncio
async def test_audit_headers_returns_result_for_valid_url():
    result = await audit_headers("https://example.com")
    assert result.error is None
    assert result.url == "https://example.com"
    assert len(result.checks) > 0


@pytest.mark.asyncio
async def test_audit_headers_handles_missing_headers_as_fail():
    # example.com is known to lack most security headers
    result = await audit_headers("https://example.com")
    hsts_check = next(c for c in result.checks if c.header == "Strict-Transport-Security")
    assert hsts_check.status == Status.FAIL
    assert hsts_check.points_earned == 0


@pytest.mark.asyncio
async def test_audit_headers_handles_invalid_domain_gracefully():
    result = await audit_headers("https://this-domain-should-not-exist-vulnscope-test.invalid")
    assert result.error is not None


@pytest.mark.asyncio
async def test_percentage_calculation():
    result = await audit_headers("https://example.com")
    assert 0 <= result.percentage <= 100
    if result.total_possible > 0:
        expected = round((result.total_earned / result.total_possible) * 100, 1)
        assert result.percentage == expected
