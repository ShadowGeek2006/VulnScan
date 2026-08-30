"""
Tests for the TLS/SSL scanner.

Run with: pytest tests/test_tls.py -v
"""
from backend.scanners.tls import audit_tls, Status


def test_audit_tls_returns_result_for_valid_https_domain():
    result = audit_tls("https://example.com")
    assert result.error is None
    assert len(result.checks) == 4


def test_audit_tls_negotiates_modern_protocol():
    result = audit_tls("https://example.com")
    protocol_check = next(c for c in result.checks if c.header == "TLS Protocol Version")
    assert protocol_check.status == Status.PASS


def test_audit_tls_detects_no_legacy_protocol_support():
    result = audit_tls("https://example.com")
    legacy_check = next(c for c in result.checks if c.header == "Legacy Protocol Support")
    # example.com's TLS termination (Fastly/AWS) should not allow TLS 1.0/1.1
    assert legacy_check.status == Status.PASS


def test_audit_tls_handles_unreachable_host_gracefully():
    result = audit_tls("https://this-domain-should-not-exist-vulnscope-test.invalid")
    assert result.error is not None


def test_percentage_within_bounds():
    result = audit_tls("https://example.com")
    assert 0 <= result.percentage <= 100
