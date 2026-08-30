"""
TLS/SSL Scanner

Checks certificate validity/expiry and negotiated protocol/cipher strength.
Also probes whether the server still accepts deprecated protocol versions
(TLS 1.0 / 1.1), which is a common misconfiguration.

Uses Python's built-in ssl module — no external binaries required.
"""
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from backend.scanners.headers import Status, HeaderCheckResult  # reuse Status enum + shape


@dataclass
class TlsAuditResult:
    hostname: str
    port: int = 443
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


def _get_hostname(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    return parsed.hostname or url


def _check_cert_and_default_negotiation(hostname: str, port: int, timeout: float):
    """Connects with a standard verifying context; returns (cert_dict, protocol, cipher_tuple, error)."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()  # (name, protocol_version, secret_bits)
                return cert, protocol, cipher, None
    except ssl.SSLCertVerificationError as e:
        return None, None, None, f"Certificate verification failed: {e.verify_message}"
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        return None, None, None, f"Connection failed: {e}"


def _check_legacy_protocol_allowed(hostname: str, port: int, timeout: float, proto_const) -> bool:
    """Returns True if the server accepts a connection pinned to a legacy protocol (bad)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = proto_const
        ctx.maximum_version = proto_const
    except (ValueError, AttributeError):
        return False  # this Python/OpenSSL build doesn't even support the legacy protocol - good
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True  # handshake succeeded on a legacy protocol - bad
    except Exception:
        return False  # handshake rejected - good, server refuses legacy protocol


def _eval_cert_expiry(cert: dict):
    not_after = cert.get("notAfter")
    if not not_after:
        return Status.WARN, 5, 10, "Could not determine certificate expiry."
    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days_left = (expiry - datetime.now(timezone.utc)).days
    if days_left < 0:
        return Status.FAIL, 0, 10, f"Certificate EXPIRED {abs(days_left)} days ago."
    if days_left < 14:
        return Status.WARN, 3, 10, f"Certificate expires very soon ({days_left} days). Renew immediately."
    if days_left < 30:
        return Status.WARN, 6, 10, f"Certificate expires in {days_left} days. Plan renewal."
    return Status.PASS, 10, 10, f"Valid, expires in {days_left} days."


def _eval_protocol(protocol: Optional[str]):
    if protocol is None:
        return Status.FAIL, 0, 15, "Could not negotiate a TLS connection at all."
    good = {"TLSv1.3", "TLSv1.2"}
    if protocol in good:
        pts = 15 if protocol == "TLSv1.3" else 12
        return Status.PASS, pts, 15, f"Negotiated {protocol} (modern, secure)."
    return Status.FAIL, 0, 15, f"Negotiated {protocol}, which is deprecated and insecure."


def _eval_cipher(cipher: Optional[tuple]):
    if cipher is None:
        return Status.WARN, 3, 10, "Could not determine negotiated cipher."
    name, _, secret_bits = cipher
    weak_markers = ("RC4", "DES", "3DES", "MD5", "NULL", "EXPORT")
    if any(m in name for m in weak_markers):
        return Status.FAIL, 0, 10, f"Negotiated weak cipher '{name}'."
    if secret_bits < 128:
        return Status.WARN, 4, 10, f"Cipher '{name}' uses only {secret_bits}-bit secret."
    return Status.PASS, 10, 10, f"Negotiated strong cipher '{name}' ({secret_bits}-bit)."


def _eval_legacy_protocols(hostname: str, port: int, timeout: float):
    """Checks whether TLS 1.0 or 1.1 are still accepted (bad practice, should be disabled)."""
    findings = []
    legacy_map = {}
    if hasattr(ssl, "TLSVersion"):
        if hasattr(ssl.TLSVersion, "TLSv1"):
            legacy_map["TLSv1.0"] = ssl.TLSVersion.TLSv1
        if hasattr(ssl.TLSVersion, "TLSv1_1"):
            legacy_map["TLSv1.1"] = ssl.TLSVersion.TLSv1_1

    allowed_legacy = []
    for name, const in legacy_map.items():
        if _check_legacy_protocol_allowed(hostname, port, timeout, const):
            allowed_legacy.append(name)

    if allowed_legacy:
        return Status.WARN, 5, 15, f"Server still accepts deprecated protocol(s): {', '.join(allowed_legacy)}."
    return Status.PASS, 15, 15, "Deprecated protocols (TLS 1.0/1.1) are correctly disabled."


def audit_tls(url: str, port: int = 443, timeout: float = 8.0) -> TlsAuditResult:
    hostname = _get_hostname(url)
    result = TlsAuditResult(hostname=hostname, port=port)

    cert, protocol, cipher, error = _check_cert_and_default_negotiation(hostname, port, timeout)
    if error:
        result.error = error
        return result

    status, pts, max_pts, detail = _eval_cert_expiry(cert)
    result.checks.append(HeaderCheckResult("Certificate Expiry", status, pts, max_pts, detail))

    status, pts, max_pts, detail = _eval_protocol(protocol)
    result.checks.append(HeaderCheckResult("TLS Protocol Version", status, pts, max_pts, detail))

    status, pts, max_pts, detail = _eval_cipher(cipher)
    result.checks.append(HeaderCheckResult("Cipher Strength", status, pts, max_pts, detail))

    status, pts, max_pts, detail = _eval_legacy_protocols(hostname, port, timeout)
    result.checks.append(HeaderCheckResult("Legacy Protocol Support", status, pts, max_pts, detail))

    return result
