# VulnScope

A web-based vulnerability assessment tool: give it a URL, it audits security headers, TLS/SSL config, DNS posture, and known misconfigurations, then returns a letter-grade score with a plain-English remediation report.

Think "SSL Labs + Mozilla Observatory + Nikto" combined into one dashboard.

## ⚠️ Authorized Use Only

This tool is for auditing systems **you own or are explicitly authorized to test**. Running active scans against third-party systems without permission is illegal in most jurisdictions (e.g. under the Computer Misuse Act / IT Act 2000 in India). VulnScope requires an ownership confirmation step before running anything beyond passive checks. Use it on your own sites, lab environments (DVWA, Metasploitable), or systems with signed authorization.

## Architecture

| Layer | What it does |
|---|---|
| **Recon & Fingerprinting** | Server/CMS/framework detection, DNS record checks (SPF/DKIM/DMARC) |
| **HTTP Header Audit** | CSP, HSTS, X-Frame-Options, cookie flags, etc. |
| **TLS/SSL Check** | Certificate validity, protocol/cipher strength (via `testssl.sh`/`sslscan`) |
| **Active Scan** (opt-in, authorization-gated) | Nikto misconfig scan, optional OWASP ZAP baseline scan |
| **Scoring Engine** | Weighted A–F grade across all categories |
| **Reporting** | HTML/PDF report with findings + remediation guidance |

## Project Structure

```
vulnscope/
├── backend/
│   ├── api/            # FastAPI routes
│   ├── core/            # scoring engine, config, orchestration
│   ├── scanners/         # tool wrappers (headers, tls, dns, nikto...)
│   └── reports/          # generated report output (gitignored)
├── frontend/            # dashboard UI
├── tests/
└── docs/
```

## Status

🚧 Early scaffold — building incrementally. See `docs/` for design notes and the scoring rubric as they're added.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn backend.main:app --reload
```

Visit `http://localhost:8000/health` to confirm the API is running.

## License

MIT — see `LICENSE`.
