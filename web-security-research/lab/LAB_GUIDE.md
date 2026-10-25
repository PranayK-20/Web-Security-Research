# Hands-On Web Security Research Lab: Vulnerable vs. Hardened Architectures

## Overview
This laboratory environment provides reproducible, isolated targets designed to evaluate and demonstrate modern web application vulnerabilities alongside their enterprise-grade defense-in-depth remediations.

Aligned with:
- **OWASP Top 10:2021** (A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection, A05 Security Misconfiguration, A10 SSRF)
- **OWASP API Security Top 10:2023** (API1 BOLA, API2 Broken Auth, API7 SSRF, API8 Misconfig)
- **OWASP ASVS v4.0.3** (Chapters V2, V3, V4, V5, V9, V12, V14)

---

## Directory Structure
```
lab/
├── vulnerable_app/
│   └── app.py              # Intentionally vulnerable target running on port 5001
├── secure_app/
│   └── app.py              # Hardened defense-in-depth target running on port 5002
├── scanner/
│   ├── web_security_auditor.py  # Standalone CLI compliance scanner & auditor
│   └── test_scanner.py          # Automated comparative evaluation harness
└── benchmarks/
    ├── audit_results_vulnerable.json   # Machine-readable scan output (Vulnerable)
    ├── audit_results_secure.json       # Machine-readable scan output (Hardened)
    └── comparative_audit_report.md     # Comparative delta & compliance matrix
```

---

## Quickstart & Execution

### Option 1: Run Full Automated Comparative Benchmark
To launch both servers, execute the full audit suite, generate JSON/Markdown reports, and verify the defense delta:
```bash
python lab/scanner/test_scanner.py
```

### Option 2: Run Individual Applications Manually

#### Launch Vulnerable Application (Port 5001):
```bash
python lab/vulnerable_app/app.py
```
Test with curl or browser:
- **BOLA/IDOR Probe**: `curl http://127.0.0.1:5001/api/v1/document?id=103` (leaks admin keys)
- **SQLi Probe**: `curl "http://127.0.0.1:5001/api/v1/search?q=Keyboard'%20OR%20'1'='1"` (dumps all products)
- **Insecure Cookie**: `curl -i -X POST http://127.0.0.1:5001/api/v1/login -H "Content-Type: application/json" -d '{"username":"alice","password":"password123"}'` (missing `HttpOnly`, `Secure`, `SameSite`)

#### Launch Hardened Application (Port 5002):
```bash
python lab/secure_app/app.py
```
Test with curl:
- **BOLA Mitigated**: `curl http://127.0.0.1:5002/api/v1/document?id=103` (returns 401 Unauthorized)
- **SQLi Neutralized**: `curl "http://127.0.0.1:5002/api/v1/search?q=Keyboard'%20OR%20'1'='1"` (parameterized, 0 match)
- **SSRF Blocked**: `curl "http://127.0.0.1:5002/api/v1/fetch-url?url=http://127.0.0.1:5001/"` (returns 403 Forbidden with egress policy violation)

#### Run the Standalone Compliance Auditor:
```bash
# Scan vulnerable app
python lab/scanner/web_security_auditor.py --url http://127.0.0.1:5001

# Scan hardened app
python lab/scanner/web_security_auditor.py --url http://127.0.0.1:5002

# Export audit to Markdown or JSON
python lab/scanner/web_security_auditor.py --url http://127.0.0.1:5002 --out audit_report.md
python lab/scanner/web_security_auditor.py --url http://127.0.0.1:5002 --json --out audit_report.json
```

---

## Safety & Ethics Disclaimer
All testing and code included in this directory is restricted to local loopback (`127.0.0.1`) environments. Do NOT deploy the vulnerable application in production or public-facing networks.
