# Web Security Research
1. **Intern :** Pranay Vinod Kadam
2. **Intern Id :** 2404
3. **Organisation:** RedKross Research Foundation
4. **Assignment:** Web Security Research
5. **Submission deadline:** 25 October 2026
**Threat Modeling, Empirical Vulnerability Analysis, and Automated OWASP ASVS Compliance Verification**

[![Python 3.12](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OWASP ASVS](https://img.shields.io/badge/OWASP%20ASVS-v4.0.3%20Level%202-brightgreen.svg)](https://owasp.org/www-project-application-security-verification-standard/)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%3A2021-red.svg)](https://owasp.org/Top10/)
[![Security Compliance](https://img.shields.io/badge/Compliance%20Score-100.0%25-success.svg)](lab/benchmarks/comparative_audit_report.md)

---

## 🎥 Explanatory Presentation Video

> **📺 Watch the Explanatory Project Walkthrough Video**:  
> **[Click Here to Watch the Explanatory Video [https://drive.google.com/file/d/1eAhpO84TD2LK752OidMz9aLLdwC-TM5s/view?usp=sharing]]**  

---

## 📌 Executive Summary & Project Objectives

As web application architectures have transitioned from monolithic server-side rendering to decoupled Single-Page Applications (SPAs), microservices, and multi-cloud API fabrics, traditional perimeter firewalls have dissolved. According to the Verizon Data Breach Investigations Report (DBIR), web applications represent the **#1 external attack vector**, accounting for over 70% of enterprise breaches. Furthermore, **Broken Access Control (OWASP A01:2021)** has become the most prevalent risk across the web, present in over 94% of audited applications.

This repository represents the completed cybersecurity internship research project on **Web Security Research**. It delivers:
1. **3-Page Technical Brief**: An authoritative, publication-grade engineering guide detailing modern vulnerability vectors, defense-in-depth architectures, code diffs, and security headers.
2. **Enterprise Risk-to-Mitigation Matrix**: A granular analysis of twelve critical web vulnerabilities mapped to CVSS v3.1, CWEs, attack mechanics, multi-tier mitigations, and ASVS verification requirements (available in both Markdown and CSV).
3. **OWASP Framework Alignment Compendium**: A cross-standard alignment unifying the OWASP Top 10:2021, OWASP API Security Top 10:2023, OWASP ASVS v4.0.3, and OWASP Proactive Controls.
4. **Mandatory Formal Technical Report**: A comprehensive research report covering background literature, STRIDE threat modeling, experimental methodology, implementation results, empirical benchmarks, and strategic recommendations.
5. **Hands-On Isolated Research Lab**: A reproducible, dependency-free Python testbed containing an intentionally vulnerable target (port 5001), an enterprise-hardened counterpart (port 5002), and an automated compliance auditor script that verifies defense effectiveness.

---

## 📁 Repository Directory Structure

```text
web-security-research/
├── README.md                                  # Master repository documentation & video link
├── LICENSE                                    # MIT Open Source License
├── .gitignore                                 # Standard Python & OS ignore rules
│
├── deliverables/                              # Core assigned task deliverables
│   ├── 01_TECHNICAL_BRIEF.md                  # 3-Page publication-grade technical brief
│   ├── 02_RISK_TO_MITIGATION_TABLE.md         # Comprehensive 12-vector risk matrix (Markdown)
│   ├── 02_risk_to_mitigation_table.csv        # GRC / Jira importable risk matrix (CSV)
│   └── 03_OWASP_FRAMEWORK_MAPPINGS.md         # OWASP Top 10, API Top 10 & ASVS compendium
│
├── reports/                                   # Mandatory internship documentation
│   └── MANDATORY_TECHNICAL_REPORT.md          # Comprehensive formal technical research report
│
├── lab/                                       # Hands-on reproducible laboratory code
│   ├── LAB_GUIDE.md                           # Lab architecture & instructions
│   ├── vulnerable_app/
│   │   └── app.py                             # Intentionally vulnerable service (Port 5001)
│   ├── secure_app/
│   │   └── app.py                             # Hardened defense-in-depth service (Port 5002)
│   ├── scanner/
│   │   ├── web_security_auditor.py            # Standalone CLI compliance auditor
│   │   └── test_scanner.py                    # Automated comparative evaluation harness
│   └── benchmarks/
│       ├── audit_results_vulnerable.json      # Scan results for vulnerable target (7.7%)
│       ├── audit_results_secure.json          # Scan results for hardened target (100.0%)
│       └── comparative_audit_report.md        # Side-by-side verification report
│
├── video/                                     # Video presentation assets
│   ├── EXPLANATORY_VIDEO_SCRIPT.md            # Word-for-word script, outline & recording guide
│   └── SLIDES_OUTLINE.md                      # Slide-by-slide markdown presentation deck
│
└── docs/                                      # Supporting architecture & evidence
    └── ARCHITECTURE_AND_EVIDENCE.md           # Mermaid sequence flows & execution logs
```

---

## 🚀 Quickstart: Reproducing the Lab & Running Tests

The entire research laboratory is engineered using **Python 3 standard libraries**, requiring **zero third-party dependencies** (`pip install` is NOT required).

### Option 1: Run the Automated Comparative Benchmark (Recommended)
This command boots both servers, executes the security auditor against both targets, and writes empirical benchmark files:
```bash
python lab/scanner/test_scanner.py
```

### Option 2: Run the Web Security Auditor Standalone
You can audit any local or remote web endpoint against OWASP ASVS requirements:
```bash
# Scan vulnerable application (Port 5001)
python lab/scanner/web_security_auditor.py --url http://127.0.0.1:5001

# Scan hardened application (Port 5002)
python lab/scanner/web_security_auditor.py --url http://127.0.0.1:5002

# Export audit to Markdown or JSON
python lab/scanner/web_security_auditor.py --url http://127.0.0.1:5002 --out audit.md
python lab/scanner/web_security_auditor.py --url http://127.0.0.1:5002 --json --out audit.json
```

---

## 📊 Empirical Evaluation & Benchmark Results

The automated auditor evaluated both targets across 13 standardized security checks. The table below displays the verified empirical delta:

| Evaluation Metric | Baseline Target (Port 5001) | Hardened Target (Port 5002) | Delta / Defense Impact |
|:---|:---:|:---:|:---:|
| **OWASP ASVS Compliance Score** | **7.7%** | **100.0%** | **+92.3% Compliance Improvement** |
| **Identified Vulnerabilities** | **12 Failures** | **0 Failures** | **100% Vulnerability Elimination** |
| **Verified Controls Passed** | 1 Control | 13 Controls | +12 Defenses Successfully Verified |
| **BOLA / IDOR Protection** | ❌ Leaked Admin Keys (CWE-639) | ✅ Scoped Authorization (ASVS V4.2) | 100% Tenant Isolation |
| **SQL Injection Defense** | ❌ Raw Query Executed (CWE-89) | ✅ Parameterized Query (ASVS V5.3) | 100% Injection Resistance |
| **SSRF Egress Defense** | ❌ Loopback Reached (CWE-918) | ✅ Private IP Blocked (ASVS V12.6) | 100% Egress Boundary Protection |
| **HTTP Security Headers** | ❌ 6 Mandatory Headers Missing | ✅ Full Modern Suite Supplied | Complete Browser Hardening |
| **Cookie Flags & Hygiene** | ❌ Missing HttpOnly & Secure | ✅ `__Host-` with Strict Flags | Protected Against Session Hijacking |

---

## 🛡️ Summary of Core Deliverables

### 1. [3-Page Technical Brief (`deliverables/01_TECHNICAL_BRIEF.md`)](deliverables/01_TECHNICAL_BRIEF.md)
Structured for senior software engineers and architects, this whitepaper explores:
- Executive summary of modern web threat vectors.
- Architectural mechanics of Broken Access Control (BOLA/IDOR), Template Injection (SSTI), and Cloud Metadata SSRF.
- Concrete vulnerable vs. secure code implementations.
- Recommended production HTTP security headers specification table.
- Credible references from NIST, OWASP, and RFCs.

### 2. [Risk-to-Mitigation Matrix (`deliverables/02_RISK_TO_MITIGATION_TABLE.md`)](deliverables/02_RISK_TO_MITIGATION_TABLE.md)
Covers twelve enterprise risk vectors:
1. Broken Object Level Authorization (BOLA/IDOR)
2. SQL & Command Injection
3. Cryptographic Failures & Sensitive Data Exposure
4. Cross-Site Scripting (XSS)
5. Server-Side Request Forgery (SSRF)
6. Security Misconfiguration
7. Vulnerable and Outdated Components
8. Identification & Authentication Failures
9. Software and Data Integrity Failures
10. Security Logging & Monitoring Failures
11. Unrestricted Resource Consumption
12. CSRF & Insecure CORS  
*Also available in machine-readable CSV: [`deliverables/02_risk_to_mitigation_table.csv`](deliverables/02_risk_to_mitigation_table.csv).*

### 3. [OWASP Framework Mappings (`deliverables/03_OWASP_FRAMEWORK_MAPPINGS.md`)](deliverables/03_OWASP_FRAMEWORK_MAPPINGS.md)
Cross-references:
- OWASP Top 10:2021 vs. 2017 historical shifts.
- OWASP API Security Top 10 (2023 Edition) mapping.
- OWASP ASVS v4.0.3 Level 1, 2, and 3 verification requirements.
- OWASP Proactive Controls (C1 - C10).
- Curated OWASP Cheat Sheet index for developers.

### 4. [Mandatory Formal Technical Report (`reports/MANDATORY_TECHNICAL_REPORT.md`)](reports/MANDATORY_TECHNICAL_REPORT.md)
The comprehensive academic/industrial research report detailing:
- Project objectives and background literature review.
- STRIDE threat modeling framework and methodology.
- Complete implementation documentation of vulnerable and hardened applications.
- Empirical findings with request/response HTTP transcripts.
- Benchmarks, limitations, strategic DevSecOps recommendations, and conclusion.

---

## 🔒 Security & Safe Research Disclaimer

All code, penetration test scripts, and vulnerable implementations contained in this repository were developed strictly for educational, defensive, and research benchmarking purposes in an isolated local loopback environment (`127.0.0.1`). 
- **No live credentials, production tokens, or personally identifiable information (PII) are stored in this repository.**
- Do NOT deploy the vulnerable testbed application (`lab/vulnerable_app/app.py`) on public or production networks.
- All testing was performed within an explicitly authorized local testing harness.

---

## 📚 Key References & Standards

1. **OWASP Foundation** (2021). *OWASP Top 10: 2021 The Ten Most Critical Web Application Security Risks*. [https://owasp.org/Top10/](https://owasp.org/Top10/)
2. **OWASP Foundation** (2023). *OWASP API Security Top 10 2023*. [https://owasp.org/www-project-api-security/](https://owasp.org/www-project-api-security/)
3. **OWASP Foundation** (2021). *OWASP Application Security Verification Standard (ASVS) v4.0.3*. [https://owasp.org/www-project-application-security-verification-standard/](https://owasp.org/www-project-application-security-verification-standard/)
4. **NIST** (2020). *Security and Privacy Controls for Information Systems and Organizations* (NIST SP 800-53, Rev. 5). [https://doi.org/10.6028/NIST.SP.800-53r5](https://doi.org/10.6028/NIST.SP.800-53r5)
5. **NIST** (2007). *Guide to Secure Web Services* (NIST SP 800-95). [https://doi.org/10.6028/NIST.SP.800-95](https://doi.org/10.6028/NIST.SP.800-95)
6. **IETF** (2022). *HTTP Semantics* (RFC 9110). [https://datatracker.ietf.org/doc/html/rfc9110](https://datatracker.ietf.org/doc/html/rfc9110)
7. **Verizon Business** (2024). *2024 Data Breach Investigations Report (DBIR)*. [https://www.verizon.com/business/resources/reports/dbir/](https://www.verizon.com/business/resources/reports/dbir/)
