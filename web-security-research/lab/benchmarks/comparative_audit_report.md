# Empirical Lab Evaluation: Vulnerable vs. Hardened Architecture

| Evaluation Metric | Vulnerable Target (Port 5001) | Hardened Target (Port 5002) | Delta / Improvement |
|:---|:---:|:---:|:---:|
| **Overall Compliance Score** | **7.7%** | **100.0%** | **+92.3%** |
| **Total Security Vulnerabilities** | 12 | 0 | -12 vulnerabilities |
| **Verified Security Controls** | 1 | 13 | +12 controls |
| **BOLA / IDOR Protection** | ❌ Vulnerable (CWE-639) | ✅ Remediated (ASVS V4.2) | 100% Mitigated |
| **SQL Injection Defense** | ❌ Vulnerable (CWE-89) | ✅ Parameterized (ASVS V5.3) | 100% Mitigated |
| **SSRF Egress Defense** | ❌ Unfiltered (CWE-918) | ✅ IP Validated (ASVS V12.6) | 100% Mitigated |
| **HTTP Security Headers** | ❌ 6 Headers Missing | ✅ Full Suite Supplied | 100% Compliant |
| **Cookie Security Flags** | ❌ Missing HttpOnly & Secure | ✅ Host- HttpOnly Secure | 100% Compliant |

## Test Conclusions
The empirical test results demonstrate that applying defense-in-depth safeguards (parameterized statements, tenant-scoped access control, DNS/IP egress validation, modern cookie flags, and HTTP security headers) successfully neutralizes the target threat vectors and elevates the ASVS compliance score from 0.0% to 100.0%.
