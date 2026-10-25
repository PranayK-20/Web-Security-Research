# ARCHITECTURE SPECIFICATIONS & EMPIRICAL EVIDENCE COMPENDIUM
**Web Application Security Research: Laboratory Architecture, Attack Flow Visuals, and Execution Logs**

---

## 1. System Architecture & Component Interactions

```mermaid
graph TB
    subgraph "Client / Auditor Execution Layer"
        Auditor[Python Web Security Auditor<br/>web_security_auditor.py]
        ManualTester[Adversary / Browser / Curl Client]
    end

    subgraph "Target 1: Vulnerable Architecture (Port 5001)"
        VApp[Vulnerable HTTP Server<br/>vulnerable_app/app.py]
        VDB[(In-Memory SQLite DB<br/>Unsalted MD5 Passwords)]
        VApp -->|Raw String Concatenation| VDB
        VApp -->|Blind Outbound Fetch| Net1[Intranet / Loopback 127.0.0.1]
    end

    subgraph "Target 2: Hardened Defense-in-Depth Architecture (Port 5002)"
        SApp[Hardened HTTP Server<br/>secure_app/app.py]
        SDB[(In-Memory SQLite DB<br/>Salted PBKDF2 Hashes)]
        DNSCheck[DNS Resolver & Egress IP Policy<br/>Block RFC 1918 & 169.254.169.254]
        HeaderInject[Security Header Middleware<br/>CSP, HSTS, X-Content-Type, COOP]
        
        SApp --> HeaderInject
        SApp -->|Tenant-Scoped Prepared Statements| SDB
        SApp --> DNSCheck
        DNSCheck -.->|403 Forbidden| Blocked[Blocked Subnet]
    end

    Auditor -->|Probe Ports 5001 & 5002| VApp
    Auditor -->|Probe Ports 5001 & 5002| SApp
    ManualTester --> VApp
    ManualTester --> SApp
```

---

## 2. Attack Sequence Diagrams

### 2.1 Broken Object Level Authorization (BOLA) Attack vs. Defense

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Malicious User (User 102)
    participant VServer as Vulnerable App (Port 5001)
    participant SServer as Hardened App (Port 5002)
    participant Database as Database Engine

    Note over Attacker, VServer: Scenario A: Vulnerable Target (No Scoping)
    Attacker->>VServer: GET /api/v1/document?id=103 (Admin Record)
    VServer->>Database: SELECT * FROM documents WHERE id = 103;
    Database-->>VServer: Returns Admin Document #103
    VServer-->>Attacker: HTTP 200 OK: Leaks AWS_SECRET_KEY

    Note over Attacker, SServer: Scenario B: Hardened Target (Tenant-Scoped)
    Attacker->>SServer: GET /api/v1/document?id=103
    Note over SServer: Validates session token & user ownership
    SServer-->>Attacker: HTTP 401 Unauthorized / 404 Not Found
```

### 2.2 Server-Side Request Forgery (SSRF) Attack vs. Defense

```mermaid
sequenceDiagram
    autonumber
    actor Attacker
    participant SServer as Hardened App (Port 5002)
    participant DNS as Local DNS Resolver
    participant Internal as Internal Infrastructure (127.0.0.1 / IMDS)

    Attacker->>SServer: GET /api/v1/fetch-url?url=http://127.0.0.1:5001/
    SServer->>DNS: Resolve hostname "127.0.0.1"
    DNS-->>SServer: IPv4 Address: 127.0.0.1
    Note over SServer: Inspects IP: is_loopback == True
    SServer-->>Attacker: HTTP 403 Forbidden: "Access to restricted private IP is blocked."
    Note over Internal: Request never sent to internal resource
```

---

## 3. Terminal Execution Logs (Raw Test Output)

The following raw execution transcript was recorded during automated test execution on the system:

```text
================================================================================
STARTING EMPIRICAL LAB EVALUATION: VULNERABLE VS. HARDENED TARGETS
================================================================================
[*] Launching Vulnerable Application Server on port 5001...
[*] Launching Hardened Application Server on port 5002...
[+] Both test servers active and responsive.

--------------------------------------------------------------------------------
PHASE 1: AUDITING VULNERABLE TARGET (http://127.0.0.1:5001)
--------------------------------------------------------------------------------
[-] Vulnerable Target Scan Completed.
[-] Score: 7.7%
[-] Total Findings: 12 (Failures)
[-] Passed Checks: 1
    * [HIGH] Missing HTTP Header: Content-Security-Policy (CWE: CWE-16 | ASVS: V14.4.1)
    * [HIGH] Missing HTTP Header: Strict-Transport-Security (CWE: CWE-16 | ASVS: V9.2.1)
    * [MEDIUM] Missing HTTP Header: X-Content-Type-Options (CWE: CWE-16 | ASVS: V14.4.2)
    * [MEDIUM] Missing HTTP Header: X-Frame-Options (CWE: CWE-16 | ASVS: V14.4.3)
    * [LOW] Missing HTTP Header: Referrer-Policy (CWE: CWE-16 | ASVS: V14.4.4)
    * [LOW] Missing HTTP Header: Permissions-Policy (CWE: CWE-16 | ASVS: V14.4.5)
    * [LOW] Server Banner Information Disclosure (CWE: CWE-200 | ASVS: V14.1.3)
    * [MEDIUM] Insecure CORS Wildcard Allowed (CWE: CWE-942 | ASVS: V14.4.5)
    * [HIGH] Session Cookie Missing 'HttpOnly' Flag (CWE: CWE-1004 | ASVS: V3.4.1)
    * [MEDIUM] Session Cookie Missing 'SameSite' Attribute (CWE: CWE-1275 | ASVS: V3.4.2)
    * [CRITICAL] Broken Object Level Authorization (BOLA / IDOR) Detected (CWE: CWE-639 | ASVS: V4.2.1)
    * [CRITICAL] SQL Injection & Raw Query Reflection Detected (CWE: CWE-89 | ASVS: V5.3.1)

--------------------------------------------------------------------------------
PHASE 2: AUDITING HARDENED TARGET (http://127.0.0.1:5002)
--------------------------------------------------------------------------------
[+] Hardened Target Scan Completed.
[+] Score: 100.0%
[+] Total Findings: 0 (Failures)
[+] Passed Checks: 13
    * [PASS] Header Present: Content-Security-Policy
    * [PASS] Header Present: Strict-Transport-Security
    * [PASS] Header Present: X-Content-Type-Options
    * [PASS] Header Present: X-Frame-Options
    * [PASS] Header Present: Referrer-Policy
    * [PASS] Header Present: Permissions-Policy
    * [PASS] Server Header Hardened
    * [PASS] Cookie HttpOnly Enforced
    * [PASS] Cookie Secure Enforced
    * [PASS] Cookie SameSite Enforced
    * [PASS] BOLA / IDOR Access Control Verified
    * [PASS] SQL Parameterization Confirmed
    * [PASS] SSRF Egress Defense Confirmed

================================================================================
[+] Benchmark artifacts successfully generated in: .../lab/benchmarks
[+] Comparative Report: .../lab/benchmarks/comparative_audit_report.md
================================================================================
[*] Terminating test server processes...
[+] Test servers stopped cleanly.
```
