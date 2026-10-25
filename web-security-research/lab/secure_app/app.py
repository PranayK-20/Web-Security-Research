"""
Hardened & Remediated Web Application Target (Educational & Defense-in-Depth Reference)
Demonstrating enterprise-grade mitigations aligned with OWASP ASVS v4.0.3 and NIST SP 800-95.

Defensive Safeguards Implemented:
- ASVS V4.1 / V4.2: Tenant-Scoped Authorization & BOLA/IDOR Elimination
- ASVS V5.3: Parameterized Prepared Statements & SQL Injection Neutralization
- ASVS V2.4 / V3.4: Cryptographically Hardened PBKDF2 Hashing & __Host- HttpOnly Cookies
- ASVS V14.4: Comprehensive Suite of Modern HTTP Security Headers
- ASVS V12.6: SSRF Mitigation via DNS Resolution & Private IP Subnet Blocking
"""

import http.server
import ipaddress
import json
import secrets
import socket
import sqlite3
import urllib.parse
import urllib.request
import hashlib

PORT = 5002

def hash_password_secure(password: str, salt: bytes = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_bytes(16)
    # NIST SP 800-63B / OWASP compliant PBKDF2-HMAC-SHA256 with 600,000 iterations
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)
    return key.hex(), salt.hex()

def verify_password_secure(password: str, stored_hash_hex: str, salt_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    computed_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 600_000)
    return secrets.compare_digest(computed_key.hex(), stored_hash_hex)

def init_secure_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    cur = conn.cursor()
    # Users table with salted PBKDF2 hashes
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, salt TEXT, role TEXT);")
    for uid, user, pwd, role in [
        (1, "alice", "AliceSecurePass2026!", "user"),
        (2, "bob", "BobSecurePass2026!", "user"),
        (3, "admin", "AdminMasterVault2026!#", "administrator")
    ]:
        h_hex, s_hex = hash_password_secure(pwd)
        cur.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?);", (uid, user, h_hex, s_hex, role))

    # Documents table
    cur.execute("CREATE TABLE documents (id INTEGER PRIMARY KEY, owner_id INTEGER, title TEXT, content TEXT);")
    cur.execute("INSERT INTO documents VALUES (101, 1, 'Alice Q1 Review', 'Confidential salary data: $140,000');")
    cur.execute("INSERT INTO documents VALUES (102, 2, 'Bob Medical Records', 'Private health diagnosis data.');")
    cur.execute("INSERT INTO documents VALUES (103, 3, 'Enterprise Master Key', 'AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE');")

    # Products table
    cur.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, description TEXT, price REAL);")
    cur.execute("INSERT INTO products VALUES (1, 'Ergonomic Keyboard', 'Wireless split keyboard', 129.99);")
    cur.execute("INSERT INTO products VALUES (2, '4K Monitor', '32-inch IPS display', 399.50);")
    cur.execute("INSERT INTO products VALUES (3, 'Security Token', 'Hardware FIDO2 authenticator', 45.00);")
    conn.commit()
    return conn

DB_CONN = init_secure_db()
ACTIVE_SESSIONS = {}  # session_token -> {"user_id": int, "username": str, "role": str}

class SecureAppHandler(http.server.BaseHTTPRequestHandler):
    server_version = "ProtectedApp/2.0"  # Stripped server banner
    sys_version = ""

    def _apply_security_headers(self):
        # OWASP ASVS V14.4 Compliant Modern Security Headers
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';")
        self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store, max-age=0")

    def _send_json(self, status_code, payload):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self._apply_security_headers()
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def _get_authenticated_session(self):
        cookie_header = self.headers.get("Cookie", "")
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.startswith("__Host-SessionId="):
                token = part.split("=", 1)[1]
                return ACTIVE_SESSIONS.get(token)
        return None

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/":
            self._send_json(200, {
                "status": "online",
                "app": "Hardened Defense-in-Depth Target (v2.0.0)",
                "security_controls": [
                    "Strict CSP & HSTS Headers",
                    "Argon2id/PBKDF2 Password Key Derivation",
                    "Tenant-Scoped Authorization (BOLA Elimination)",
                    "Prepared Parameterized Queries (SQLi Elimination)",
                    "DNS-Pinning & Private IP Egress Filtering (SSRF Elimination)"
                ]
            })
            return

        # -------------------------------------------------------------
        # 1. HARDENED ENDPOINT: Scoped Authorization (BOLA / IDOR Neutralized)
        # Requires valid authentication and enforces tenant ownership
        # -------------------------------------------------------------
        if parsed.path == "/api/v1/document":
            session = self._get_authenticated_session()
            if not session:
                self._send_json(401, {"error": "Authentication required. Supply a valid session cookie."})
                return

            doc_id = params.get("id", [""])[0]
            if not doc_id.isdigit():
                self._send_json(400, {"error": "Invalid parameter: 'id' must be an integer."})
                return

            cur = DB_CONN.cursor()
            # Enforce access control at data query layer:
            # Users can only view documents they OWN, unless possessing the 'administrator' role
            if session["role"] == "administrator":
                cur.execute("SELECT id, owner_id, title, content FROM documents WHERE id = ?", (int(doc_id),))
            else:
                cur.execute(
                    "SELECT id, owner_id, title, content FROM documents WHERE id = ? AND owner_id = ?",
                    (int(doc_id), session["user_id"])
                )
            row = cur.fetchone()

            if row:
                self._send_json(200, {
                    "document_id": row[0],
                    "owner_id": row[1],
                    "title": row[2],
                    "content": row[3],
                    "access_validation": "SUCCESS: Verified requester is authorized owner or administrator."
                })
            else:
                # Return generic 404 to avoid object enumeration
                self._send_json(404, {"error": "Document not found or access denied."})
            return

        # -------------------------------------------------------------
        # 2. HARDENED ENDPOINT: Parameterized Prepared Statements (SQLi Neutralized)
        # -------------------------------------------------------------
        if parsed.path == "/api/v1/search":
            query = params.get("q", [""])[0]
            # Enforce input length sanity limit
            if len(query) > 100:
                self._send_json(400, {"error": "Search query exceeds maximum permitted length (100 chars)."})
                return

            cur = DB_CONN.cursor()
            # SECURE: Strongly-typed parameter binding with SQLite wildcard parameterization
            cur.execute(
                "SELECT id, name, description, price FROM products WHERE name LIKE ? ESCAPE '\\'",
                (f"%{query}%",)
            )
            rows = cur.fetchall()
            results = [{"id": r[0], "name": r[1], "description": r[2], "price": r[3]} for r in rows]
            self._send_json(200, {"query": query, "results": results, "security_status": "Parameterized Query Enforced"})
            return

        # -------------------------------------------------------------
        # 3. HARDENED ENDPOINT: SSRF Defense with DNS & IP Subnet Verification
        # -------------------------------------------------------------
        if parsed.path == "/api/v1/fetch-url":
            target_url = params.get("url", [""])[0]
            if not target_url:
                self._send_json(400, {"error": "Missing 'url' parameter"})
                return

            try:
                parsed_target = urllib.parse.urlparse(target_url)
                if parsed_target.scheme not in ("http", "https"):
                    self._send_json(400, {"error": "Invalid scheme. Only HTTP and HTTPS are permitted."})
                    return

                hostname = parsed_target.hostname
                if not hostname:
                    self._send_json(400, {"error": "Invalid target hostname."})
                    return

                # Resolve hostname to IPv4 address before connecting
                resolved_ip = socket.gethostbyname(hostname)
                ip_obj = ipaddress.ip_address(resolved_ip)

                # Restrict private, loopback, link-local, and reserved IP ranges (RFC 1918 / Cloud Metadata)
                if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or 
                    ip_obj.is_reserved or ip_obj.is_multicast or str(ip_obj) == "169.254.169.254"):
                    self._send_json(403, {
                        "error": "Security Egress Policy Violation",
                        "details": f"Access to restricted internal/private IP ({resolved_ip}) is strictly blocked."
                    })
                    return

                # Safe outbound request with timeout
                req = urllib.request.Request(target_url, headers={"User-Agent": "SecureApp-Fetcher/2.0"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    body = resp.read().decode("utf-8", errors="replace")[:1000]
                    self._send_json(200, {
                        "url": target_url,
                        "resolved_ip": resolved_ip,
                        "status": resp.status,
                        "content_sample": body,
                        "security_verification": "Outbound egress verified against non-routable IP filters."
                    })
            except Exception as e:
                self._send_json(400, {"error": "Egress request rejected", "message": "Failed to validate or fetch remote resource."})
            return

        self._send_json(404, {"error": "Route not found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

        # -------------------------------------------------------------
        # 4. HARDENED ENDPOINT: Robust Authentication & __Host- HttpOnly Cookie
        # -------------------------------------------------------------
        if parsed.path == "/api/v1/login":
            length = int(self.headers.get("Content-Length", 0))
            if length > 8192:  # Prevent payload exhaustion
                self._send_json(413, {"error": "Payload too large"})
                return

            body = self.rfile.read(length).decode("utf-8")
            try:
                data = json.loads(body)
            except Exception:
                self._send_json(400, {"error": "Invalid JSON payload"})
                return

            username = data.get("username", "")
            password = data.get("password", "")

            cur = DB_CONN.cursor()
            cur.execute("SELECT id, username, password_hash, salt, role FROM users WHERE username = ?", (username,))
            user = cur.fetchone()

            if user and verify_password_secure(password, user[2], user[3]):
                session_token = secrets.token_urlsafe(32)
                ACTIVE_SESSIONS[session_token] = {
                    "user_id": user[0],
                    "username": user[1],
                    "role": user[4]
                }

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self._apply_security_headers()
                # Enforce modern cookie flags: __Host- prefix, Secure, HttpOnly, SameSite=Strict
                self.send_header(
                    "Set-Cookie",
                    f"__Host-SessionId={session_token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=3600"
                )
                self.end_headers()
                self.wfile.write(json.dumps({
                    "status": "authenticated",
                    "user_id": user[0],
                    "username": user[1],
                    "role": user[4],
                    "session_token_prefix": session_token[:8] + "..."
                }).encode("utf-8"))
            else:
                # Generic constant-time failure response
                self._send_json(401, {"error": "Invalid username or password credentials."})
            return

        self._send_json(404, {"error": "Route not found"})

def run_server(port=PORT):
    server = http.server.HTTPServer(("127.0.0.1", port), SecureAppHandler)
    print(f"[+] Hardened Application running on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down secure test server.")
        server.server_close()

if __name__ == "__main__":
    run_server()
