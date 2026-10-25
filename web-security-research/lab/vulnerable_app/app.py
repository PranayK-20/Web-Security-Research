"""
Vulnerable Web Application Lab Target (Educational & Research Demonstration)
WARNING: This application contains deliberate security vulnerabilities for research,
evaluation, and defensive benchmarking purposes only. Do NOT deploy in production.

OWASP Alignment:
- A01:2021 / API1:2023: Broken Object Level Authorization (BOLA/IDOR)
- A03:2021: SQL Injection (SQLi)
- A02:2021: Cryptographic Failures & Weak Session Management
- A05:2021: Security Misconfiguration (Missing Security Headers & Information Disclosure)
- A10:2021 / API7:2023: Server-Side Request Forgery (SSRF)
"""

import http.server
import json
import sqlite3
import urllib.parse
import urllib.request
import hashlib

PORT = 5001

def init_vulnerable_db():
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    # Users table with weak MD5 hashed password
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);")
    cur.execute("INSERT INTO users VALUES (1, 'alice', ?, 'user');", (hashlib.md5(b"password123").hexdigest(),))
    cur.execute("INSERT INTO users VALUES (2, 'bob', ?, 'user');", (hashlib.md5(b"bob_secret").hexdigest(),))
    cur.execute("INSERT INTO users VALUES (3, 'admin', ?, 'administrator');", (hashlib.md5(b"admin_vault_2026").hexdigest(),))

    # Documents table (for BOLA / IDOR testing)
    cur.execute("CREATE TABLE documents (id INTEGER PRIMARY KEY, owner_id INTEGER, title TEXT, content TEXT);")
    cur.execute("INSERT INTO documents VALUES (101, 1, 'Alice Q1 Review', 'Confidential salary data: $140,000');")
    cur.execute("INSERT INTO documents VALUES (102, 2, 'Bob Medical Records', 'Private health diagnosis data.');")
    cur.execute("INSERT INTO documents VALUES (103, 3, 'Enterprise Master Key', 'AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE');")

    # Products table (for SQL Injection testing)
    cur.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, description TEXT, price REAL);")
    cur.execute("INSERT INTO products VALUES (1, 'Ergonomic Keyboard', 'Wireless split keyboard', 129.99);")
    cur.execute("INSERT INTO products VALUES (2, '4K Monitor', '32-inch IPS display', 399.50);")
    cur.execute("INSERT INTO products VALUES (3, 'Security Token', 'Hardware FIDO2 authenticator', 45.00);")
    conn.commit()
    return conn

DB_CONN = init_vulnerable_db()

class VulnerableAppHandler(http.server.BaseHTTPRequestHandler):
    server_version = "Apache/2.4.41 (Ubuntu) PHP/7.4.3"  # VULNERABLE: Verbose banner exposure
    sys_version = ""

    def _send_json(self, status_code, payload):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        # VULNERABLE: Deliberately missing all security headers (CSP, HSTS, X-Content-Type-Options, etc.)
        self.send_header("Access-Control-Allow-Origin", "*")  # VULNERABLE: Insecure CORS wildcard
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        # -------------------------------------------------------------
        # 1. Health check & index
        # -------------------------------------------------------------
        if parsed.path == "/":
            self._send_json(200, {
                "status": "online",
                "app": "Vulnerable Research Target (v1.0.0)",
                "endpoints": [
                    "/api/v1/document?id=<id>",
                    "/api/v1/search?q=<query>",
                    "/api/v1/fetch-url?url=<url>",
                    "/api/v1/login (POST)"
                ]
            })
            return

        # -------------------------------------------------------------
        # 2. VULNERABLE ENDPOINT: Broken Object Level Authorization (BOLA / IDOR)
        # Any caller can view documents of ANY user without authentication or ownership check
        # -------------------------------------------------------------
        if parsed.path == "/api/v1/document":
            doc_id = params.get("id", [""])[0]
            if not doc_id:
                self._send_json(400, {"error": "Missing 'id' parameter"})
                return

            cur = DB_CONN.cursor()
            # Flaw: Queries directly by ID without scoping to authenticated session user
            cur.execute("SELECT id, owner_id, title, content FROM documents WHERE id = ?", (doc_id,))
            row = cur.fetchone()
            if row:
                self._send_json(200, {
                    "document_id": row[0],
                    "owner_id": row[1],
                    "title": row[2],
                    "content": row[3],
                    "vulnerability_notice": "BOLA / IDOR: Returned document without checking user permissions."
                })
            else:
                self._send_json(404, {"error": "Document not found"})
            return

        # -------------------------------------------------------------
        # 3. VULNERABLE ENDPOINT: Raw SQL Injection
        # Directly concatenates query string into SQL statement
        # -------------------------------------------------------------
        if parsed.path == "/api/v1/search":
            query = params.get("q", [""])[0]
            cur = DB_CONN.cursor()
            # VULNERABLE: Direct string concatenation
            raw_sql = f"SELECT id, name, description, price FROM products WHERE name LIKE '%{query}%'"
            try:
                cur.execute(raw_sql)
                rows = cur.fetchall()
                results = [{"id": r[0], "name": r[1], "description": r[2], "price": r[3]} for r in rows]
                self._send_json(200, {"query": query, "executed_sql": raw_sql, "results": results})
            except Exception as e:
                # VULNERABLE: Verbose internal SQL error disclosure
                self._send_json(500, {"error": "Database error", "details": str(e), "executed_sql": raw_sql})
            return

        # -------------------------------------------------------------
        # 4. VULNERABLE ENDPOINT: Server-Side Request Forgery (SSRF)
        # Backend blindly fetches arbitrary user-supplied URL without IP/subnet validation
        # -------------------------------------------------------------
        if parsed.path == "/api/v1/fetch-url":
            target_url = params.get("url", [""])[0]
            if not target_url:
                self._send_json(400, {"error": "Missing 'url' parameter"})
                return

            try:
                # Flaw: No IP address check, no allowlist, connects directly to intranet/loopback/cloud metadata
                req = urllib.request.Request(target_url, headers={"User-Agent": "VulnerableApp-Fetcher/1.0"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    body = resp.read().decode("utf-8", errors="replace")[:1000]
                    self._send_json(200, {
                        "url": target_url,
                        "status": resp.status,
                        "content_sample": body,
                        "vulnerability_notice": "SSRF: Backend fetched unvalidated URL."
                    })
            except Exception as e:
                self._send_json(500, {"error": "Failed to fetch URL", "details": str(e)})
            return

        self._send_json(404, {"error": "Route not found"})

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

        # -------------------------------------------------------------
        # 5. VULNERABLE ENDPOINT: Insecure Authentication & Weak Session Cookie
        # -------------------------------------------------------------
        if parsed.path == "/api/v1/login":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            try:
                data = json.loads(body)
            except Exception:
                data = urllib.parse.parse_qs(body)
                data = {k: v[0] for k, v in data.items()}

            username = data.get("username", "")
            password = data.get("password", "")

            # Weak MD5 hashing
            hashed = hashlib.md5(password.encode("utf-8")).hexdigest()
            cur = DB_CONN.cursor()
            cur.execute("SELECT id, username, role FROM users WHERE username = ? AND password = ?", (username, hashed))
            user = cur.fetchone()

            if user:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                # VULNERABLE: Insecure session cookie (Missing HttpOnly, Secure, SameSite flags)
                self.send_header("Set-Cookie", f"session_id=insecure_token_for_{user[1]}; Path=/")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "status": "authenticated",
                    "user_id": user[0],
                    "username": user[1],
                    "role": user[2],
                    "warning": "Cookie missing Secure, HttpOnly, and SameSite attributes."
                }).encode("utf-8"))
            else:
                self._send_json(401, {"error": "Authentication failed: invalid username or password."})
            return

        self._send_json(404, {"error": "Route not found"})

def run_server(port=PORT):
    server = http.server.HTTPServer(("127.0.0.1", port), VulnerableAppHandler)
    print(f"[!] Vulnerable Application running on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down vulnerable test server.")
        server.server_close()

if __name__ == "__main__":
    run_server()
