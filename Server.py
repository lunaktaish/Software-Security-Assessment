import json
import os
import time
import uuid
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from hashPass import verify_password, load_and_hash_passwords, hash_sha256_salt, hash_bcrypt, hash_argon2id
from protection import (
    check_rate_limit, record_rate_limit_attempt, reset_rate_limit,
    check_lockout, record_failed_attempt, reset_lockout,
    generate_captcha, verify_captcha,
    generate_totp_secret, get_totp_secret, generate_totp_code, verify_totp,
    get_protection_flags, after_login_attempt,
    RATE_LIMIT_ENABLED, LOCKOUT_ENABLED, CAPTCHA_ENABLED, TOTP_ENABLED, PEPPER_ENABLED
)

USER_DB_FILE = "user_db.json"
LOGGING_FILE = "logging.json"
WEB_HTML_FILE = "web.html"

GROUP_SEED = 25493314  # Group Seed number: 323047696 XOR 314945106

# =============================================================================
# CONFIGURATION
# =============================================================================
HASH_MODE = "none"  # Options: "none", "sha256_salt", "bcrypt", "argon2id"

# Track users who passed password verification but need TOTP
pending_totp = {}  # {session_id: {"username": str, "expires": timestamp}}


def get_protection_flags_str():
    """Get current protection flags as string"""
    return get_protection_flags()


def load_user_db():
    """Load user database (user_db.json) and convert to username:password format"""
    if os.path.exists(USER_DB_FILE):
        with open(USER_DB_FILE, 'r') as f:
            data = json.load(f)
            user_dict = {}
            for key, value in data.items():
                if isinstance(value, dict) and 'username' in value and 'password' in value:
                    user_dict[value['username']] = value['password']
                else:
                    user_dict[key] = value
            return user_dict
    return {}


def load_user_db_full():
    """Load full user database with all fields"""
    if os.path.exists(USER_DB_FILE):
        with open(USER_DB_FILE, 'r') as f:
            return json.load(f)
    return {}


def save_user_db(data):
    """Save user database"""
    with open(USER_DB_FILE, 'w') as f:
        json.dump(data, f, indent=2)


def load_logs():
    """Load login logs"""
    if os.path.exists(LOGGING_FILE):
        with open(LOGGING_FILE, 'r') as f:
            content = f.read().strip()
            if content:
                data = json.loads(content)
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict) and "attempts" in data:
                    return data["attempts"]
    return []


def save_log(username, password, success, latency_ms):
    """Record login attempt to log file"""
    logs = load_logs()
    
    # Count attempts for this username
    attempt_count = sum(1 for a in logs if a["username"] == username) + 1
    
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "group_seed": GROUP_SEED,
        "username": username,
        "password": password,
        "hash_mode": HASH_MODE,
        "protection_flags": get_protection_flags_str(),
        "result": success,
        "latency_ms": latency_ms,
        "attempt_number": attempt_count
    }
    
    logs.append(log_entry)
    
    with open(LOGGING_FILE, 'w') as f:
        json.dump(logs, f, indent=2)
    
    return log_entry


class LoginHandler(BaseHTTPRequestHandler):
    """HTTP request handler for login server"""
    
    def get_client_ip(self):
        """Get client IP address"""
        return self.client_address[0]
    
    def send_cors_headers(self):
        """Send CORS headers"""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
    
    def send_json_response(self, status_code, data):
        """Send JSON response"""
        self.send_response(status_code)
        self.send_header("Content-type", "application/json")
        self.send_cors_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def do_OPTIONS(self):
        """Handle preflight CORS requests"""
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()
    
    def do_GET(self):
        """Handle GET requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        query_params = parse_qs(parsed_path.query)
        
        if path == "/" or path == "/login":
            # Serve the web.html file
            if os.path.exists(WEB_HTML_FILE):
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                with open(WEB_HTML_FILE, 'r') as f:
                    self.wfile.write(f.read().encode())
            else:
                self.send_response(404)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(b"<h1>web.html not found!</h1>")
        
        elif path == "/logs":
            # View logs endpoint
            self.send_json_response(200, load_logs())
        
        elif path == "/admin/get_captcha_token":
            # Get CAPTCHA token endpoint
            group_seed = query_params.get('group_seed', [None])[0]
            
            session_id = str(uuid.uuid4())
            question, _ = generate_captcha(session_id)
            
            self.send_json_response(200, {
                "captcha_required": True,
                "captcha_token": session_id,
                "captcha_question": question,
                "group_seed": group_seed
            })
        
        elif path == "/admin/get_totp_code":
            # Get current TOTP code for a user (for testing/simulation)
            username = query_params.get('username', [None])[0]
            if username:
                code = generate_totp_code(username)
                secret = get_totp_secret(username)
                self.send_json_response(200, {
                    "username": username,
                    "totp_code": code,
                    "totp_secret": secret
                })
            else:
                self.send_json_response(400, {"error": "username required"})
        
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        """Handle POST requests"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else "{}"
        
        try:
            data = json.loads(post_data)
        except json.JSONDecodeError:
            self.send_json_response(400, {"success": False, "message": "Invalid JSON"})
            return
        
        if path == "/register":
            self.handle_register(data)
        
        elif path == "/login" or path == "/api/login":
            self.handle_login(data)
        
        elif path == "/login_totp":
            self.handle_login_totp(data)
        
        else:
            self.send_response(404)
            self.end_headers()
    
    def handle_register(self, data):
        """Handle user registration"""
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        
        if not username or not password:
            self.send_json_response(400, {
                "success": False,
                "message": "Username and password required"
            })
            return
        
        # Load current database
        user_db = load_user_db_full()
        
        # Check if username already exists
        for key, value in user_db.items():
            if isinstance(value, dict) and value.get('username') == username:
                self.send_json_response(400, {
                    "success": False,
                    "message": "Username already exists"
                })
                return
        
        # Generate TOTP secret for new user
        totp_secret = generate_totp_secret(username)
        
        # Create new user entry
        new_user_id = f"user_db{len(user_db) + 1}"
        user_db[new_user_id] = {
            "username": username,
            "password": password,
            "totp_secret": totp_secret
        }
        
        # Save database
        save_user_db(user_db)
        
        # Reload hashed passwords if hashing is enabled
        if HASH_MODE != "none":
            load_and_hash_passwords(HASH_MODE)
        
        self.send_json_response(200, {
            "success": True,
            "message": "User registered successfully",
            "totp_secret": totp_secret
        })
    
    def handle_login(self, data):
        """Handle login request"""
        start_time = time.time()
        
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        captcha_token = data.get('captcha_token')
        captcha_answer = data.get('captcha_answer')
        
        ip_address = self.get_client_ip()
        
        # Check rate limit
        if RATE_LIMIT_ENABLED:
            rate_allowed, remaining, reset_time = check_rate_limit(ip_address)
            if not rate_allowed:
                latency_ms = round((time.time() - start_time) * 1000, 2)
                save_log(username, password, False, latency_ms)
                self.send_json_response(429, {
                    "success": False,
                    "message": f"Rate limit exceeded. Try again in {reset_time} seconds.",
                    "retry_after": reset_time
                })
                return
        
        # Check lockout
        if LOCKOUT_ENABLED:
            locked, lock_remaining = check_lockout(username)
            if locked:
                latency_ms = round((time.time() - start_time) * 1000, 2)
                save_log(username, password, False, latency_ms)
                self.send_json_response(423, {
                    "success": False,
                    "message": f"Account locked. Try again in {lock_remaining} seconds.",
                    "locked_for": lock_remaining
                })
                return
        
        # Check CAPTCHA if enabled
        if CAPTCHA_ENABLED:
            if not captcha_token or not captcha_answer:
                # Generate new CAPTCHA
                session_id = str(uuid.uuid4())
                question, _ = generate_captcha(session_id)
                latency_ms = round((time.time() - start_time) * 1000, 2)
                self.send_json_response(200, {
                    "success": False,
                    "captcha_required": True,
                    "captcha_token": session_id,
                    "captcha_question": question,
                    "message": "CAPTCHA required"
                })
                return
            else:
                if not verify_captcha(captcha_token, captcha_answer):
                    latency_ms = round((time.time() - start_time) * 1000, 2)
                    save_log(username, password, False, latency_ms)
                    self.send_json_response(400, {
                        "success": False,
                        "message": "Invalid CAPTCHA"
                    })
                    return
        
        # Load user database and verify password
        user_db = load_user_db()
        
        success = False
        if username in user_db:
            stored_password = user_db[username]
            success = verify_password(password, stored_password, HASH_MODE, username)
        
        # Record rate limit attempt
        if RATE_LIMIT_ENABLED:
            record_rate_limit_attempt(ip_address)
        
        if success:
            # Check if TOTP is enabled
            if TOTP_ENABLED:
                # Password correct, but need TOTP
                session_id = str(uuid.uuid4())
                pending_totp[session_id] = {
                    "username": username,
                    "expires": time.time() + 300  # 5 minutes
                }
                
                latency_ms = round((time.time() - start_time) * 1000, 2)
                self.send_json_response(200, {
                    "success": False,
                    "totp_required": True,
                    "totp_session": session_id,
                    "message": "TOTP code required"
                })
                return
            
            # Login successful (no TOTP)
            reset_lockout(username)
            reset_rate_limit(ip_address)
            
            latency_ms = round((time.time() - start_time) * 1000, 2)
            log_entry = save_log(username, password, True, latency_ms)
            
            self.send_json_response(200, {
                "success": True,
                "message": "Authentication successful",
                "attempt_number": log_entry['attempt_number']
            })
        else:
            # Login failed
            if LOCKOUT_ENABLED:
                record_failed_attempt(username)
            
            latency_ms = round((time.time() - start_time) * 1000, 2)
            log_entry = save_log(username, password, False, latency_ms)
            
            self.send_json_response(401, {
                "success": False,
                "message": "Invalid username or password",
                "attempt_number": log_entry['attempt_number']
            })
    
    def handle_login_totp(self, data):
        """Handle TOTP verification (second factor)"""
        start_time = time.time()
        
        totp_session = data.get('totp_session', '')
        totp_code = data.get('totp_code', '')
        
        # Check if session exists and is valid
        if totp_session not in pending_totp:
            self.send_json_response(400, {
                "success": False,
                "message": "Invalid or expired TOTP session"
            })
            return
        
        session_data = pending_totp[totp_session]
        
        # Check expiration
        if time.time() > session_data["expires"]:
            del pending_totp[totp_session]
            self.send_json_response(400, {
                "success": False,
                "message": "TOTP session expired"
            })
            return
        
        username = session_data["username"]
        
        # Verify TOTP code
        if verify_totp(username, totp_code):
            # TOTP verified, login successful
            del pending_totp[totp_session]
            
            ip_address = self.get_client_ip()
            reset_lockout(username)
            reset_rate_limit(ip_address)
            
            latency_ms = round((time.time() - start_time) * 1000, 2)
            log_entry = save_log(username, "[TOTP]", True, latency_ms)
            
            self.send_json_response(200, {
                "success": True,
                "message": "Authentication successful (TOTP verified)",
                "attempt_number": log_entry['attempt_number']
            })
        else:
            latency_ms = round((time.time() - start_time) * 1000, 2)
            save_log(username, "[TOTP_FAILED]", False, latency_ms)
            
            self.send_json_response(401, {
                "success": False,
                "message": "Invalid TOTP code"
            })


def run_server(port=8080):
    """Start the HTTP server"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, LoginHandler)
    print(f"\n{'='*50}")
    print(f"  Software Security Assessment Server")
    print(f"{'='*50}")
    print(f"\nServer running on http://localhost:{port}")
    print(f"\nEndpoints:")
    print(f"  GET  /                - Login page")
    print(f"  GET  /logs            - View logs")
    print(f"  GET  /admin/get_captcha_token?group_seed=XXX")
    print(f"  GET  /admin/get_totp_code?username=XXX")
    print(f"  POST /register        - Register new user")
    print(f"  POST /login           - Login with password")
    print(f"  POST /login_totp      - Verify TOTP code")
    print(f"\nConfiguration:")
    print(f"  Hash Mode: {HASH_MODE}")
    print(f"  Protections: {get_protection_flags_str()}")
    print(f"  GROUP_SEED: {GROUP_SEED}")
    print(f"\nPress Ctrl+C to stop the server\n")
    httpd.serve_forever()


if __name__ == "__main__":
    if not os.path.exists(LOGGING_FILE):
        with open(LOGGING_FILE, 'w') as f:
            json.dump([], f)
    
    # Load and hash passwords if hashing is enabled
    if HASH_MODE != "none":
        print(f"Loading and hashing passwords with {HASH_MODE}...")
        load_and_hash_passwords(HASH_MODE)
    
    run_server()
