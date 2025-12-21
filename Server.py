import os
import json
import time
import hashlib
import secrets
import bcrypt
import argon2
import pyotp
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse
from collections import defaultdict

GROUP_SEED = 25493314 #Group Seed number: 323047696 XOR 314945106

# Environment-based configuration 
HASH_MODE = os.getenv('HASH_MODE', 'bcrypt')  # Options: sha256, bcrypt, argon2id
PEPPER = os.getenv('PEPPER', secrets.token_hex(32))  # Loaded from environment
RATE_LIMIT_REQUESTS = int(os.getenv('RATE_LIMIT_REQUESTS', '5'))
RATE_LIMIT_WINDOW = int(os.getenv('RATE_LIMIT_WINDOW', '60'))  # seconds
LOCKOUT_ATTEMPTS = int(os.getenv('LOCKOUT_ATTEMPTS', '5'))
LOCKOUT_DURATION = int(os.getenv('LOCKOUT_DURATION', '300'))  # seconds
ENABLE_CAPTCHA = os.getenv('ENABLE_CAPTCHA', 'false').lower() == 'true'
ENABLE_TOTP = os.getenv('ENABLE_TOTP', 'false').lower() == 'true'
LOG_FILE = os.getenv('LOG_FILE', 'auth_attempts.jsonl')
CONNECTION_LOG_FILE = 'logging.json'

# In-memory storage (not database)
USERS_FILE = 'users.json'
users_db = {}  # {username: {password_hash, salt, totp_secret, lockout_until, failed_attempts}}
rate_limit_db = defaultdict(list)  # {ip: [timestamps]}
lockout_db = {}  # {username: lockout_until_timestamp}
captcha_tokens = {}  # {username: token} for CAPTCHA simulation

# User persistence functions
def load_users():
    """Load users from users.json file"""
    global users_db
    try:
        if os.path.isfile(USERS_FILE):
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                users_db = json.load(f)
        else:
            users_db = {}
    except Exception as e:
        print(f"Error loading users: {e}")
        users_db = {}

def save_users():
    """Save users to users.json file"""
    try:
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users_db, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Error saving users: {e}")

# Password hashing functions
def hash_password_sha256(password, salt, pepper):
    """Hash password using SHA-256 with salt and pepper"""
    combined = password + salt + pepper
    return hashlib.sha256(combined.encode()).hexdigest()

def hash_password_bcrypt(password, pepper):
    """Hash password using bcrypt with pepper (cost=12)"""
    combined = password + pepper
    return bcrypt.hashpw(combined.encode(), bcrypt.gensalt(rounds=12)).decode()

def hash_password_argon2id(password, pepper):
    """Hash password using Argon2id with pepper"""
    combined = password + pepper
    ph = argon2.PasswordHasher()
    return ph.hash(combined)

def verify_password(password, stored_hash, salt=None, pepper=PEPPER):
    """Verify password based on configured hash mode"""
    if HASH_MODE == 'sha256':
        if not salt:
            return False
        computed_hash = hash_password_sha256(password, salt, pepper)
        return computed_hash == stored_hash
    elif HASH_MODE == 'bcrypt':
        combined = password + pepper
        try:
            return bcrypt.checkpw(combined.encode(), stored_hash.encode())
        except:
            return False
    elif HASH_MODE == 'argon2id':
        combined = password + pepper
        try:
            ph = argon2.PasswordHasher()
            ph.verify(stored_hash, combined)
            return True
        except:
            return False
    return False

# Security functions
def check_rate_limit(ip_address):
    """Check if IP address has exceeded rate limit"""
    now = time.time()
    timestamps = rate_limit_db[ip_address]
    # Remove old timestamps outside the window
    timestamps[:] = [ts for ts in timestamps if now - ts < RATE_LIMIT_WINDOW]
    
    if len(timestamps) >= RATE_LIMIT_REQUESTS:
        return False
    timestamps.append(now)
    return True

def check_lockout(username):
    """Check if username is locked out"""
    if username in lockout_db:
        if time.time() < lockout_db[username]:
            return True
        else:
            del lockout_db[username]
            if username in users_db:
                users_db[username]['failed_attempts'] = 0
                save_users()  # Persist to file
    return False

def record_failed_attempt(username):
    """Record a failed login attempt and lockout if needed"""
    if username not in users_db:
        users_db[username] = {'failed_attempts': 0}
        save_users()  # Persist new user entry
    
    users_db[username]['failed_attempts'] = users_db[username].get('failed_attempts', 0) + 1
    save_users()  # Persist to file
    
    if users_db[username]['failed_attempts'] >= LOCKOUT_ATTEMPTS:
        lockout_db[username] = time.time() + LOCKOUT_DURATION
        return True
    return False

def reset_failed_attempts(username):
    """Reset failed attempts on successful login"""
    if username in users_db:
        users_db[username]['failed_attempts'] = 0
        save_users()  
    if username in lockout_db:
        del lockout_db[username]

def generate_captcha_token(username):
    """Generate a CAPTCHA simulation token"""
    token = secrets.token_hex(8)
    captcha_tokens[username] = token
    return token

def verify_captcha_token(username, token):
    """Verify CAPTCHA simulation token"""
    if username in captcha_tokens:
        return captcha_tokens[username] == token
    return False

# Logging function
def log_attempt(timestamp, group_seed, username, hash_mode, protection_flags, result, latency_ms):
    """Log authentication attempt to JSON (JSONL format) with required fields"""
    log_entry = {
        'timestamp': timestamp,
        'group_seed': group_seed,
        'username': username,
        'hash_mode': hash_mode,
        'protection_flags': protection_flags,
        'result': result,
        'latency_ms': latency_ms
    }
    
    # Write to JSONL format
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps(log_entry) + '\n')

def log_connection(method, path, ip_address, username=None, latency_ms=0):
    """Log every connection to the site in logging.json"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'method': method,
        'path': path,
        'ip_address': ip_address,
        'username': username if username else '',
        'user_exists': username in users_db if username else False,
        'latency_ms': latency_ms
    }
    
    # Write to logging.json 
    try:
        logs = []
        if os.path.isfile(CONNECTION_LOG_FILE):
            try:
                with open(CONNECTION_LOG_FILE, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    if content:
                        logs = json.loads(content)
                        if not isinstance(logs, list):
                            logs = []
            except:
                logs = []
        
        # Append new log entry
        logs.append(log_entry)
        
        # Write back to file
        with open(CONNECTION_LOG_FILE, 'w', encoding='utf-8') as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Error logging connection: {e}")

def log_login_attempt(username, password, success):
    """Log login attempts to logging.json with username, password, and result"""
    log_entry = {
        'username': username,
        'password': password,
        'result': 'succeed' if success else 'sorry but you contact is not exist'
    }
    
    # Write to logging.json 
    try:
        logs = []
        if os.path.isfile(CONNECTION_LOG_FILE):
            try:
                with open(CONNECTION_LOG_FILE, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                    if content:
                        logs = json.loads(content)
                        if not isinstance(logs, list):
                            logs = []
            except:
                logs = []
        
        # Append new log entry
        logs.append(log_entry)
        
        # Write back to file
        with open(CONNECTION_LOG_FILE, 'w', encoding='utf-8') as f:
            json.dump(logs, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Error logging login attempt: {e}")

class Handler(BaseHTTPRequestHandler):
    def get_client_ip(self):
        """Get client IP address"""
        return self.client_address[0]
    
    def send_json_response(self, status_code, data):
        """Send JSON response"""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))
        self.wfile.flush()
    
    def send_html_response(self, status_code, html_content):
        """Send HTML response"""
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html_content.encode("utf-8"))
        self.wfile.flush()
    
    def parse_json_body(self):
        """Parse JSON request body"""
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            return {}
        body = self.rfile.read(content_length).decode('utf-8')
        try:
            return json.loads(body)
        except:
            return {}
    
    def do_GET(self):
        """Handle GET requests"""
        start_time = time.time()
        ip_address = self.get_client_ip()
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        # Log connection
        latency_ms = int((time.time() - start_time) * 1000)
        log_connection('GET', path, ip_address, latency_ms=latency_ms)
        
        if self.path == "/":
            html = """<!DOCTYPE html>
<html>
<head>
    <title>Software Security Assessment</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f0f0f0;
        }
        .login-box {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            width: 300px;
        }
        h1 {
            text-align: center;
            color: #52169c;
            margin-top: 0;
        }
        form {
            width: 100%;
        }
        input {
            display: block;
            width: 100%;
            min-width: 250px;
            padding: 12px;
            margin: 10px 0;
            border: 2px solid #ddd;
            border-radius: 5px;
            box-sizing: border-box;
            font-size: 14px;
        }
        input:focus {
            outline: none;
            border-color: #52169c;
        }
        button {
            display: block;
            width: 100%;
            padding: 12px;
            margin-top: 15px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background-color: #45a049;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h1>Software Security Assessment</h1>
        <form method="POST" action="/">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>"""
            self.send_html_response(200, html)
        else:
            self.send_json_response(404, {'error': 'Not found'})
    
    def do_POST(self):
        """Handle POST requests"""
        start_time = time.time()
        ip_address = self.get_client_ip()
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        # Handle form submission to "/"
        if self.path == "/":
            # Read the POST data
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                post_data = self.rfile.read(content_length).decode('utf-8')
            else:
                post_data = ''
            
            # Parse form data
            form_data = parse_qs(post_data)
            username = form_data.get('username', [''])[0]
            password = form_data.get('password', [''])[0]
            
            # Log login attempt immediately (before validation)
            login_success = False
            
            # Check if user exists and password is correct
            if username in users_db:
                user = users_db[username]
                if verify_password(password, user['password_hash'], user.get('salt'), PEPPER):
                    login_success = True
                    reset_failed_attempts(username)
                else:
                    record_failed_attempt(username)
            else:
                # User doesn't exist - record failed attempt for non-existent user
                if username:
                    record_failed_attempt(username)
            
            # Log the attempt with result
            log_login_attempt(username, password, login_success)
            
            # Show success or failure page
            if login_success:
                html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Software Security Assessment - Success</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f0f0f0;
        }}
        .success-box {{
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        h1 {{
            color: #4CAF50;
        }}
        a {{
            color: #52169c;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="success-box">
        <h1>Login Successful!</h1>
        <p>Welcome, {username}!</p>
        <a href="/">Back to Login</a>
    </div>
</body>
</html>"""
            else:
                html = """<!DOCTYPE html>
<html>
<head>
    <title>Software Security Assessment - Failed</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background-color: #f0f0f0;
        }
        .failure-box {
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        h1 {
            color: #f44336;
        }
        a {
            color: #52169c;
            text-decoration: none;
            display: inline-block;
            margin-top: 15px;
            padding: 10px 20px;
            background-color: #52169c;
            color: white;
            border-radius: 5px;
        }
        a:hover {
            background-color: #42158c;
        }
    </style>
</head>
<body>
    <div class="failure-box">
        <h1>Login Failed</h1>
        <p>Sorry, but your contact does not exist.</p>
        <a href="/">Try to Login Again</a>
    </div>
</body>
</html>"""
            self.send_html_response(200, html)
            return
        
        # Check rate limiting for API endpoints
        if not check_rate_limit(ip_address):
            latency_ms = int((time.time() - start_time) * 1000)
            log_attempt(
                datetime.now().isoformat(),
                GROUP_SEED,
                '',
                HASH_MODE,
                'rate_limit',
                'rate_limit_exceeded',
                latency_ms
            )
            # Log connection
            log_connection('POST', path, ip_address, None, latency_ms)
            self.send_json_response(429, {'error': 'Rate limit exceeded'})
            return
        
        # Parse request body once for logging
        data = self.parse_json_body()
        username = data.get('username', '') if data else ''
        
        # Log connection with username check (skip for login endpoints - they use log_login_attempt instead)
        if path not in ['/login', '/login_totp']:
            latency_ms = int((time.time() - start_time) * 1000)
            log_connection('POST', path, ip_address, username if username else None, latency_ms)
        
        # Route to appropriate handler (they will parse body again, but that's okay)
        if path == '/register':
            self.handle_register(start_time, data)
        elif path == '/login':
            self.handle_login(start_time, ip_address, data)
        elif path == '/login_totp':
            self.handle_login_totp(start_time, ip_address, data)
        else:
            self.send_json_response(404, {'error': 'Not found'})
    
    def handle_register(self, start_time, data=None):
        """Handle user registration"""
        try:
            if data is None:
                data = self.parse_json_body()
            username = data.get('username', '')
            password = data.get('password', '')
            
            if not username or not password:
                latency_ms = int((time.time() - start_time) * 1000)
                log_attempt(
                    datetime.now().isoformat(),
                    GROUP_SEED,
                    username,
                    HASH_MODE,
                    'none',
                    'registration_failed_missing_fields',
                    latency_ms
                )
                self.send_json_response(400, {'error': 'Username and password required'})
                return
            
            if username in users_db:
                latency_ms = int((time.time() - start_time) * 1000)
                log_attempt(
                    datetime.now().isoformat(),
                    GROUP_SEED,
                    username,
                    HASH_MODE,
                    'none',
                    'registration_failed_user_exists',
                    latency_ms
                )
                self.send_json_response(409, {'error': 'Username already exists'})
                return
            
            # Generate salt for SHA-256
            salt = secrets.token_hex(16) if HASH_MODE == 'sha256' else None
            
            # Hash password based on configured mode
            if HASH_MODE == 'sha256':
                password_hash = hash_password_sha256(password, salt, PEPPER)
            elif HASH_MODE == 'bcrypt':
                password_hash = hash_password_bcrypt(password, PEPPER)
            elif HASH_MODE == 'argon2id':
                password_hash = hash_password_argon2id(password, PEPPER)
            else:
                password_hash = hash_password_bcrypt(password, PEPPER)
            
            # Generate TOTP secret if enabled
            totp_secret = pyotp.random_base32() if ENABLE_TOTP else None
            
            # Store user
            users_db[username] = {
                'password_hash': password_hash,
                'salt': salt,
                'totp_secret': totp_secret,
                'failed_attempts': 0
            }
            save_users()  
            
            latency_ms = int((time.time() - start_time) * 1000)
            
            log_attempt(
                datetime.now().isoformat(),
                GROUP_SEED,
                username,
                HASH_MODE,
                'none',
                'registration_success',
                latency_ms
            )
            
            response = {'message': 'User registered successfully', 'username': username}
            if ENABLE_TOTP and totp_secret:
                response['totp_secret'] = totp_secret
                response['totp_uri'] = pyotp.totp.TOTP(totp_secret).provisioning_uri(username, issuer_name="Security Assessment")
            
            self.send_json_response(201, response)
        except Exception as e:
            latency_ms = int((time.time() - start_time) * 1000)
            error_msg = str(e)
            print(f"Registration error: {error_msg}")  # Debug output
            log_attempt(
                datetime.now().isoformat(),
                GROUP_SEED,
                '',
                HASH_MODE,
                'none',
                f'registration_error: {error_msg}',
                latency_ms
            )
            self.send_json_response(500, {'error': f'Internal server error: {error_msg}'})
    
    def handle_login(self, start_time, ip_address):
        """Handle login with username and password"""
        try:
            data = self.parse_json_body()
            username = data.get('username', '')
            password = data.get('password', '')
            captcha_token = data.get('captcha_token', '')
            
            protection_flags = []
            
            # Check lockout
            if check_lockout(username):
                protection_flags.append('lockout')
                latency_ms = int((time.time() - start_time) * 1000)
                log_attempt(
                    datetime.now().isoformat(),
                    GROUP_SEED,
                    username,
                    HASH_MODE,
                    ','.join(protection_flags),
                    'login_failed_locked',
                    latency_ms
                )
                # Log to logging.json
                log_login_attempt(username, password, False)
                self.send_json_response(423, {'error': 'Account locked'})
                return
            
            # Check CAPTCHA if enabled
            if ENABLE_CAPTCHA:
                protection_flags.append('captcha')
                if not captcha_token:
                    # Generate and return CAPTCHA token for simulation
                    token = generate_captcha_token(username)
                    latency_ms = int((time.time() - start_time) * 1000)
                    log_attempt(
                        datetime.now().isoformat(),
                        GROUP_SEED,
                        username,
                        HASH_MODE,
                        ','.join(protection_flags),
                        'login_failed_captcha_required',
                        latency_ms
                    )
                    # Log to logging.json
                    log_login_attempt(username, password, False)
                    self.send_json_response(400, {'error': 'CAPTCHA token required', 'captcha_required': True, 'captcha_token': token})
                    return
                
                # Verify CAPTCHA token
                if not verify_captcha_token(username, captcha_token):
                    latency_ms = int((time.time() - start_time) * 1000)
                    log_attempt(
                        datetime.now().isoformat(),
                        GROUP_SEED,
                        username,
                        HASH_MODE,
                        ','.join(protection_flags),
                        'login_failed_captcha_invalid',
                        latency_ms
                    )
                    # Log to logging.json
                    log_login_attempt(username, password, False)
                    self.send_json_response(400, {'error': 'Invalid CAPTCHA token'})
                    return
            
            # Verify user exists
            if username not in users_db:
                latency_ms = int((time.time() - start_time) * 1000)
                log_attempt(
                    datetime.now().isoformat(),
                    GROUP_SEED,
                    username,
                    HASH_MODE,
                    ','.join(protection_flags) if protection_flags else 'none',
                    'login_failed_user_not_found',
                    latency_ms
                )
                # Log to logging.json
                log_login_attempt(username, password, False)
                self.send_json_response(401, {'error': 'Invalid credentials'})
                return
            
            # Verify password
            user = users_db[username]
            if verify_password(password, user['password_hash'], user.get('salt'), PEPPER):
                reset_failed_attempts(username)
                latency_ms = int((time.time() - start_time) * 1000)
                
                log_attempt(
                    datetime.now().isoformat(),
                    GROUP_SEED,
                    username,
                    HASH_MODE,
                    ','.join(protection_flags) if protection_flags else 'none',
                    'login_success',
                    latency_ms
                )
                
                # Log to logging.json
                log_login_attempt(username, password, True)
                
                self.send_json_response(200, {'message': 'Login successful', 'username': username})
            else:
                record_failed_attempt(username)
                latency_ms = int((time.time() - start_time) * 1000)
                log_attempt(
                    datetime.now().isoformat(),
                    GROUP_SEED,
                    username,
                    HASH_MODE,
                    ','.join(protection_flags) if protection_flags else 'none',
                    'login_failed_invalid_password',
                    latency_ms
                )
                # Log to logging.json
                log_login_attempt(username, password, False)
                self.send_json_response(401, {'error': 'Invalid credentials'})
        except Exception as e:
            latency_ms = int((time.time() - start_time) * 1000)
            log_attempt(
                datetime.now().isoformat(),
                GROUP_SEED,
                '',
                HASH_MODE,
                'none',
                f'login_error: {str(e)}',
                latency_ms
            )
            # Log to logging.json (try to get username/password from data if available)
            try:
                username = data.get('username', '') if data else ''
                password = data.get('password', '') if data else ''
                log_login_attempt(username, password, False)
            except:
                pass
            self.send_json_response(500, {'error': 'Internal server error'})
    
    def handle_login_totp(self, start_time, ip_address, data=None):
        """Handle login with username, password, and TOTP"""
        try:
            if data is None:
                data = self.parse_json_body()
            username = data.get('username', '')
            password = data.get('password', '')
            totp_code = data.get('totp_code', '')
            
            protection_flags = ['totp']
            
            # Check lockout
            if check_lockout(username):
                protection_flags.append('lockout')
                latency_ms = int((time.time() - start_time) * 1000)
                log_attempt(
                    datetime.now().isoformat(),
                    GROUP_SEED,
                    username,
                    HASH_MODE,
                    ','.join(protection_flags),
                    'login_totp_failed_locked',
                    latency_ms
                )
                # Log to logging.json
                log_login_attempt(username, password, False)
                self.send_json_response(423, {'error': 'Account locked'})
                return
            
            # Verify user exists
            if username not in users_db:
                latency_ms = int((time.time() - start_time) * 1000)
                log_attempt(
                    datetime.now().isoformat(),
                    GROUP_SEED,
                    username,
                    HASH_MODE,
                    ','.join(protection_flags),
                    'login_totp_failed_user_not_found',
                    latency_ms
                )
                # Log to logging.json
                log_login_attempt(username, password, False)
                self.send_json_response(401, {'error': 'Invalid credentials'})
                return
            
            user = users_db[username]
            
            # Verify password
            if not verify_password(password, user['password_hash'], user.get('salt'), PEPPER):
                record_failed_attempt(username)
                latency_ms = int((time.time() - start_time) * 1000)
                log_attempt(
                    datetime.now().isoformat(),
                    GROUP_SEED,
                    username,
                    HASH_MODE,
                    ','.join(protection_flags),
                    'login_totp_failed_invalid_password',
                    latency_ms
                )
                # Log to logging.json
                log_login_attempt(username, password, False)
                self.send_json_response(401, {'error': 'Invalid credentials'})
                return
            
            # Verify TOTP
            if not ENABLE_TOTP or not user.get('totp_secret'):
                latency_ms = int((time.time() - start_time) * 1000)
                log_attempt(
                    datetime.now().isoformat(),
                    GROUP_SEED,
                    username,
                    HASH_MODE,
                    ','.join(protection_flags),
                    'login_totp_failed_totp_not_enabled',
                    latency_ms
                )
                # Log to logging.json
                log_login_attempt(username, password, False)
                self.send_json_response(400, {'error': 'TOTP not enabled for this user'})
                return
            
            totp = pyotp.TOTP(user['totp_secret'])
            if not totp.verify(totp_code, valid_window=1):
                record_failed_attempt(username)
                latency_ms = int((time.time() - start_time) * 1000)
                log_attempt(
                    datetime.now().isoformat(),
                    GROUP_SEED,
                    username,
                    HASH_MODE,
                    ','.join(protection_flags),
                    'login_totp_failed_invalid_totp',
                    latency_ms
                )
                # Log to logging.json
                log_login_attempt(username, password, False)
                self.send_json_response(401, {'error': 'Invalid TOTP code'})
                return
            
            # Success
            reset_failed_attempts(username)
            latency_ms = int((time.time() - start_time) * 1000)
            
            log_attempt(
                datetime.now().isoformat(),
                GROUP_SEED,
                username,
                HASH_MODE,
                ','.join(protection_flags),
                'login_totp_success',
                latency_ms
            )
            
            # Log to logging.json
            log_login_attempt(username, password, True)
            
            self.send_json_response(200, {'message': 'TOTP login successful', 'username': username})
        except Exception as e:
            latency_ms = int((time.time() - start_time) * 1000)
            log_attempt(
                datetime.now().isoformat(),
                GROUP_SEED,
                '',
                HASH_MODE,
                'totp',
                f'login_totp_error: {str(e)}',
                latency_ms
            )
            # Log to logging.json (try to get username/password from data if available)
            try:
                username = data.get('username', '') if data else ''
                password = data.get('password', '') if data else ''
                log_login_attempt(username, password, False)
            except:
                pass
            self.send_json_response(500, {'error': 'Internal server error'})

if __name__ == "__main__":
    # Load users from file
    load_users()
    print(f"Loaded {len(users_db)} users from {USERS_FILE}")
    
    host = "127.0.0.1"
    port = 8000
    server = HTTPServer((host, port), Handler)
    print(f"Server running on http://{host}:{port}")
    print(f"Group Seed: {GROUP_SEED}")
    print(f"Hash mode: {HASH_MODE}")
    print(f"Rate limit: {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW} seconds")
    print(f"Lockout: {LOCKOUT_ATTEMPTS} attempts, {LOCKOUT_DURATION} seconds")
    print(f"CAPTCHA enabled: {ENABLE_CAPTCHA}")
    print(f"TOTP enabled: {ENABLE_TOTP}")
    print(f"Logging to: {LOG_FILE}")
    server.serve_forever()
