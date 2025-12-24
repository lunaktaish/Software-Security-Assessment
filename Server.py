import json
import os
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

USER_DB_FILE = "user_db.json"
LOGGING_FILE = "logging.json"
WEB_HTML_FILE = "web.html"

GROUP_SEED = 25493314  # Group Seed number: 323047696 XOR 314945106

def load_user_db():
    # Load user database (user_db.json) and convert to username password format
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

def load_logs():
    # function that loads login logs
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
    # defines a function that records one login attempt.
    logs = load_logs()  # loads all previous login attempts.
    
    # Count attempts for this username
    attempt_count = sum(1 for a in logs if a["username"] == username) + 1
    
    log_entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "group_seed": GROUP_SEED,
        "username": username,
        "password": password,
        "result": success,
        "latency_ms": latency_ms,
        "attempt_number": attempt_count
    }
    
    logs.append(log_entry)  # appends the new entry 
    
    with open(LOGGING_FILE, 'w') as f:  # write all logs back to the file.
        json.dump(logs, f, indent=2)
    
    return log_entry

class LoginHandler(BaseHTTPRequestHandler):
    # defines the HTTP request handler
 
    def send_cors_headers(self):
        # allows browsers to send requests from different origins
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
    
    def do_OPTIONS(self):
        # Handle preflight CORS requests
        self.send_response(200)
        self.send_cors_headers()
        self.end_headers()
    
    def do_GET(self):
        if self.path == "/" or self.path == "/login":
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
                self.wfile.write(b"<h1>web.html not found!</h1><p>Make sure web.html is in the same directory as server.py</p>")
        
        elif self.path == "/logs":
            # View logs endpoint
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_cors_headers()
            self.end_headers()
            logs = load_logs()
            self.wfile.write(json.dumps(logs, indent=2).encode())
        
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        # Handle login API requests
        if self.path == "/api/login":
            start_time = time.time()  # Start measuring latency
            
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length).decode('utf-8')
            
            # Parse JSON data
            try:
                data = json.loads(post_data)
                username = data.get('username', '')
                password = data.get('password', '')
            except json.JSONDecodeError:
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.send_cors_headers()
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Invalid JSON"}).encode())
                return
            
            # Load user database from user_db.json
            user_db = load_user_db()
            
            # Check credentials
            success = False
            if username in user_db and user_db[username] == password:
                success = True
            
            # Calculate latency
            latency_ms = round((time.time() - start_time) * 1000, 2)
            
            # Determine result
            #result = "success" if success else "failure"
            
            # Log the attempt to logging.json
            log_entry = save_log(username, password, success , latency_ms)

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_cors_headers()
            self.end_headers()
            
            response = {
                "success": success,
                "message": "Authentication successful" if success else "Invalid username or password",
                "attempt_number": log_entry['attempt_number']
            }
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()

def run_server(port=8080):
    """Start the HTTP server"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, LoginHandler)
    print(f"\n{'='*50}")
    print(f"  Software Security Assessment Server")
    print(f"{'='*50}")
    print(f"\nServer running on http://localhost:{port}")
    print(f"  - View logs:  http://localhost:{port}/logs")
    print(f"\nPress Ctrl+C to stop the server\n")
    httpd.serve_forever()

if __name__ == "__main__":
    if not os.path.exists(LOGGING_FILE):
        with open(LOGGING_FILE, 'w') as f:
            json.dump([], f)
    
    run_server()
