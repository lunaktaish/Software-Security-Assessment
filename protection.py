"""Supports: Rate Limiting, Lockout, CAPTCHA, TOTP, and Pepper"""

import time
import random
import string
import hashlib
import hmac
import struct

# ON/OFF FLAGS - Set True to enable, False to disable
RATE_LIMIT_ENABLED = False     
LOCKOUT_ENABLED = False  
CAPTCHA_ENABLED = False     
TOTP_ENABLED = False           
PEPPER_ENABLED = False   

# Rate Limiting: Max attempts per time window
RATE_LIMIT_MAX_ATTEMPTS = 5        
RATE_LIMIT_WINDOW_SECONDS = 60     

# Lockout: Lock account after failed attempts
LOCKOUT_MAX_ATTEMPTS = 3           # Max failed attempts before lockout
LOCKOUT_DURATION_SECONDS = 300     # Lockout duration (5 minutes)

# TOTP: Time-based One-Time Password
TOTP_SECRET_LENGTH = 16            
TOTP_TIME_STEP = 30               
TOTP_DIGITS = 6                    

PEPPER = "SECRET_PEPPER_VALUE_CHANGE_ME_2024"

# STORAGE (In-memory - resets when server restarts)
# Rate limiting: {ip_address: [(timestamp1), (timestamp2), ...]}
rate_limit_tracker = {}

# Lockout: {username: {"failed_attempts": int, "locked_until": timestamp}}
lockout_tracker = {}

# CAPTCHA: {session_id: {"answer": int, "expires": timestamp}}
captcha_tracker = {}

# TOTP: {username: {"secret": string}} - Simulated TOTP secrets per user
totp_secrets = {}

def check_rate_limit(ip_address):
   # Check if IP address has exceeded rate limit
    if not RATE_LIMIT_ENABLED:  # Skip if disabled
        return True, RATE_LIMIT_MAX_ATTEMPTS, 0
    
    current_time = time.time()
    
    # Initialize if new IP
    if ip_address not in rate_limit_tracker:
        rate_limit_tracker[ip_address] = []
    
    # Remove old attempts outside the time window
    rate_limit_tracker[ip_address] = [
        t for t in rate_limit_tracker[ip_address]
        if current_time - t < RATE_LIMIT_WINDOW_SECONDS
    ]
    
    attempts = len(rate_limit_tracker[ip_address])
    remaining = RATE_LIMIT_MAX_ATTEMPTS - attempts
    
    if attempts >= RATE_LIMIT_MAX_ATTEMPTS:
        # Calculate when the oldest attempt will expire
        oldest = min(rate_limit_tracker[ip_address])
        reset_time = int(oldest + RATE_LIMIT_WINDOW_SECONDS - current_time)
        return False, 0, reset_time
    
    return True, remaining, 0


def record_rate_limit_attempt(ip_address):
    """Record a login attempt for rate limiting"""
    # Skip if disabled
    if not RATE_LIMIT_ENABLED:
        return
    
    current_time = time.time()
    
    if ip_address not in rate_limit_tracker:
        rate_limit_tracker[ip_address] = []
    
    rate_limit_tracker[ip_address].append(current_time)


def reset_rate_limit(ip_address):
    if ip_address in rate_limit_tracker:
        rate_limit_tracker[ip_address] = []


# ACCOUNT LOCKOUT
def check_lockout(username):
    # Skip if disabled
    if not LOCKOUT_ENABLED:
        return False, 0
    
    current_time = time.time()
    
    if username not in lockout_tracker:
        return False, 0
    
    user_data = lockout_tracker[username]
    
    # Check if still locked
    if user_data.get("locked_until", 0) > current_time:
        remaining = int(user_data["locked_until"] - current_time)
        return True, remaining
    
    # Lock has expired, reset if it was locked
    if user_data.get("locked_until", 0) > 0:
        lockout_tracker[username] = {"failed_attempts": 0, "locked_until": 0}
    
    return False, 0


def record_failed_attempt(username): #Record a failed login attempt
    # Skip if disabled
    if not LOCKOUT_ENABLED:
        return False, LOCKOUT_MAX_ATTEMPTS
    
    current_time = time.time()
    
    if username not in lockout_tracker:
        lockout_tracker[username] = {"failed_attempts": 0, "locked_until": 0}
    
    lockout_tracker[username]["failed_attempts"] += 1
    failed = lockout_tracker[username]["failed_attempts"]
    
    if failed >= LOCKOUT_MAX_ATTEMPTS:
        # Lock the account
        lockout_tracker[username]["locked_until"] = current_time + LOCKOUT_DURATION_SECONDS
        return True, 0
    
    return False, LOCKOUT_MAX_ATTEMPTS - failed


def reset_lockout(username):
    """Reset lockout after successful login"""
    if username in lockout_tracker:
        lockout_tracker[username] = {"failed_attempts": 0, "locked_until": 0}

# CAPTCHA 
def generate_captcha(session_id):
    num1 = random.randint(1, 20)
    num2 = random.randint(1, 20)
    operation = random.choice(['+', '-'])
    
    if operation == '+':
        answer = num1 + num2
        question = f"{num1} + {num2} = ?"
    else:
        # Ensure positive result
        if num1 < num2:
            num1, num2 = num2, num1
        answer = num1 - num2
        question = f"{num1} - {num2} = ?"
    
    # Store answer with expiration (5 minutes)
    captcha_tracker[session_id] = {
        "answer": answer,
        "expires": time.time() + 300
    }
    
    return question, session_id


def verify_captcha(session_id, user_answer): # Verify CAPTCHA answer
    if session_id not in captcha_tracker:
        return False
    
    captcha_data = captcha_tracker[session_id]
    
    # Check expiration
    if time.time() > captcha_data["expires"]:
        del captcha_tracker[session_id]
        return False
    
    # Verify answer
    try:
        correct = int(user_answer) == captcha_data["answer"]
    except (ValueError, TypeError):
        correct = False
    
    # Remove used CAPTCHA
    del captcha_tracker[session_id]
    
    return correct

# TOTP 
def generate_totp_secret(username):
    """Generate and store a TOTP secret for a user"""
    secret = ''.join(random.choices(string.ascii_uppercase + '234567', k=TOTP_SECRET_LENGTH))
    totp_secrets[username] = {"secret": secret}
    return secret


def get_totp_secret(username):
    """Get TOTP secret for a user, generate if doesn't exist"""
    if username not in totp_secrets:
        return generate_totp_secret(username)
    return totp_secrets[username]["secret"]


def generate_totp_code(username):
    
    # Generate current TOTP code for a user (simulated)
    secret = get_totp_secret(username)
    
    # Get current time step
    current_time = int(time.time())
    time_step = current_time // TOTP_TIME_STEP
    
    # Generate HMAC-SHA1
    key = secret.encode()
    msg = struct.pack('>Q', time_step)
    hmac_hash = hmac.new(key, msg, hashlib.sha1).digest()
    
    # Dynamic truncation
    offset = hmac_hash[-1] & 0x0F
    code_int = struct.unpack('>I', hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF
    code = code_int % (10 ** TOTP_DIGITS)
    
    return str(code).zfill(TOTP_DIGITS)


def verify_totp(username, user_code):
   # Verify TOTP code
    secret = get_totp_secret(username)
    current_time = int(time.time())
    
    # Check current and adjacent time steps (tolerance)
    for offset in [-1, 0, 1]:
        time_step = (current_time // TOTP_TIME_STEP) + offset
        
        key = secret.encode()
        msg = struct.pack('>Q', time_step)
        hmac_hash = hmac.new(key, msg, hashlib.sha1).digest()
        
        offset_byte = hmac_hash[-1] & 0x0F
        code_int = struct.unpack('>I', hmac_hash[offset_byte:offset_byte + 4])[0] & 0x7FFFFFFF
        code = str(code_int % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)
        
        if user_code == code:
            return True
    
    return False

# PEPPER 
def apply_pepper(password):
    """Apply pepper to password before hashing"""
    if not PEPPER_ENABLED:
        return password
    return password + PEPPER


def get_pepper():
    return PEPPER if PEPPER_ENABLED else ""


def is_pepper_enabled():
    return PEPPER_ENABLED

# COMBINED PROTECTION CHECK
def check_all_protections(username, ip_address, captcha_session=None, captcha_answer=None, totp_code=None):
    """
    Check all enabled protections before allowing login attempt
    
    Returns: {
        "allowed": bool,
        "reason": str or None,
        "captcha_required": bool,
        "captcha_question": str or None,
        "totp_required": bool
    }
    """
    result = {
        "allowed": True,
        "reason": None,
        "captcha_required": CAPTCHA_ENABLED,
        "captcha_question": None,
        "totp_required": TOTP_ENABLED
    }
    
    # Check rate limit
    rate_allowed, remaining, reset_time = check_rate_limit(ip_address)
    if not rate_allowed:
        result["allowed"] = False
        result["reason"] = f"Rate limit exceeded. Try again in {reset_time} seconds."
        return result
    
    # Check lockout
    locked, lock_remaining = check_lockout(username)
    if locked:
        result["allowed"] = False
        result["reason"] = f"Account locked. Try again in {lock_remaining} seconds."
        return result
    
    # Check CAPTCHA
    if CAPTCHA_ENABLED:
        if captcha_session and captcha_answer:
            if not verify_captcha(captcha_session, captcha_answer):
                result["allowed"] = False
                result["reason"] = "Invalid CAPTCHA."
                return result
        else:
            # Generate new CAPTCHA
            import uuid
            session_id = str(uuid.uuid4())
            question, _ = generate_captcha(session_id)
            result["captcha_question"] = question
            result["captcha_session"] = session_id
    
    # Check TOTP
    if TOTP_ENABLED:
        if totp_code:
            if not verify_totp(username, totp_code):
                result["allowed"] = False
                result["reason"] = "Invalid TOTP code."
                return result
        else:
            result["allowed"] = False
            result["reason"] = "TOTP code required."
            return result
    
    return result

def after_login_attempt(username, ip_address, success):
    """ Call after each login attempt to update trackers """
    # Record rate limit attempt
    record_rate_limit_attempt(ip_address)
    
    if success:
        # Reset on successful login
        reset_lockout(username)
        reset_rate_limit(ip_address)
    else:
        # Record failed attempt for lockout
        record_failed_attempt(username)

# GET ACTIVE PROTECTIONS (for logging)
def get_protection_flags():
    flags = []
    
    if RATE_LIMIT_ENABLED:
        flags.append(f"rate_limit({RATE_LIMIT_MAX_ATTEMPTS}/{RATE_LIMIT_WINDOW_SECONDS}s)")
    
    if LOCKOUT_ENABLED:
        flags.append(f"lockout({LOCKOUT_MAX_ATTEMPTS}fails/{LOCKOUT_DURATION_SECONDS}s)")
    
    if CAPTCHA_ENABLED:
        flags.append("captcha")
    
    if TOTP_ENABLED:
        flags.append("totp")
    
    if PEPPER_ENABLED:
        flags.append("pepper")
    
    return ",".join(flags) if flags else "none"
