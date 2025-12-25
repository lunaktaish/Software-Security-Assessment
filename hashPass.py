"""Supports: SHA-256+salt, bcrypt and Argon2id"""
import json
import os
import hashlib
import secrets

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

try:
    from argon2 import PasswordHasher
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

USER_DB_FILE = "user_db.json"

HASHED_PASSWORDS = {} # Store hashed passwords in memory

def hash_sha256_salt(password, salt=None):
    # Hash password using SHA-256 with salt
    if salt is None:
        salt = secrets.token_hex(16)
    salted_password = password + salt
    hashed = hashlib.sha256(salted_password.encode()).hexdigest()
    return hashed, salt


def verify_sha256_salt(password, stored_hash, salt):
    # Verify password against SHA-256+salt hash
    salted_password = password + salt
    hashed = hashlib.sha256(salted_password.encode()).hexdigest()
    return hashed == stored_hash

def hash_bcrypt(password):
    """Hash password using bcrypt"""
    if not BCRYPT_AVAILABLE:
        print("Error: bcrypt not installed. Run: pip install bcrypt")
        return None
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode('utf-8')


def verify_bcrypt(password, stored_hash):
    """Verify password against bcrypt hash"""
    if not BCRYPT_AVAILABLE:
        return False
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

def hash_argon2id(password):
    """Hash password using Argon2id (time=1, memory=64MB, parallelism=1)"""
    if not ARGON2_AVAILABLE:
        print("Error: argon2-cffi not installed. Run: pip install argon2-cffi")
        return None
    ph = PasswordHasher(
        time_cost=1,         # time = 1
        memory_cost=65536,   # memory = 64 MB (in KB)
        parallelism=1        # parallelism = 1
    )
    return ph.hash(password)

def verify_argon2id(password, stored_hash):
    """Verify password against Argon2id hash"""
    if not ARGON2_AVAILABLE:
        return False
    try:
        ph = PasswordHasher(
            time_cost=1,
            memory_cost=65536,
            parallelism=1
        )
        ph.verify(stored_hash, password)
        return True
    except:
        return False
    
def load_and_hash_passwords(hash_mode):
    """
    Load passwords from user_db.json and hash them in memory
    """
    global HASHED_PASSWORDS
    
    if not os.path.exists(USER_DB_FILE):
        return {}
    
    with open(USER_DB_FILE, 'r') as f:
        data = json.load(f)
    
    HASHED_PASSWORDS = {}
    
    for key, value in data.items():
        if isinstance(value, dict) and 'username' in value and 'password' in value:
            username = value['username']
            plain_password = value['password']
            
            if hash_mode == "sha256_salt":
                hashed, salt = hash_sha256_salt(plain_password)
                HASHED_PASSWORDS[username] = {"hash": hashed, "salt": salt}
            
            elif hash_mode == "bcrypt":
                hashed = hash_bcrypt(plain_password)
                HASHED_PASSWORDS[username] = {"hash": hashed}
            
            elif hash_mode == "argon2id":
                hashed = hash_argon2id(plain_password)
                HASHED_PASSWORDS[username] = {"hash": hashed}
    
    return HASHED_PASSWORDS

def verify_password(password, stored_password, hash_mode, username=None):
    if hash_mode == "none":
        return password == stored_password
    
    elif hash_mode == "sha256_salt":
        if username in HASHED_PASSWORDS:
            stored_hash = HASHED_PASSWORDS[username]["hash"]
            salt = HASHED_PASSWORDS[username]["salt"]
            return verify_sha256_salt(password, stored_hash, salt)
        return False
    
    elif hash_mode == "bcrypt":
        if username in HASHED_PASSWORDS:
            stored_hash = HASHED_PASSWORDS[username]["hash"]
            return verify_bcrypt(password, stored_hash)
        return False
    
    elif hash_mode == "argon2id":
        if username in HASHED_PASSWORDS:
            stored_hash = HASHED_PASSWORDS[username]["hash"]
            return verify_argon2id(password, stored_hash)
        return False
    
    return False
















    


