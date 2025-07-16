#!/usr/bin/env python3
"""
Additional test file for MCP security scanner.
This file contains various types of security vulnerabilities.
"""

import os
import subprocess
import sqlite3
import requests
import hashlib
import random
import jwt
from cryptography.fernet import Fernet

# Network Security Issues
def insecure_request():
    """HTTP instead of HTTPS and no SSL verification."""
    response = requests.get("http://example.com/api", verify=False)
    return response.json()

# Cryptography Issues  
def weak_crypto():
    """Weak cryptographic algorithms."""
    # Weak hash
    md5_hash = hashlib.md5(b"password").hexdigest()
    
    # Weak random
    random_key = random.randint(1000, 9999)
    
    # Small key size would be: rsa.generate_private_key(public_exponent=65537, key_size=512)
    return md5_hash, random_key

# Input Validation Issues
def no_validation(user_input):
    """Missing input validation."""
    # Direct use without validation
    result = eval(user_input)  # Dangerous eval
    
    # No length check
    filename = user_input
    with open(filename, 'w') as f:
        f.write("data")
    
    return result

# File Security Issues
def path_traversal(filename):
    """Path traversal vulnerability."""
    file_path = os.path.join("/safe/directory", filename)  # Vulnerable to ../
    with open(file_path, 'r') as f:
        return f.read()

def unsafe_pickle():
    """Unsafe pickle usage."""
    import pickle
    user_data = input("Enter data: ")
    obj = pickle.loads(user_data)  # Dangerous
    return obj

# More Authentication Issues
def bypass_auth():
    """Authentication bypass."""
    skip_auth = True  # Skip authentication
    if not skip_auth:
        authenticate_user()
    return "Access granted"

# JWT without verification
def insecure_jwt(token):
    """JWT without verification."""
    payload = jwt.decode(token, verify=False)  # No signature verification
    return payload

# More credential exposures
STRIPE_API_KEY = "sk_live_1234567890abcdef"  # Hardcoded API key
DB_PASSWORD = "super_secret_password_123"    # Hardcoded password

def database_connection():
    """Insecure database connection."""
    conn_string = f"postgresql://user:{DB_PASSWORD}@localhost/db"
    return conn_string

# CORS and security headers
def insecure_web_config():
    """Missing security headers."""
    headers = {
        "Access-Control-Allow-Origin": "*",  # CORS wildcard
        "Content-Type": "application/json"
        # Missing: Strict-Transport-Security, X-Content-Type-Options, etc.
    }
    return headers

if __name__ == "__main__":
    print("This file contains intentional security vulnerabilities for testing.")
