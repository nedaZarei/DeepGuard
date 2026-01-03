"""
Authentication module with security vulnerabilities
"""
import hashlib
import pickle
import base64

# Hardcoded credentials
DB_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdef"

def hash_password(password):
    """Hash password using MD5 (weak)"""
    # VULNERABLE: Using MD5 for password hashing
    return hashlib.md5(password.encode()).hexdigest()

def verify_login(username, password):
    """Verify user credentials"""
    import sqlite3
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # VULNERABLE: SQL injection via string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + hash_password(password) + "'"

    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()

    return result is not None

def deserialize_session(session_data):
    """Deserialize user session"""
    # VULNERABLE: Insecure deserialization with pickle
    decoded = base64.b64decode(session_data)
    return pickle.loads(decoded)

def serialize_session(user_data):
    """Serialize user session"""
    pickled = pickle.dumps(user_data)
    return base64.b64encode(pickled).decode()
