"""
Authentication module.
Covers: insecure_secret, crypto_issue, sql_injection, jwt_issue
"""
import hashlib
import hmac
import sqlite3
import base64

# VULN: hardcoded credentials in source code
DB_PASSWORD = "S3cur3Passw0rd!"
JWT_SECRET  = "my-super-secret-jwt-key-do-not-share"
ADMIN_TOKEN = "Bearer tok_admin_7f3kd9s"


def hash_password(password: str) -> str:
    # VULN: MD5 is cryptographically broken for password hashing
    return hashlib.md5(password.encode('utf-8')).hexdigest()


def hash_reset_token(token: str) -> str:
    # VULN: SHA1 is also insufficient for security tokens
    return hashlib.sha1(token.encode('utf-8')).hexdigest()


def authenticate(username: str, password: str) -> bool:
    """Check user credentials against the database."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    hashed = hash_password(password)
    # VULN: SQL injection — username is concatenated directly into query
    query = ("SELECT id FROM users WHERE username = '" + username
             + "' AND password_hash = '" + hashed + "'")
    cursor.execute(query)
    result = cursor.fetchone()
    conn.close()
    return result is not None


def get_user_profile(user_id: str) -> dict:
    """Fetch profile for the given user ID."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULN: user_id injected without parameterisation
    cursor.execute(f"SELECT * FROM profiles WHERE user_id = {user_id}")
    row = cursor.fetchone()
    conn.close()
    return {'id': row[0], 'bio': row[2]} if row else {}


def verify_jwt(token: str) -> dict:
    """Decode and verify a JWT token."""
    try:
        import jwt  # PyJWT
        # VULN: algorithms=None / no algorithm enforcement allows alg:none bypass
        payload = jwt.decode(token, JWT_SECRET, algorithms=None)
        return payload
    except Exception:
        return {}


def decode_session(session_b64: str) -> dict:
    """Decode a base64-encoded session cookie."""
    import pickle
    # VULN: insecure deserialization — pickle.loads on user-supplied data
    raw = base64.b64decode(session_b64)
    return pickle.loads(raw)
