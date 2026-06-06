import uuid
from datetime import datetime, timedelta
import jwt
from jwt_profile_app.core.config import settings

def create_access_token(user_id: int, username: str) -> str:
    """Generates a short-lived stateless JWT access token containing subject and username."""
    now = datetime.utcnow()
    payload = {
        "sub": str(user_id),
        "username": username,
        "iat": now,
        "exp": now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRY_MINUTES),
        "type": "access"
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def generate_jti() -> str:
    """Generates a unique identifier (JTI) for tracking and rotating refresh tokens."""
    return str(uuid.uuid4())

def create_refresh_token(user_id: int, jti: str) -> str:
    """Generates a long-lived JWT refresh token with a unique JTI for rotation checks."""
    now = datetime.utcnow()
    payload = {
        "sub": str(user_id),
        "jti": jti,
        "iat": now,
        "exp": now + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRY_MINUTES),
        "type": "refresh"
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    """Decodes a JWT and verifies its signature and expiration.
    
    Raises:
        jwt.ExpiredSignatureError: If the token signature is expired.
        jwt.InvalidTokenError: If the signature is invalid or token malformed.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM]
    )
