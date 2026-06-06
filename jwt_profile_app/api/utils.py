import jwt
from fastapi import Request, Depends, HTTPException, status
from sqlalchemy.orm import Session
from jwt_profile_app.core.database import get_db
from jwt_profile_app.core.config import settings
from jwt_profile_app.models.models import User
from jwt_profile_app.core.jwt_helper import decode_token

async def capture_debug_meta(request: Request, db_queries: list, response_headers: dict = None):
    """Gathers incoming request payloads and mock SQL commands for visual logging."""
    body = None
    try:
        if request.method in ["POST", "PUT"]:
            body = await request.json()
    except Exception:
        pass

    return {
        "request": {
            "method": request.method,
            "url": str(request.url),
            "headers": {k: v for k, v in request.headers.items() if k.lower() in ["authorization", "cookie", "user-agent", "content-type", "accept"]},
            "body": body
        },
        "db_actions": db_queries,
        "response_headers": response_headers or {}
    }

def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Verifies the stateless JWT access token in the Authorization header.
    
    If the access token is expired, raises a 401 with a specific error message
    ('Token expired') to instruct the client-side JavaScript to try refreshing the token.
    """
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header."
        )
        
    parts = auth_header.split(" ")
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Use 'Bearer <token>'."
        )
        
    token = parts[1]
    
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type. Expected access token."
            )
        user_id = int(payload.get("sub"))
    except jwt.ExpiredSignatureError:
        # Crucial for client-side automated token refresh trigger
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token. Please log in again."
        )
        
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found."
        )
        
    return user
