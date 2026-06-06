from fastapi import Request, Depends, HTTPException, status
from sqlalchemy.orm import Session
from session_profile_app.core.database import get_db
from session_profile_app.core.config import settings
from session_profile_app.models.models import User

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
            "headers": {k: v for k, v in request.headers.items() if k.lower() in ["cookie", "user-agent", "content-type", "accept"]},
            "body": body
        },
        "db_actions": db_queries,
        "response_headers": response_headers or {}
    }

def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Verifies incoming session cookies and returns the active database User object."""
    from session_profile_app.core.session import DatabaseSessionManager
    session_id = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No session cookie found. Please log in."
        )
    
    session_mgr = DatabaseSessionManager(db)
    user_id = session_mgr.get_user_id(session_id)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid. Please log in again."
        )
        
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found."
        )
    return user
