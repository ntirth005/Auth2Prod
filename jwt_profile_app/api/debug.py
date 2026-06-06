from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from jwt_profile_app.core.database import get_db
from jwt_profile_app.models.models import User, RefreshToken
from jwt_profile_app.core.config import settings

router = APIRouter()

@router.get("/api/debug/state")
def get_debug_state(request: Request, db: Session = Depends(get_db)):
    """Returns database state for dashboard diagnostics panels."""
    users = db.query(User).all()
    tokens = db.query(RefreshToken).all()
    
    client_refresh_cookie = request.cookies.get(settings.REFRESH_TOKEN_COOKIE_NAME)
    
    return {
        "client_refresh_cookie": client_refresh_cookie,
        "users": [
            {
                "id": u.id, 
                "username": u.username, 
                "display_name": u.display_name,
                "email": u.email,
                "bio": u.bio
            } for u in users
        ],
        "refresh_tokens": [
            {
                "id": t.id,
                "jti": f"{t.token_jti[:8]}...",
                "user_id": t.user_id,
                "username": db.query(User.username).filter(User.id == t.user_id).scalar() or "Unknown",
                "expires_at": t.expires_at.isoformat(),
                "is_revoked": t.is_revoked
            } for t in tokens
        ]
    }

@router.post("/api/debug/reset")
def reset_database(db: Session = Depends(get_db)):
    """Wipes all refresh tokens and users to reset system state."""
    db.query(RefreshToken).delete()
    db.query(User).delete()
    db.commit()
    return {"message": "All database records have been reset."}
