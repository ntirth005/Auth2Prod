from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from session_profile_app.core.database import get_db
from session_profile_app.models.models import User, SessionRecord, LoginChallenge
from session_profile_app.core.config import settings

router = APIRouter()

@router.get("/api/debug/state")
def get_debug_state(request: Request, db: Session = Depends(get_db)):
    """Returns database state for dashboard diagnostics panels."""
    users = db.query(User).all()
    sessions = db.query(SessionRecord).all()
    
    client_session_cookie = request.cookies.get(settings.SESSION_COOKIE_NAME)
    
    return {
        "client_session_cookie": client_session_cookie,
        "users": [
            {
                "id": u.id, 
                "username": u.username, 
                "display_name": u.display_name,
                "email": u.email,
                "bio": u.bio
            } for u in users
        ],
        "sessions": [
            {
                "id": s.id,
                "session_id": f"{s.session_id[:6]}...",
                "user_id": s.user_id,
                "username": db.query(User.username).filter(User.id == s.user_id).scalar(),
                "created_at": s.created_at.isoformat(),
                "expires_at": s.expires_at.isoformat()
            } for s in sessions
        ]
    }

@router.post("/api/debug/reset")
def reset_database(db: Session = Depends(get_db)):
    """Wipes all sessions and users to reset system state."""
    db.query(SessionRecord).delete()
    db.query(LoginChallenge).delete()
    db.query(User).delete()
    db.commit()
    return {"message": "All database records have been reset."}
