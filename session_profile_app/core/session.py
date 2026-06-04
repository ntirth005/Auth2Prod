import secrets
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from session_profile_app.models.models import SessionRecord

class DatabaseSessionManager:
    def __init__(self, db: Session):
        self.db = db

    def create_session(self, user_id: int, expires_delta: timedelta) -> str:
        """Generates a secure random session ID and saves it to the database."""
        session_id = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + expires_delta
        
        session_rec = SessionRecord(
            session_id=session_id,
            user_id=user_id,
            expires_at=expires_at
        )
        self.db.add(session_rec)
        self.db.commit()
        return session_id

    def get_user_id(self, session_id: str) -> Optional[int]:
        """Returns the user ID if the session is valid and active, otherwise deletes expired sessions."""
        rec = self.db.query(SessionRecord).filter(
            SessionRecord.session_id == session_id
        ).first()
        
        if not rec:
            return None
            
        if rec.expires_at < datetime.utcnow():
            self.delete_session(session_id)
            return None
            
        return rec.user_id

    def delete_session(self, session_id: str):
        """Wipes a specific session ID (used on logout)."""
        rec = self.db.query(SessionRecord).filter(
            SessionRecord.session_id == session_id
        ).first()
        if rec:
            self.db.delete(rec)
            self.db.commit()

    def delete_all_user_sessions(self, user_id: int):
        """Wipes all sessions for a user (used on security actions like password changes)."""
        self.db.query(SessionRecord).filter(
            SessionRecord.user_id == user_id
        ).delete()
        self.db.commit()
