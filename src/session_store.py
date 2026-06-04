from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.orm import Session as DbSession
from .models import Session as DbSessionModel

class InMemorySessionStore:
    def __init__(self):
        # Maps session_id -> {"user_id": int, "expires_at": datetime}
        self.store: Dict[str, Dict[str, Any]] = {}

    def create(self, user_id: int, expires_delta: timedelta) -> str:
        from .security import generate_random_token
        session_id = generate_random_token()
        expires_at = datetime.now(timezone.utc) + expires_delta
        self.store[session_id] = {"user_id": user_id, "expires_at": expires_at}
        return session_id

    def get(self, session_id: str) -> Optional[int]:
        session_data = self.store.get(session_id)
        if not session_data:
            return None
        # Check expiration
        now = datetime.now(timezone.utc)
        expires_at = session_data["expires_at"]
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if now > expires_at:
            self.delete(session_id)
            return None
        return session_data["user_id"]

    def delete(self, session_id: str):
        if session_id in self.store:
            del self.store[session_id]

    def get_all(self) -> Dict[str, Dict[str, Any]]:
        # Remove expired sessions first
        now = datetime.now(timezone.utc)
        expired = [
            sid for sid, data in self.store.items() 
            if (data["expires_at"].replace(tzinfo=timezone.utc) if data["expires_at"].tzinfo is None else data["expires_at"]) <= now
        ]
        for sid in expired:
            self.delete(sid)
            
        return {
            sid: {
                "user_id": data["user_id"],
                "expires_at": data["expires_at"].isoformat()
            }
            for sid, data in self.store.items()
        }

# Single global instance of in-memory store
in_memory_session_store = InMemorySessionStore()


class DatabaseSessionStore:
    def __init__(self, db: DbSession):
        self.db = db

    def create(self, user_id: int, expires_delta: timedelta) -> str:
        from .security import generate_random_token
        session_id = generate_random_token()
        expires_at = datetime.now(timezone.utc) + expires_delta
        db_session = DbSessionModel(
            session_id=session_id, 
            user_id=user_id, 
            expires_at=expires_at
        )
        self.db.add(db_session)
        self.db.commit()
        return session_id

    def get(self, session_id: str) -> Optional[int]:
        db_session = self.db.query(DbSessionModel).filter(DbSessionModel.session_id == session_id).first()
        if not db_session:
            return None
        
        now = datetime.now(timezone.utc)
        expires_at = db_session.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
            
        if now > expires_at:
            self.delete(session_id)
            return None
        return db_session.user_id

    def delete(self, session_id: str):
        db_session = self.db.query(DbSessionModel).filter(DbSessionModel.session_id == session_id).first()
        if db_session:
            self.db.delete(db_session)
            self.db.commit()
