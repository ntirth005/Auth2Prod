from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import User
from ..security import verify_password

router = APIRouter(prefix="/auth/basic", tags=["Basic Authentication"])

security = HTTPBasic()

def get_current_user_basic(
    credentials: HTTPBasicCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    user = db.query(User).filter(User.username == credentials.username).first()
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user

@router.get("/protected")
def protected_route(user: User = Depends(get_current_user_basic)):
    """A protected endpoint that returns user details if Basic Authentication succeeds."""
    return {
        "message": f"Hello {user.username}! You authenticated successfully using HTTP Basic Auth.",
        "auth_method": "basic",
        "user": {
            "id": user.id,
            "username": user.username
        }
    }
