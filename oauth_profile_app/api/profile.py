from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from ..core.database import get_db
from ..core.security import get_session_user_id
from ..models.models import User
from ..schemas.schemas import UserResponse, UserUpdate

router = APIRouter(prefix="/api/profile", tags=["User Profile"])

def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = get_session_user_id(request)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated. Active session cookie missing or invalid."
        )
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session linked to a non-existent user profile."
        )
    return user

@router.get("/me", response_model=UserResponse)
def read_current_user(user: User = Depends(get_current_user)):
    return user

@router.put("/update", response_model=UserResponse)
def update_profile(
    payload: UserUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if payload.display_name is not None:
        user.display_name = payload.display_name
    if payload.email is not None:
        user.email = payload.email
    if payload.bio is not None:
        user.bio = payload.bio
        
    db.commit()
    db.refresh(user)
    return user
