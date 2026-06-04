from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Header, status
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import User, APIKey
from ..security import generate_random_token, hash_api_key
from .basic import get_current_user_basic

router = APIRouter(prefix="/auth/apikey", tags=["API Key Authentication"])

def get_user_from_api_key(
    x_api_key: str = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db)
) -> User:
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key missing from headers (X-API-Key)",
        )

    # Hash the key to look it up in the database
    hashed_key = hash_api_key(x_api_key)
    api_key_record = db.query(APIKey).filter(
        APIKey.hashed_key == hashed_key, 
        APIKey.is_active == True
    ).first()

    if not api_key_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive API Key",
        )

    return api_key_record.user

@router.post("/generate")
def generate_key(
    description: str = "Default API Key",
    user: User = Depends(get_current_user_basic),  # Require Basic Auth to generate keys
    db: Session = Depends(get_db)
):
    """Generates a new API Key for the authenticated user."""
    raw_key = f"ap_{generate_random_token(24)}"
    prefix = raw_key[:7] # e.g. "ap_abcd"
    hashed_key = hash_api_key(raw_key)

    new_key = APIKey(
        key_prefix=prefix,
        hashed_key=hashed_key,
        user_id=user.id,
        description=description,
        is_active=True
    )
    db.add(new_key)
    db.commit()

    return {
        "message": "API Key generated successfully. Save this key, it won't be shown again!",
        "api_key": raw_key,
        "prefix": prefix,
        "description": description
    }

@router.get("/protected")
def protected_route(user: User = Depends(get_user_from_api_key)):
    """A protected endpoint that resolves a user via their API Key header."""
    return {
        "message": f"Hello {user.username}! You authenticated successfully using an API Key.",
        "auth_method": "api_key",
        "user": {
            "id": user.id,
            "username": user.username
        }
    }
