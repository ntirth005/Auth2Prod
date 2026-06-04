from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import User
from ..security import verify_password
from ..session_store import in_memory_session_store, DatabaseSessionStore

router = APIRouter(prefix="/auth/session", tags=["Session Authentication"])

SESSION_COOKIE_NAME = "auth2prod_session_id"
STORE_TYPE_COOKIE_NAME = "auth2prod_session_store"
SESSION_EXPIRY_MINUTES = 15

@router.post("/login")
async def login(
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Validates username and password, creates a session in the chosen store 
    (memory or db), and sets session cookies.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
        
    username = body.get("username")
    password = body.get("password")
    store_type = body.get("store_type", "memory")  # "memory" or "db"

    if not username or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing username or password"
        )

    # Validate User
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    expires_delta = timedelta(minutes=SESSION_EXPIRY_MINUTES)

    # Store Session based on selected store_type
    if store_type == "db":
        db_store = DatabaseSessionStore(db)
        session_id = db_store.create(user.id, expires_delta)
    else:
        session_id = in_memory_session_store.create(user.id, expires_delta)

    # Set cookies
    # In a real environment we would use secure=True, httponly=True, samesite="Lax"
    # We omit secure=True for local development over HTTP without SSL.
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        samesite="lax",
        max_age=SESSION_EXPIRY_MINUTES * 60
    )
    response.set_cookie(
        key=STORE_TYPE_COOKIE_NAME,
        value=store_type,
        httponly=True,
        samesite="lax",
        max_age=SESSION_EXPIRY_MINUTES * 60
    )

    return {
        "message": f"Successfully logged in via Session Auth ({store_type} store)!",
        "session_id": session_id,
        "store_type": store_type,
        "user": {"id": user.id, "username": user.username}
    }

def get_current_user_session(request: Request, db: Session = Depends(get_db)) -> User:
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    store_type = request.cookies.get(STORE_TYPE_COOKIE_NAME, "memory")

    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No session cookie found. Please log in."
        )

    # Retrieve user_id based on store type
    user_id = None
    if store_type == "db":
        db_store = DatabaseSessionStore(db)
        user_id = db_store.get(session_id)
    else:
        user_id = in_memory_session_store.get(session_id)

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session. Please log in again."
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found for active session."
        )

    return user

@router.get("/protected")
def protected_route(user: User = Depends(get_current_user_session)):
    """A protected endpoint that resolves a user from their active session cookie."""
    return {
        "message": f"Hello {user.username}! You authenticated successfully using a Stateful Session.",
        "auth_method": "session",
        "user": {
            "id": user.id,
            "username": user.username
        }
    }

@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    """Deletes the session from the chosen store and clears client-side cookies."""
    session_id = request.cookies.get(SESSION_COOKIE_NAME)
    store_type = request.cookies.get(STORE_TYPE_COOKIE_NAME, "memory")

    if session_id:
        if store_type == "db":
            db_store = DatabaseSessionStore(db)
            db_store.delete(session_id)
        else:
            in_memory_session_store.delete(session_id)

    response.delete_cookie(SESSION_COOKIE_NAME)
    response.delete_cookie(STORE_TYPE_COOKIE_NAME)

    return {"message": "Successfully logged out and cleared session."}
