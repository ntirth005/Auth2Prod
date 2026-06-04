from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from .database import engine, Base, get_db
from .models import User, Session as DbSessionModel, APIKey
from .security import hash_password, compute_digest_ha1
from .session_store import in_memory_session_store
from .auth import basic, digest, api_key, session

# Create SQLite tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Auth2Prod - Authentication Systems Visualizer",
    description="A diagnostic environment for studying Basic, Digest, API Key, and Session Authentication."
)

# Enable CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Authentication routers
app.include_router(basic.router)
app.include_router(digest.router)
app.include_router(api_key.router)
app.include_router(session.router)

# User registration endpoint
@app.post("/register")
def register_user(payload: dict, db: Session = Depends(get_db)):
    username = payload.get("username")
    password = payload.get("password")
    
    if not username or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and password are required"
        )
        
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
        
    # Store bcrypt hash for Basic/Session auth
    hashed_pw = hash_password(password)
    # Store precomputed MD5 HA1 hash for Digest auth
    digest_ha1 = compute_digest_ha1(username, password)
    
    new_user = User(
        username=username, 
        hashed_password=hashed_pw, 
        digest_ha1=digest_ha1
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {
        "message": f"User '{username}' registered successfully!",
        "user": {
            "id": new_user.id,
            "username": new_user.username
        }
    }

# Debug & visualization endpoints
@app.get("/api/debug/state")
def get_debug_state(db: Session = Depends(get_db)):
    """Returns the current state of users, active DB sessions, in-memory sessions, and API keys."""
    users = db.query(User).all()
    api_keys = db.query(APIKey).all()
    db_sessions = db.query(DbSessionModel).all()
    
    return {
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "has_basic_hash": u.hashed_password is not None,
                "has_digest_ha1": u.digest_ha1 is not None
            } for u in users
        ],
        "api_keys": [
            {
                "id": k.id,
                "prefix": k.key_prefix,
                "hashed_key": k.hashed_key[:12] + "...",
                "user_id": k.user_id,
                "username": k.user.username if k.user else "Unknown",
                "description": k.description,
                "is_active": k.is_active,
                "created_at": k.created_at.isoformat()
            } for k in api_keys
        ],
        "db_sessions": [
            {
                "id": s.id,
                "session_id": s.session_id[:12] + "...",
                "user_id": s.user_id,
                "username": s.user.username if s.user else "Unknown",
                "created_at": s.created_at.isoformat(),
                "expires_at": s.expires_at.isoformat()
            } for s in db_sessions
        ],
        "in_memory_sessions": in_memory_session_store.get_all()
    }

@app.get("/api/debug/echo-headers")
def echo_headers(request: Request):
    """Echoes back all received request headers and cookies for diagnostic display."""
    return {
        "headers": dict(request.headers),
        "cookies": dict(request.cookies)
    }

@app.post("/api/debug/reset")
def reset_system(db: Session = Depends(get_db)):
    """Clears all users, API keys, and sessions (DB and in-memory)."""
    db.query(DbSessionModel).delete()
    db.query(APIKey).delete()
    db.query(User).delete()
    db.commit()
    in_memory_session_store.store.clear()
    return {"message": "All database and in-memory states have been reset."}

# Mount static files (must be mounted after custom routes to avoid overlapping root issues)
app.mount("/static", StaticFiles(directory="src/static"), name="static")

@app.get("/")
def read_root():
    return RedirectResponse(url="/static/index.html")
