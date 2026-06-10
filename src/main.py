from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from .database import engine, Base, get_db
from .models import User, OAuthClient
from .security import hash_password
from .auth import oauth

# Create SQLite tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Auth2Prod - OAuth 2.0 Playround & Sandbox",
    description="An interactive diagnostic environment for studying OAuth 2.0 Authorization Code Flow."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Authentication routers
app.include_router(oauth.router)

# User registration endpoint
@app.post("/register")
def register_user(payload: dict, db: Session = Depends(get_db)):
    username = payload.get("username")
    password = payload.get("password")
    email = payload.get("email", f"{username}@example.com")
    display_name = payload.get("display_name", username.capitalize())

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

    new_user = User(
        username=username,
        hashed_password=hash_password(password),
        email=email,
        display_name=display_name,
        bio="Playground user account"
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

# Pre-seed default user and client on startup
@app.on_event("startup")
def preseed_data():
    db = next(get_db())
    try:
        # Preseed default user
        default_user = db.query(User).filter(User.username == "alice").first()
        if not default_user:
            seeded_user = User(
                username="alice",
                hashed_password=hash_password("password123"),
                email="alice@example.com",
                display_name="Alice Smith",
                bio="Software Engineer studying authentication systems."
            )
            db.add(seeded_user)
            db.commit()

        # Preseed default client
        default_client = db.query(OAuthClient).filter(OAuthClient.client_id == "mock-client-123").first()
        if not default_client:
            seeded_client = OAuthClient(
                client_id="mock-client-123",
                client_secret="mock-client-secret-999",
                client_name="Mock Auth2Prod Dashboard Client",
                redirect_uri="http://localhost:8000/static/index.html"
            )
            db.add(seeded_client)
            db.commit()
    finally:
        db.close()

# Mount static files
app.mount("/static", StaticFiles(directory="src/static"), name="static")

@app.get("/")
def read_root():
    return RedirectResponse(url="/static/index.html")
