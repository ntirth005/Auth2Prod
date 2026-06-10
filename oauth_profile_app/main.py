from fastapi import FastAPI, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from .core.database import engine, Base, get_db
from .models.models import User
from .api import auth, profile

# Create SQLite database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Auth2Prod - Third-Party OAuth 2.0 Identity Portal",
    description="A production-grade application demonstrating GitHub and Google OAuth 2.0 login."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth.router)
app.include_router(profile.router)

# Diagnostics helper route
@app.get("/api/debug/state")
def get_debug_state(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return {
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "display_name": u.display_name,
                "email": u.email,
                "avatar_url": u.avatar_url,
                "provider": "GitHub" if u.github_id else ("Google" if u.google_id else "Local")
            } for u in users
        ]
    }

@app.post("/api/debug/reset")
def reset_database(db: Session = Depends(get_db)):
    db.query(User).delete()
    db.commit()
    return {"message": "All user profiles have been deleted from the database."}

# Mount static folder
app.mount("/static", StaticFiles(directory="oauth_profile_app/static"), name="static")

@app.get("/")
def read_root():
    return RedirectResponse(url="/static/index.html")
