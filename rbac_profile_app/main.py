from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from rbac_profile_app.core.config import settings
from rbac_profile_app.core.database import engine, Base, SessionLocal, executed_queries
from rbac_profile_app.models.models import Role, User
from rbac_profile_app.api.debug import seed_database
from rbac_profile_app.api import auth, profile, admin, debug

# Initialize database schemas
Base.metadata.create_all(bind=engine)

# Auto seed database on initial startup
db = SessionLocal()
try:
    if db.query(Role).count() == 0 or db.query(User).count() == 0:
        seed_database(db)
finally:
    db.close()

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="Diagnostic environment showcasing dynamic Role-Based Access Control and interactive gateway simulation."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def request_sql_logging_middleware(request: Request, call_next):
    """Binds an in-memory SQL buffer to the active request context, enabling query capture."""
    token = executed_queries.set([])
    try:
        response = await call_next(request)
        return response
    finally:
        executed_queries.reset(token)

# Include routers
app.include_router(auth.router)
app.include_router(profile.router)
app.include_router(admin.router)
app.include_router(debug.router)

# Mount static folder
app.mount("/static", StaticFiles(directory="rbac_profile_app/static"), name="static")

@app.get("/")
def read_root():
    return RedirectResponse(url="/static/index.html")
