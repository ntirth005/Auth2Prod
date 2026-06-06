import uuid
from datetime import datetime
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse


from jwt_profile_app.core.database import engine, Base
from jwt_profile_app.core.logging import get_logger, request_id_var
from jwt_profile_app.api.auth import router as auth_router
from jwt_profile_app.api.profile import router as profile_router
from jwt_profile_app.api.debug import router as debug_router

# Create database tables automatically
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Stateless JWT Profile & Session App")

logger = get_logger("jwt_profile_app")

@app.middleware("http")
async def log_requests(request: Request, call_next):
    correlation_id = str(uuid.uuid4())
    token = request_id_var.set(correlation_id)
    
    start_time = datetime.utcnow()
    logger.info(
        "Request started", 
        extra={"extra_fields": {"method": request.method, "url": str(request.url)}}
    )
    
    try:
        response = await call_next(request)
        duration = (datetime.utcnow() - start_time).total_seconds()
        logger.info(
            "Request completed", 
            extra={"extra_fields": {"status_code": response.status_code, "duration_seconds": duration}}
        )
        return response
    except Exception as e:
        logger.exception("Unhandled server error encountered")
        raise e
    finally:
        request_id_var.reset(token)

# Register domain API routers
app.include_router(auth_router)
app.include_router(profile_router)
app.include_router(debug_router)

@app.get("/")
def read_root():
    return RedirectResponse(url="/static/index.html")

# Mount frontend assets
app.mount("/static", StaticFiles(directory="jwt_profile_app/static"), name="static")

