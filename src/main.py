import time
import jwt
from fastapi import FastAPI, HTTPException, status, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Auth2Prod - JWT Protocol Visualizer & Playground",
    description="A diagnostic environment for studying JWT structure, claims, signature validation, and token tampering."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/playground/generate")
def generate_jwt(payload: dict, request: Request):
    """Generates a JWT token using custom inputs for study."""
    sub = payload.get("sub", "123")
    username = payload.get("username", "alice")
    role = payload.get("role", "user")
    expires_in = int(payload.get("expires_in", 60))  # seconds
    secret = payload.get("secret", "playground-secret-key-123456")
    alg = payload.get("alg", "HS256")
    
    # Custom headers
    headers = {"typ": "JWT", "alg": alg}
    
    # Build claims
    now = int(time.time())
    token_claims = {
        "sub": sub,
        "username": username,
        "role": role,
        "iat": now,
        "exp": now + expires_in
    }
    
    try:
        token = jwt.encode(token_claims, secret, algorithm=alg, headers=headers)
        
        debug_meta = {
            "request": {
                "method": "POST",
                "url": str(request.url),
                "headers": dict(request.headers),
                "body": payload
            },
            "db_actions": ["No DB check (Stateless token creation on server)"],
            "response_headers": {}
        }
        
        return {
            "token": token,
            "header": headers,
            "payload": token_claims,
            "debug": debug_meta
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to generate JWT: {str(e)}"
        )

@app.post("/api/playground/verify")
def verify_jwt(payload: dict, request: Request):
    """Verifies a JWT token with a specified secret and algorithm, returning granular diagnostics."""
    token = payload.get("token", "")
    secret = payload.get("secret", "playground-secret-key-123456")
    alg = payload.get("alg", "HS256")
    
    db_actions = []
    resp_headers = {}
    
    try:
        # Decode without verification first to extract raw header/payload details for diagnostic display
        unverified_header = jwt.get_unverified_header(token)
        unverified_payload = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        # Malformed token structure (not 3 dot-separated parts)
        return {
            "is_valid": False,
            "error_type": "InvalidTokenError",
            "message": f"Malformed JWT structure: {str(e)}",
            "header": {},
            "payload": {},
            "debug": {
                "request": {
                    "method": "POST",
                    "url": str(request.url),
                    "headers": dict(request.headers),
                    "body": payload
                },
                "db_actions": ["No DB check (Stateless check failed early)"],
                "response_headers": resp_headers
            }
        }
        
    try:
        # Full validation check
        verified_payload = jwt.decode(token, secret, algorithms=[alg])
        is_valid = True
        message = "Signature is valid and token is active."
        error_type = None
    except jwt.ExpiredSignatureError:
        is_valid = False
        error_type = "ExpiredSignatureError"
        message = "Token has expired (exp claim is in the past)."
    except jwt.InvalidSignatureError:
        is_valid = False
        error_type = "InvalidSignatureError"
        message = "Signature verification failed. The token was tampered with or signed with a different secret."
    except jwt.InvalidTokenError as e:
        is_valid = False
        error_type = "InvalidTokenError"
        message = f"Token validation failed: {str(e)}"
        
    debug_meta = {
        "request": {
            "method": "POST",
            "url": str(request.url),
            "headers": dict(request.headers),
            "body": payload
        },
        "db_actions": ["No DB check (Stateless check completed successfully)"],
        "response_headers": resp_headers
    }
    
    return {
        "is_valid": is_valid,
        "error_type": error_type,
        "message": message,
        "header": unverified_header,
        "payload": unverified_payload,
        "debug": debug_meta
    }

# Mount static files
app.mount("/static", StaticFiles(directory="src/static"), name="static")

@app.get("/")
def read_root():
    return RedirectResponse(url="/static/index.html")
