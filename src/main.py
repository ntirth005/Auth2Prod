import time
import jwt
from fastapi import FastAPI, HTTPException, status, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(
    title="Auth2Prod - Stateless JWT RBAC Visualizer & Guard Simulator",
    description="An educational diagnostic workspace for studying JWT structures, claim mappings, tampering effects, and role-based access control evaluations."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class GenerateRequest(BaseModel):
    sub: str
    username: str
    roles: List[str]
    permissions: List[str]
    secret_key: str
    algorithm: str
    expiry: int  # In minutes

class EvaluateRequest(BaseModel):
    token: str
    secret_key: str
    algorithm: str
    required_role: Optional[str] = None
    required_permission: Optional[str] = None

@app.post("/api/playground/generate")
def generate_jwt(payload: GenerateRequest, request: Request):
    """Generates and signs a stateless JWT token using user-supplied parameters."""
    now = int(time.time())
    token_claims = {
        "sub": payload.sub,
        "username": payload.username,
        "roles": payload.roles,
        "permissions": payload.permissions,
        "iat": now,
        "exp": now + (payload.expiry * 60)
    }
    
    headers = {
        "typ": "JWT",
        "alg": payload.algorithm
    }

    try:
        token = jwt.encode(
            token_claims, 
            payload.secret_key, 
            algorithm=payload.algorithm, 
            headers=headers
        )

        debug_meta = {
            "request": {
                "method": "POST",
                "url": str(request.url),
                "headers": dict(request.headers),
                "body": payload.model_dump()
            },
            "db_actions": ["No DB operations (Stateless token generation completed in-memory)"],
            "response_headers": {"Content-Type": "application/json"}
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

@app.post("/api/playground/evaluate")
def evaluate_jwt(payload: EvaluateRequest, request: Request):
    """Decodes, verifies, and runs RBAC guard checks on the JWT in a step-by-step fashion."""
    token = payload.token.strip()
    secret_key = payload.secret_key
    algorithm = payload.algorithm
    required_role = payload.required_role.strip() if payload.required_role else None
    required_permission = payload.required_permission.strip() if payload.required_permission else None

    evaluation_logs = []
    is_valid = True
    error_type = None
    message = "Evaluation successful."
    unverified_header = {}
    unverified_payload = {}

    # --- STEP 1: Parse Structure ---
    try:
        unverified_header = jwt.get_unverified_header(token)
        unverified_payload = jwt.decode(token, options={"verify_signature": False})
        
        evaluation_logs.append({
            "step": 1,
            "name": "Parse Structure",
            "status": "success",
            "message": "Token structure is valid. Header and claims decoded successfully.",
            "detail": f"Decoded Header: {unverified_header}\n\nDecoded Claims Payload: {unverified_payload}"
        })
    except Exception as e:
        evaluation_logs.append({
            "step": 1,
            "name": "Parse Structure",
            "status": "failed",
            "message": "Malformed JWT structure. Token must consist of 3 dot-separated base64url segments.",
            "detail": f"Parsing Error: {str(e)}"
        })
        evaluation_logs.extend([
            {"step": 2, "name": "Verify Signature", "status": "skipped", "message": "Signature check skipped due to structural parsing failure.", "detail": ""},
            {"step": 3, "name": "Expiry Check", "status": "skipped", "message": "Expiry check skipped due to structural parsing failure.", "detail": ""},
            {"step": 4, "name": "Claim Check", "status": "skipped", "message": "RBAC claims evaluation skipped due to structural parsing failure.", "detail": ""}
        ])
        
        return {
            "is_valid": False,
            "error_type": "InvalidTokenError",
            "message": f"Malformed JWT structure: {str(e)}",
            "header": {},
            "payload": {},
            "evaluation_logs": evaluation_logs,
            "debug": {
                "request": {
                    "method": "POST",
                    "url": str(request.url),
                    "headers": dict(request.headers),
                    "body": payload.model_dump()
                },
                "db_actions": ["No DB operations (Stateless check failed at parsing stage)"],
                "response_headers": {"Content-Type": "application/json"}
            }
        }

    # --- STEP 2: Verify Signature (Isolating signature verification from expiration check) ---
    try:
        jwt.decode(token, secret_key, algorithms=[algorithm], options={"verify_exp": False})
        evaluation_logs.append({
            "step": 2,
            "name": "Verify Signature",
            "status": "success",
            "message": f"Cryptographic signature is authentic, matching expected algorithm {algorithm}.",
            "detail": f"Signature integrity successfully validated using the configured secret key."
        })
    except jwt.InvalidSignatureError:
        evaluation_logs.append({
            "step": 2,
            "name": "Verify Signature",
            "status": "failed",
            "message": "Signature verification failed. The token was tampered with or signed with a different key.",
            "detail": f"Decoded header specifies algorithm '{unverified_header.get('alg')}', signature checked against algorithm '{algorithm}' using expected key."
        })
        evaluation_logs.extend([
            {"step": 3, "name": "Expiry Check", "status": "skipped", "message": "Expiry check skipped due to signature validation failure.", "detail": ""},
            {"step": 4, "name": "Claim Check", "status": "skipped", "message": "RBAC claims evaluation skipped due to signature validation failure.", "detail": ""}
        ])
        return {
            "is_valid": False,
            "error_type": "InvalidSignatureError",
            "message": "Signature verification failed. The token is invalid or has been modified.",
            "header": unverified_header,
            "payload": unverified_payload,
            "evaluation_logs": evaluation_logs,
            "debug": {
                "request": {
                    "method": "POST",
                    "url": str(request.url),
                    "headers": dict(request.headers),
                    "body": payload.model_dump()
                },
                "db_actions": ["No DB operations (Stateless check failed signature validation)"],
                "response_headers": {"Content-Type": "application/json"}
            }
        }
    except Exception as e:
        evaluation_logs.append({
            "step": 2,
            "name": "Verify Signature",
            "status": "failed",
            "message": f"Cryptographic validation failed: {str(e)}",
            "detail": f"Ensure your verifier expected algorithm matches the token algorithm."
        })
        evaluation_logs.extend([
            {"step": 3, "name": "Expiry Check", "status": "skipped", "message": "Expiry check skipped due to signature error.", "detail": ""},
            {"step": 4, "name": "Claim Check", "status": "skipped", "message": "RBAC claims evaluation skipped due to signature error.", "detail": ""}
        ])
        return {
            "is_valid": False,
            "error_type": "InvalidTokenError",
            "message": f"Signature validation error: {str(e)}",
            "header": unverified_header,
            "payload": unverified_payload,
            "evaluation_logs": evaluation_logs,
            "debug": {
                "request": {
                    "method": "POST",
                    "url": str(request.url),
                    "headers": dict(request.headers),
                    "body": payload.model_dump()
                },
                "db_actions": ["No DB operations (Stateless check failed at signature stage)"],
                "response_headers": {"Content-Type": "application/json"}
            }
        }

    # --- STEP 3: Expiry Check ---
    exp = unverified_payload.get("exp")
    now = int(time.time())
    if exp is None:
        evaluation_logs.append({
            "step": 3,
            "name": "Expiry Check",
            "status": "success",
            "message": "No expiration claim ('exp') present. Token treated as permanent.",
            "detail": "Expiration validation skipped since no 'exp' key exists in payload."
        })
    else:
        time_remaining = exp - now
        if time_remaining >= 0:
            evaluation_logs.append({
                "step": 3,
                "name": "Expiry Check",
                "status": "success",
                "message": f"Token is currently active. Expires in {time_remaining} seconds.",
                "detail": f"Current Server Time: {now} ({time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(now))} UTC)\nClaimed Expiry Time: {exp} ({time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(exp))} UTC)"
            })
        else:
            evaluation_logs.append({
                "step": 3,
                "name": "Expiry Check",
                "status": "failed",
                "message": f"Token has expired. Overdue by {abs(time_remaining)} seconds.",
                "detail": f"Current Server Time: {now} ({time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(now))} UTC)\nClaimed Expiry Time: {exp} ({time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(exp))} UTC)"
            })
            evaluation_logs.append({
                "step": 4,
                "name": "Claim Check",
                "status": "skipped",
                "message": "RBAC claims evaluation skipped due to token expiration.",
                "detail": ""
            })
            return {
                "is_valid": False,
                "error_type": "ExpiredSignatureError",
                "message": "Token has expired (exp claim is in the past).",
                "header": unverified_header,
                "payload": unverified_payload,
                "evaluation_logs": evaluation_logs,
                "debug": {
                    "request": {
                        "method": "POST",
                        "url": str(request.url),
                        "headers": dict(request.headers),
                        "body": payload.model_dump()
                    },
                    "db_actions": ["No DB operations (Stateless check failed token expiration)"],
                    "response_headers": {"Content-Type": "application/json"}
                }
            }

    # --- STEP 4: Claim Check ---
    token_roles = unverified_payload.get("roles", [])
    token_permissions = unverified_payload.get("permissions", [])

    if not isinstance(token_roles, list):
        token_roles = [token_roles] if token_roles else []
    if not isinstance(token_permissions, list):
        token_permissions = [token_permissions] if token_permissions else []

    role_ok = True
    perm_ok = True
    claim_details = []

    if required_role:
        if required_role in token_roles:
            claim_details.append(f"✅ Required role '{required_role}' found in token claims.")
        else:
            role_ok = False
            claim_details.append(f"❌ Required role '{required_role}' is missing from token claims {token_roles}.")

    if required_permission:
        if required_permission in token_permissions:
            claim_details.append(f"✅ Required permission '{required_permission}' found in token claims.")
        else:
            perm_ok = False
            claim_details.append(f"❌ Required permission '{required_permission}' is missing from token claims {token_permissions}.")

    if role_ok and perm_ok:
        evaluation_logs.append({
            "step": 4,
            "name": "Claim Check",
            "status": "success",
            "message": "RBAC claims checks passed. Token contains all required roles and permissions.",
            "detail": "\n".join(claim_details) if claim_details else "No role or permission guard parameters were required for this evaluation."
        })
        message = "Access Granted: Token is valid and all RBAC checks passed."
    else:
        is_valid = False
        evaluation_logs.append({
            "step": 4,
            "name": "Claim Check",
            "status": "failed",
            "message": "RBAC claims evaluation failed. Required claims missing.",
            "detail": "\n".join(claim_details)
        })
        
        if not role_ok and not perm_ok:
            error_type = "ClaimsMissingError"
            message = f"Access Denied: Missing role '{required_role}' and permission '{required_permission}'."
        elif not role_ok:
            error_type = "RoleMissingError"
            message = f"Access Denied: Missing role '{required_role}'."
        else:
            error_type = "PermissionMissingError"
            message = f"Access Denied: Missing permission '{required_permission}'."

    debug_meta = {
        "request": {
            "method": "POST",
            "url": str(request.url),
            "headers": dict(request.headers),
            "body": payload.model_dump()
        },
        "db_actions": ["No DB operations (Stateless check completed successfully)"],
        "response_headers": {"Content-Type": "application/json"}
    }

    return {
        "is_valid": is_valid,
        "error_type": error_type,
        "message": message,
        "header": unverified_header,
        "payload": unverified_payload,
        "evaluation_logs": evaluation_logs,
        "debug": debug_meta
    }

# Mount static files
app.mount("/static", StaticFiles(directory="src/static"), name="static")

@app.get("/")
def read_root():
    return RedirectResponse(url="/static/index.html")
