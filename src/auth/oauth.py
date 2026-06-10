import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import User, OAuthClient, OAuthAuthCode, OAuthAccessToken
from ..security import (
    verify_password,
    generate_random_token,
    create_jwt_token,
    decode_jwt_token,
    hash_password
)

router = APIRouter(prefix="/api", tags=["OAuth 2.0"])

async def capture_debug_meta(request: Request, db_queries: list, response_headers: dict = None):
    body = None
    try:
        if request.method in ["POST", "PUT"]:
            body = await request.json()
    except Exception:
        # Fallback to form parsing if JSON fails
        try:
            form = await request.form()
            if form:
                body = dict(form)
        except Exception:
            pass

    return {
        "request": {
            "method": request.method,
            "url": str(request.url),
            "headers": {k: v for k, v in request.headers.items() if k.lower() in ["authorization", "content-type", "accept"]},
            "body": body
        },
        "db_actions": db_queries,
        "response_headers": response_headers or {}
    }

@router.post("/oauth/register_client")
async def register_client(request: Request, db: Session = Depends(get_db)):
    payload = await request.json()
    client_id = payload.get("client_id")
    client_secret = payload.get("client_secret")
    client_name = payload.get("client_name")
    redirect_uri = payload.get("redirect_uri")

    db_queries = [
        f"SELECT * FROM oauth_clients WHERE client_id = '{client_id}'"
    ]
    existing = db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Client already registered")

    client = OAuthClient(
        client_id=client_id,
        client_secret=client_secret,
        client_name=client_name,
        redirect_uri=redirect_uri
    )
    db.add(client)
    db.commit()
    db.refresh(client)

    db_queries.append(f"INSERT INTO oauth_clients (client_id, client_secret, client_name, redirect_uri) VALUES ('{client_id}', '***', '{client_name}', '{redirect_uri}')")

    debug_meta = await capture_debug_meta(request, db_queries)
    return {"message": "Client registered successfully", "client_id": client_id, "debug": debug_meta}

@router.get("/oauth/authorize")
async def oauth_authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    response_type: str,
    scope: str,
    state: str,
    db: Session = Depends(get_db)
):
    db_queries = [
        f"SELECT * FROM oauth_clients WHERE client_id = '{client_id}'"
    ]
    client = db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()
    
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client_id")
    if client.redirect_uri != redirect_uri:
        raise HTTPException(status_code=400, detail="Redirect URI mismatch")
    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response_type (must be 'code')")

    debug_meta = await capture_debug_meta(request, db_queries)
    return {
        "client_name": client.client_name,
        "scope": scope,
        "state": state,
        "debug": debug_meta
    }

@router.post("/oauth/consent")
async def oauth_consent(request: Request, db: Session = Depends(get_db)):
    payload = await request.json()
    client_id = payload.get("client_id")
    redirect_uri = payload.get("redirect_uri")
    scope = payload.get("scope")
    state = payload.get("state")
    username = payload.get("username")
    password = payload.get("password")
    action = payload.get("action") # "approve" or "deny"

    db_queries = []

    if action != "approve":
        debug_meta = await capture_debug_meta(request, db_queries)
        return {
            "redirect_url": f"{redirect_uri}?error=access_denied&state={state}",
            "debug": debug_meta
        }

    db_queries.append(f"SELECT * FROM users WHERE username = '{username}'")
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid user credentials")

    # Generate authorization code
    code = f"ac_{generate_random_token(16)}"
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
    
    auth_code = OAuthAuthCode(
        code=code,
        client_id=client_id,
        user_id=user.id,
        scope=scope,
        expires_at=expires_at,
        is_used=False
    )
    db.add(auth_code)
    db.commit()

    db_queries.append(f"INSERT INTO oauth_auth_codes (code, client_id, user_id, scope, expires_at, is_used) VALUES ('{code[:10]}...', '{client_id}', {user.id}, '{scope}', ..., False)")

    debug_meta = await capture_debug_meta(request, db_queries)
    return {
        "redirect_url": f"{redirect_uri}?code={code}&state={state}",
        "debug": debug_meta
    }

@router.post("/oauth/token")
async def oauth_token(request: Request, db: Session = Depends(get_db)):
    # Read payload (form-urlencoded or json)
    body = {}
    try:
        body = await request.json()
    except Exception:
        form = await request.form()
        body = dict(form)

    grant_type = body.get("grant_type")
    code = body.get("code")
    redirect_uri = body.get("redirect_uri")
    client_id = body.get("client_id")
    client_secret = body.get("client_secret")

    db_queries = []

    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="Invalid grant_type")

    # Validate client credentials
    db_queries.append(f"SELECT * FROM oauth_clients WHERE client_id = '{client_id}'")
    client = db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()
    if not client or client.client_secret != client_secret:
        raise HTTPException(status_code=401, detail="Invalid client credentials")

    # Validate auth code
    db_queries.append(f"SELECT * FROM oauth_auth_codes WHERE code = '{code[:10]}...'")
    auth_code_record = db.query(OAuthAuthCode).filter(OAuthAuthCode.code == code).first()
    if not auth_code_record:
        raise HTTPException(status_code=400, detail="Invalid authorization code")
    if auth_code_record.is_used:
        raise HTTPException(status_code=400, detail="Authorization code has already been used")
    if auth_code_record.expires_at < datetime.datetime.utcnow():
        raise HTTPException(status_code=400, detail="Authorization code expired")
    if auth_code_record.client_id != client_id:
        raise HTTPException(status_code=400, detail="Client ID mismatch")

    # Mark code as used
    auth_code_record.is_used = True
    db.commit()
    db_queries.append(f"UPDATE oauth_auth_codes SET is_used = True WHERE code = '{code[:10]}...'")

    # Issue tokens
    user = auth_code_record.user
    access_token_str = f"at_{generate_random_token(24)}"
    
    # Stateless Access Token Payload
    access_payload = {
        "sub": str(user.id),
        "client_id": client_id,
        "scope": auth_code_record.scope,
        "type": "access"
    }
    access_jwt = create_jwt_token(access_payload, datetime.timedelta(hours=1))

    # OIDC ID Token Payload containing user claims
    id_payload = {
        "sub": str(user.id),
        "iss": "http://localhost:8000/api/oauth",
        "aud": client_id,
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "type": "id_token"
    }
    id_jwt = create_jwt_token(id_payload, datetime.timedelta(hours=1))

    # Save token tracking record in DB (for visualization purposes)
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    db_token = OAuthAccessToken(
        token=access_jwt,
        client_id=client_id,
        user_id=user.id,
        scope=auth_code_record.scope,
        expires_at=expires_at,
        is_revoked=False
    )
    db.add(db_token)
    db.commit()

    db_queries.append(f"INSERT INTO oauth_access_tokens (token, client_id, user_id, scope, expires_at, is_revoked) VALUES ('{access_jwt[:10]}...', '{client_id}', {user.id}, '{auth_code_record.scope}', ..., False)")

    debug_meta = await capture_debug_meta(request, db_queries)
    return {
        "access_token": access_jwt,
        "id_token": id_jwt,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": auth_code_record.scope,
        "debug": debug_meta
    }

@router.get("/oauth/userinfo")
async def oauth_userinfo(request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    db_queries = []

    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    
    token = auth_header.split(" ")[1]
    payload = decode_jwt_token(token)
    if not payload or payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid or expired access token")

    user_id = int(payload.get("sub"))
    db_queries.append(f"SELECT * FROM users WHERE id = {user_id}")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    debug_meta = await capture_debug_meta(request, db_queries)
    return {
        "sub": str(user.id),
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "bio": user.bio,
        "debug": debug_meta
    }

@router.get("/resource")
async def protected_resource(request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    db_queries = []

    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    
    token = auth_header.split(" ")[1]
    payload = decode_jwt_token(token)
    if not payload or payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid or expired access token")

    # Check if revoked in database tracking
    db_queries.append(f"SELECT * FROM oauth_access_tokens WHERE token = '{token[:10]}...'")
    token_record = db.query(OAuthAccessToken).filter(OAuthAccessToken.token == token).first()
    if token_record and token_record.is_revoked:
        raise HTTPException(status_code=401, detail="Access token has been revoked")

    user_id = int(payload.get("sub"))
    db_queries.append(f"SELECT username FROM users WHERE id = {user_id}")
    username = db.query(User.username).filter(User.id == user_id).scalar()

    debug_meta = await capture_debug_meta(request, db_queries)
    return {
        "message": f"Success! Accessible only via active Access Token bearer authentication.",
        "sensitive_data": {
            "server_epoch": int(datetime.datetime.utcnow().timestamp()),
            "owner": username,
            "system_integrity": "OK",
            "scope_granted": payload.get("scope")
        },
        "debug": debug_meta
    }

@router.get("/debug/state")
def get_debug_state(db: Session = Depends(get_db)):
    users = db.query(User).all()
    clients = db.query(OAuthClient).all()
    codes = db.query(OAuthAuthCode).all()
    tokens = db.query(OAuthAccessToken).all()

    return {
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "display_name": u.display_name
            } for u in users
        ],
        "clients": [
            {
                "client_id": c.client_id,
                "client_name": c.client_name,
                "redirect_uri": c.redirect_uri
            } for c in clients
        ],
        "auth_codes": [
            {
                "id": cd.id,
                "code_prefix": cd.code[:10] + "...",
                "client_id": cd.client_id,
                "username": cd.user.username if cd.user else "Unknown",
                "is_used": cd.is_used,
                "expires_at": cd.expires_at.isoformat()
            } for cd in codes
        ],
        "access_tokens": [
            {
                "id": t.id,
                "token_prefix": t.token[:12] + "...",
                "client_id": t.client_id,
                "username": t.user.username if t.user else "Unknown",
                "is_revoked": t.is_revoked,
                "expires_at": t.expires_at.isoformat()
            } for t in tokens
        ]
    }

@router.post("/debug/reset")
def reset_database(db: Session = Depends(get_db)):
    db.query(OAuthAccessToken).delete()
    db.query(OAuthAuthCode).delete()
    db.query(OAuthClient).delete()
    db.query(User).delete()
    db.commit()
    return {"message": "All oauth tables and users reset."}
