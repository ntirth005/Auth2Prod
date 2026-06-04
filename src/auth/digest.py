import hashlib
import time
import hmac
import re
import base64
from typing import Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import User
from ..security import DIGEST_REALM

router = APIRouter(prefix="/auth/digest", tags=["Digest Authentication"])

# Secret key to sign stateless nonces
SERVER_SECRET = "super_secret_auth2prod_key"

def parse_digest_header(header_value: str) -> Dict[str, str]:
    """Parses HTTP Digest Authentication header parameters."""
    if not header_value or not header_value.startswith("Digest "):
        return {}
    params_str = header_value[7:]
    # Matches key="value" or key=value
    pattern = re.compile(r'(\w+)=(?:"([^"]*)"|([^,\s]*))')
    params = {}
    for match in pattern.finditer(params_str):
        key = match.group(1)
        val = match.group(2) if match.group(2) is not None else match.group(3)
        params[key] = val
    return params

def generate_nonce() -> str:
    """Generates a signed, stateless nonce containing a timestamp."""
    timestamp = str(int(time.time()))
    sig = hmac.new(
        SERVER_SECRET.encode("utf-8"), 
        timestamp.encode("utf-8"), 
        hashlib.sha256
    ).hexdigest()
    # Format: timestamp:signature
    raw_nonce = f"{timestamp}:{sig}"
    return base64.b64encode(raw_nonce.encode("utf-8")).decode("utf-8")

def verify_nonce(nonce: str, max_age: int = 300) -> bool:
    """Verifies that the nonce is signed correctly and has not expired."""
    try:
        decoded = base64.b64decode(nonce.encode("utf-8")).decode("utf-8")
        timestamp_str, sig = decoded.split(":", 1)
        timestamp = int(timestamp_str)
    except Exception:
        return False

    # Check expiration
    if int(time.time()) - timestamp > max_age:
        return False

    # Verify signature
    expected_sig = hmac.new(
        SERVER_SECRET.encode("utf-8"), 
        timestamp_str.encode("utf-8"), 
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(sig, expected_sig)

def get_current_user_digest(request: Request, db: Session = Depends(get_db)) -> User:
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise_digest_challenge()

    params = parse_digest_header(auth_header)
    required_params = ["username", "realm", "nonce", "uri", "response"]
    if not all(p in params for p in required_params):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Digest authorization header format"
        )

    # 1. Verify realm and nonce integrity/expiry
    if params["realm"] != DIGEST_REALM or not verify_nonce(params["nonce"]):
        raise_digest_challenge()

    # 2. Fetch User and their HA1 hash from database
    user = db.query(User).filter(User.username == params["username"]).first()
    if not user or not user.digest_ha1:
        raise_digest_challenge()

    # 3. Calculate HA2 = MD5(method:uri)
    method = request.method
    uri = params["uri"]
    ha2_source = f"{method}:{uri}"
    ha2 = hashlib.md5(ha2_source.encode("utf-8")).hexdigest()

    # 4. Calculate expected response hash
    ha1 = user.digest_ha1
    nonce = params["nonce"]
    qop = params.get("qop")
    
    if qop == "auth":
        nc = params.get("nc")
        cnonce = params.get("cnonce")
        if not nc or not cnonce:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing nc or cnonce parameters for auth qop"
            )
        response_source = f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}"
    else:
        response_source = f"{ha1}:{nonce}:{ha2}"

    expected_response = hashlib.md5(response_source.encode("utf-8")).hexdigest()

    if not hmac.compare_digest(params["response"], expected_response):
        raise_digest_challenge()

    return user

def raise_digest_challenge():
    """Raises a 401 Unauthorized with the WWW-Authenticate header initiating the Digest flow."""
    nonce = generate_nonce()
    challenge = f'Digest realm="{DIGEST_REALM}", nonce="{nonce}", qop="auth", algorithm="MD5"'
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Digest authentication required",
        headers={"WWW-Authenticate": challenge}
    )

@router.get("/protected")
def protected_route(user: User = Depends(get_current_user_digest)):
    """A protected endpoint that validates client response to Digest Authentication challenge."""
    return {
        "message": f"Hello {user.username}! You authenticated successfully using HTTP Digest Auth.",
        "auth_method": "digest",
        "user": {
            "id": user.id,
            "username": user.username
        }
    }
