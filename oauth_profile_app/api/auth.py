import secrets
import httpx
from urllib.parse import urlparse
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from ..core.config import settings
from ..core.database import get_db
from ..core.security import create_session_cookie, delete_session_cookie
from ..models.models import User

router = APIRouter(prefix="/api/auth", tags=["Third-Party Auth"])

@router.get("/github/login")
def github_login(request: Request):
    state = secrets.token_urlsafe(16)
    
    # Warn on host mismatch
    request_host = request.headers.get("host")
    if request_host and settings.GITHUB_REDIRECT_URI:
        parsed_redirect = urlparse(settings.GITHUB_REDIRECT_URI)
        redirect_host = parsed_redirect.netloc
        if request_host != redirect_host:
            print("\n" + "="*80)
            print(f"WARNING: Host Mismatch Detected in GitHub Login Initiation!")
            print(f"Browsing Host (Request): {request_host}")
            print(f"Redirect URI Host (Config): {redirect_host}")
            print(f"This mismatch WILL cause the browser to fail anti-CSRF state cookie validation")
            print(f"during the callback because cookie domains are distinct.")
            print(f"PLEASE ACCESS THE APPLICATION AT: http://{redirect_host}/")
            print("="*80 + "\n")

    auth_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={settings.GITHUB_CLIENT_ID}"
        f"&redirect_uri={settings.GITHUB_REDIRECT_URI}"
        f"&scope=read:user user:email"
        f"&state={state}"
    )
    
    redirect_res = RedirectResponse(url=auth_url)
    # Set transient anti-CSRF state cookie directly on the RedirectResponse
    redirect_res.set_cookie(
        key="github_oauth_state",
        value=state,
        httponly=True,
        samesite="lax",
        path="/",
        max_age=300  # 5 minutes
    )
    return redirect_res

@router.get("/github/callback")
async def github_callback(request: Request, response: Response, code: str, state: str, db: Session = Depends(get_db)):
    # Validate state cookie to prevent CSRF
    state_cookie = request.cookies.get("github_oauth_state")
    if not state_cookie or state_cookie != state:
        print("\n" + "="*80)
        print("ERROR: GitHub Callback CSRF Validation Failed!")
        print(f"Expected state (from cookie): {state_cookie}")
        print(f"Received state (from URL): {state}")
        print(f"Current Request Cookies: {request.cookies}")
        print(f"Current Request Host: {request.headers.get('host')}")
        if settings.GITHUB_REDIRECT_URI:
            parsed_redirect = urlparse(settings.GITHUB_REDIRECT_URI)
            print(f"Configured Redirect URI Host: {parsed_redirect.netloc}")
        print("Hint: This usually happens due to a host mismatch (e.g. initiating on 127.0.0.1 but callback landing on localhost).")
        print("="*80 + "\n")
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid state parameter. CSRF validation failed. "
                f"Expected state cookie value '{state_cookie or 'None'}', but received '{state}'. "
                "Ensure that the host used to start login matches the OAuth Redirect URI host."
            )
        )
    
    # Clear state cookie
    response.delete_cookie("github_oauth_state", path="/")

    if not settings.GITHUB_CLIENT_ID or not settings.GITHUB_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="GitHub OAuth credentials not configured on the server.")

    # 1. Exchange authorization code for access token
    async with httpx.AsyncClient() as client:
        token_res = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": settings.GITHUB_REDIRECT_URI
            },
            headers={"Accept": "application/json"}
        )
        if token_res.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to retrieve access token from GitHub")
        
        token_data = token_res.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail=f"GitHub token response error: {token_data.get('error_description', 'No access token')}")

        # 2. Query GitHub User API
        user_res = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {access_token}"}
        )
        if user_res.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to retrieve user info from GitHub")
        
        github_profile = user_res.json()
        github_id = str(github_profile.get("id"))
        username = github_profile.get("login")
        display_name = github_profile.get("name") or username
        avatar_url = github_profile.get("avatar_url")
        email = github_profile.get("email")

        # Fallback to fetch email if not returned in public profile
        if not email:
            email_res = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"token {access_token}"}
            )
            if email_res.status_code == 200:
                emails = email_res.json()
                primary_emails = [e for e in emails if e.get("primary") and e.get("verified")]
                if primary_emails:
                    email = primary_emails[0].get("email")
                elif emails:
                    email = emails[0].get("email")

    # 3. Synchronize user in database
    user = db.query(User).filter(User.github_id == github_id).first()
    if not user:
        # Check if username is taken, generate unique one if so
        base_username = username
        counter = 1
        while db.query(User).filter(User.username == username).first():
            username = f"{base_username}{counter}"
            counter += 1

        user = User(
            github_id=github_id,
            username=username,
            email=email,
            display_name=display_name,
            avatar_url=avatar_url,
            bio="GitHub authenticated profile."
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        # Update user profile details
        user.avatar_url = avatar_url
        if email and not user.email:
            user.email = email
        db.commit()

    # 4. Set secure session cookie
    redirect_res = RedirectResponse(url="/static/index.html")
    create_session_cookie(redirect_res, user.id)
    return redirect_res

@router.get("/google/login")
def google_login(request: Request):
    state = secrets.token_urlsafe(16)
    
    # Warn on host mismatch
    request_host = request.headers.get("host")
    if request_host and settings.GOOGLE_REDIRECT_URI:
        parsed_redirect = urlparse(settings.GOOGLE_REDIRECT_URI)
        redirect_host = parsed_redirect.netloc
        if request_host != redirect_host:
            print("\n" + "="*80)
            print(f"WARNING: Host Mismatch Detected in Google Login Initiation!")
            print(f"Browsing Host (Request): {request_host}")
            print(f"Redirect URI Host (Config): {redirect_host}")
            print(f"This mismatch WILL cause the browser to fail anti-CSRF state cookie validation")
            print(f"during the callback because cookie domains are distinct.")
            print(f"PLEASE ACCESS THE APPLICATION AT: http://{redirect_host}/")
            print("="*80 + "\n")

    auth_url = (
        f"https://accounts.google.com/o/oauth2/v2/auth"
        f"?client_id={settings.GOOGLE_CLIENT_ID}"
        f"&redirect_uri={settings.GOOGLE_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=openid%20profile%20email"
        f"&state={state}"
        f"&access_type=offline"
    )
    
    redirect_res = RedirectResponse(url=auth_url)
    # Set transient anti-CSRF state cookie directly on the RedirectResponse
    redirect_res.set_cookie(
        key="google_oauth_state",
        value=state,
        httponly=True,
        samesite="lax",
        path="/",
        max_age=300
    )
    return redirect_res

@router.get("/google/callback")
async def google_callback(request: Request, response: Response, code: str, state: str, db: Session = Depends(get_db)):
    # Validate state cookie
    state_cookie = request.cookies.get("google_oauth_state")
    if not state_cookie or state_cookie != state:
        print("\n" + "="*80)
        print("ERROR: Google Callback CSRF Validation Failed!")
        print(f"Expected state (from cookie): {state_cookie}")
        print(f"Received state (from URL): {state}")
        print(f"Current Request Cookies: {request.cookies}")
        print(f"Current Request Host: {request.headers.get('host')}")
        if settings.GOOGLE_REDIRECT_URI:
            parsed_redirect = urlparse(settings.GOOGLE_REDIRECT_URI)
            print(f"Configured Redirect URI Host: {parsed_redirect.netloc}")
        print("Hint: This usually happens due to a host mismatch (e.g. initiating on 127.0.0.1 but callback landing on localhost).")
        print("="*80 + "\n")
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid state parameter. CSRF validation failed. "
                f"Expected state cookie value '{state_cookie or 'None'}', but received '{state}'. "
                "Ensure that the host used to start login matches the OAuth Redirect URI host."
            )
        )
    
    # Clear state cookie
    response.delete_cookie("google_oauth_state", path="/")

    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Google OAuth credentials not configured on the server.")

    # 1. Exchange authorization code for token
    async with httpx.AsyncClient() as client:
        token_res = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "code": code,
                "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code"
            }
        )
        if token_res.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to retrieve access token from Google")
        
        token_data = token_res.json()
        access_token = token_data.get("access_token")

        # 2. Query Google userinfo API
        user_res = await client.get(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        if user_res.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to retrieve user info from Google")
        
        google_profile = user_res.json()
        google_id = str(google_profile.get("sub"))
        email = google_profile.get("email")
        display_name = google_profile.get("name")
        avatar_url = google_profile.get("picture")
        # Extract a raw username from email
        username = email.split("@")[0]

    # 3. Synchronize user in database
    user = db.query(User).filter(User.google_id == google_id).first()
    if not user:
        # Check if username is taken, generate unique one if so
        base_username = username
        counter = 1
        while db.query(User).filter(User.username == username).first():
            username = f"{base_username}{counter}"
            counter += 1

        user = User(
            google_id=google_id,
            username=username,
            email=email,
            display_name=display_name,
            avatar_url=avatar_url,
            bio="Google authenticated profile."
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        # Update user profile details
        user.avatar_url = avatar_url
        if email and not user.email:
            user.email = email
        db.commit()

    # 4. Set secure session cookie
    redirect_res = RedirectResponse(url="/static/index.html")
    create_session_cookie(redirect_res, user.id)
    return redirect_res

@router.get("/microsoft/login")
def microsoft_login(request: Request):
    request_host = request.headers.get("host") # get the host from the request
    if request_host and settings.MICROSOFT_REDIRECT_URI:
        parsed_redirect = urlparse(settings.MICROSOFT_REDIRECT_URI)
        redirect_host = parsed_redirect.netloc
        if request_host != redirect_host:
            print("="*80)
            print(f"WARNING: Host Mismatch Detected in Microsoft Login Initiation!")
            print(f"Browsing Host (Request): {request_host}")
            print(f"Redirect URI Host (Config): {redirect_host}")
            print(f"This mismatch WILL cause the browser to fail anti-CSRF state cookie validation")
            print(f"during the callback because cookie domains are distinct.")
            print(f"PLEASE ACCESS THE APPLICATION AT: http://{redirect_host}/")
            print("="*80 + "\n")
    

    state = secrets.token_urlsafe(16)
    auth_url = (
        f"https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
        f"?client_id={settings.MICROSOFT_CLIENT_ID}"
        f"&redirect_uri={settings.MICROSOFT_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=openid profile email User.Read"
        f"&state={state}"
    )
    redirect_res = RedirectResponse(url=auth_url)
    redirect_res.set_cookie(
        key="microsoft_oauth_state",
        value=state,
        httponly=True,
        samesite="lax",
        path="/",
        max_age=300
    )
    return redirect_res

@router.get("/microsoft/callback")
async def microsoft_callback(
    request: Request,
    response: Response,
    code: str,
    state: str,
    db: Session = Depends(get_db)
    ):
    
    #validate state cookie
    state_cookie = request.cookies.get("microsoft_oauth_state")
    if not state_cookie or state_cookie != state:
        raise HTTPException(
            status_code=400,
            detail="Invalid state parameter. CSRF validation failed."
        )

    #clear state cookie
    response.delete_cookie("microsoft_oauth_state", path="/")
    
    #check if the creds are configured
    if not settings.MICROSOFT_CLIENT_ID or not settings.MICROSOFT_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="Microsoft OAuth credentials not configured on the server."
        )
    
    #exchange authorization code for access token
    async with httpx.AsyncClient() as client:
        token_res = await client.post(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            data={
                "client_id": settings.MICROSOFT_CLIENT_ID,
                "client_secret": settings.MICROSOFT_CLIENT_SECRET,
                "code": code,
                "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
                "grant_type": "authorization_code"
            }
        )
        if token_res.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to retrieve access token from Microsoft: {token_res.status_code} - {token_res.text}"
            )
        
        token_data = token_res.json()
        access_token = token_data.get("access_token")
        
        #query microsoft userinfo API
        user_res = await client.get(
            "https://graph.microsoft.com/v1.0/me",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        if user_res.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to retrieve user info from Microsoft: {user_res.status_code} - {user_res.text}"
            )
        
        microsoft_profile = user_res.json()
        microsoft_id = str(microsoft_profile.get("id"))
        email = microsoft_profile.get("mail")
        display_name = microsoft_profile.get("displayName")
        avatar_url = microsoft_profile.get("photo")
        
        #extract a raw username from email
        email = microsoft_profile.get("mail") or microsoft_profile.get("userPrincipalName")
        username = email.split("@")[0] if email else f"ms_{microsoft_id[:8]}"
        
        #synchronize user in database
        user = db.query(User).filter(User.microsoft_id == microsoft_id).first()
        if not user:
            # Check if username is taken, generate unique one if so
            base_username = username
            counter = 1
            while db.query(User).filter(User.username == username).first():
                username = f"{base_username}{counter}"
                counter += 1
            
            user = User(
                microsoft_id=microsoft_id,
                username=username,
                email=email,
                display_name=display_name,
                avatar_url=avatar_url,
                bio="Microsoft authenticated profile."
            )
            db.add(user)
            db.commit()
            db.refresh(user)
        else:
            # Update user profile details
            user.avatar_url = avatar_url
            if email and not user.email:
                user.email = email
            db.commit()
        
        #Set secure session cookie
        redirect_res = RedirectResponse(url="/static/index.html")
        create_session_cookie(redirect_res, user.id)
        return redirect_res

@router.get("/discord/login")
def discord_login(request: Request):
    state = secrets.token_urlsafe(16)
    
    # Warn on host mismatch
    request_host = request.headers.get("host")
    if request_host and settings.DISCORD_REDIRECT_URI:
        parsed_redirect = urlparse(settings.DISCORD_REDIRECT_URI)
        redirect_host = parsed_redirect.netloc
        if request_host != redirect_host:
            print("\n" + "="*80)
            print(f"WARNING: Host Mismatch Detected in Discord Login Initiation!")
            print(f"Browsing Host (Request): {request_host}")
            print(f"Redirect URI Host (Config): {redirect_host}")
            print(f"This mismatch WILL cause the browser to fail anti-CSRF state cookie validation")
            print(f"during the callback because cookie domains are distinct.")
            print(f"PLEASE ACCESS THE APPLICATION AT: http://{redirect_host}/")
            print("="*80 + "\n")

    auth_url = (
        f"https://discord.com/oauth2/authorize"
        f"?client_id={settings.DISCORD_CLIENT_ID}"
        f"&redirect_uri={settings.DISCORD_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=identify email"
        f"&state={state}"
    )
    
    redirect_res = RedirectResponse(url=auth_url)
    redirect_res.set_cookie(
        key="discord_oauth_state",
        value=state,
        httponly=True,
        samesite="lax",
        path="/",
        max_age=300
    )
    return redirect_res

@router.get("/discord/callback")
async def discord_callback(request: Request, response: Response, code: str, state: str, db: Session = Depends(get_db)):
    # Validate state cookie
    state_cookie = request.cookies.get("discord_oauth_state")
    if not state_cookie or state_cookie != state:
        print("\n" + "="*80)
        print("ERROR: Discord Callback CSRF Validation Failed!")
        print(f"Expected state (from cookie): {state_cookie}")
        print(f"Received state (from URL): {state}")
        print("="*80 + "\n")
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid state parameter. CSRF validation failed. "
                f"Expected state cookie value '{state_cookie or 'None'}', but received '{state}'."
            )
        )
    
    # Clear state cookie
    response.delete_cookie("discord_oauth_state", path="/")

    if not settings.DISCORD_CLIENT_ID or not settings.DISCORD_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Discord OAuth credentials not configured on the server.")

    # 1. Exchange authorization code for token
    async with httpx.AsyncClient() as client:
        token_res = await client.post(
            "https://discord.com/api/oauth2/token",
            data={
                "client_id": settings.DISCORD_CLIENT_ID,
                "client_secret": settings.DISCORD_CLIENT_SECRET,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.DISCORD_REDIRECT_URI
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        if token_res.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to retrieve access token from Discord: {token_res.status_code} - {token_res.text}"
            )
        
        token_data = token_res.json()
        access_token = token_data.get("access_token")

        # 2. Query Discord User API to fetch profile details
        user_res = await client.get(
            "https://discord.com/api/users/@me",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        if user_res.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail=f"Failed to retrieve user info from Discord: {user_res.status_code} - {user_res.text}"
            )
        
        discord_profile = user_res.json()
        discord_id = str(discord_profile.get("id"))
        username = discord_profile.get("username")
        display_name = discord_profile.get("global_name") or username
        email = discord_profile.get("email")
        
        # Build avatar URL
        avatar_hash = discord_profile.get("avatar")
        if avatar_hash:
            avatar_url = f"https://cdn.discordapp.com/avatars/{discord_id}/{avatar_hash}.png"
        else:
            avatar_url = "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?auto=format&fit=crop&w=150&h=150"

    # 3. Synchronize user in database
    user = db.query(User).filter(User.discord_id == discord_id).first()
    if not user:
        # Check if username is taken, generate unique one if so
        base_username = username
        counter = 1
        while db.query(User).filter(User.username == username).first():
            username = f"{base_username}{counter}"
            counter += 1

        user = User(
            discord_id=discord_id,
            username=username,
            email=email,
            display_name=display_name,
            avatar_url=avatar_url,
            bio="Discord authenticated profile."
        )
        db.add(user)
        db.commit()
        db.refresh(user)
    else:
        # Update user profile details
        user.avatar_url = avatar_url
        if email and not user.email:
            user.email = email
        db.commit()

    # 4. Set secure session cookie
    redirect_res = RedirectResponse(url="/static/index.html")
    create_session_cookie(redirect_res, user.id)
    return redirect_res

@router.post("/logout")
def logout(response: Response):
    delete_session_cookie(response)
    return {"message": "Successfully logged out."}
