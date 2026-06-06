import httpx
import sys

BASE_URL = "http://127.0.0.1:8000"

def test_full_jwt_lifecycle():
    print("=== Stateless JWT Profile Application Verification ===")

    # Use httpx Client to manage cookie state for Refresh Tokens automatically
    with httpx.Client(base_url=BASE_URL) as client:
        # 1. Reset database
        print("\n[+] Resetting sandbox database...")
        res = client.post("/api/debug/reset")
        print(f"Status: {res.status_code}, Response: {res.json()}")
        assert res.status_code == 200

        # 2. Register new user
        print("\n[+] Registering test user 'bob'...")
        register_payload = {
            "username": "bob",
            "password": "bobpassword",
            "display_name": "Bob",
            "email": "bob@example.com",
            "bio": "Initial bio text"
        }
        res = client.post("/api/register", json=register_payload)
        print(f"Status: {res.status_code}, Response: {res.json()['message']}")
        assert res.status_code == 200

        # 3. Log in user
        print("\n[+] Logging in as 'bob'...")
        login_payload = {
            "username": "bob",
            "password": "bobpassword"
        }
        res = client.post("/api/login", json=login_payload)
        print(f"Status: {res.status_code}, Response: {res.json()['message']}")
        assert res.status_code == 200
        
        # Confirm access token returned in body, and refresh cookie set
        access_token = res.json()["access_token"]
        print(f"Stateless Access Token returned: {access_token[:20]}...")
        
        cookies = client.cookies
        print(f"Cookies returned to client: {dict(cookies)}")
        assert "jwt_refresh_token" in cookies
        
        # Keep track of initial refresh token for tampering/reuse tests
        old_refresh_token = cookies["jwt_refresh_token"]

        # 4. Fetch profile (fails without bearer header)
        print("\n[+] Fetching profile without Authorization header (should fail)...")
        res = client.get("/api/profile")
        print(f"Status: {res.status_code}, Detail: {res.json()['detail']}")
        assert res.status_code == 401

        # Fetch profile (succeeds with bearer header)
        print("\n[+] Fetching profile with Authorization Bearer header (should succeed)...")
        headers = {"Authorization": f"Bearer {access_token}"}
        res = client.get("/api/profile", headers=headers)
        print(f"Status: {res.status_code}, User Profile: {res.json()['user']}")
        assert res.status_code == 200
        assert res.json()["user"]["username"] == "bob"

        # 5. Modify profile
        print("\n[+] Updating profile details (display_name, email, bio)...")
        update_payload = {
            "display_name": "Robert Smith",
            "email": "robert.smith@example.com",
            "bio": "Principal Security Developer & Researcher"
        }
        res = client.put("/api/profile", json=update_payload, headers=headers)
        print(f"Status: {res.status_code}, Response: {res.json()['message']}")
        print(f"Updated profile: {res.json()['user']}")
        assert res.status_code == 200
        assert res.json()["user"]["display_name"] == "Robert Smith"

        # 6. Check database debug states
        print("\n[+] Inspecting server DB tables (Users and RefreshTokens)...")
        res = client.get("/api/debug/state")
        print(f"Active Users in DB: {res.json()['users']}")
        print(f"Refresh Tokens in DB: {res.json()['refresh_tokens']}")
        assert len(res.json()["users"]) == 1
        assert len(res.json()["refresh_tokens"]) == 1

        # 7. Rotate Token via refresh
        print("\n[+] Performing token refresh (RTR)...")
        res = client.post("/api/refresh")
        print(f"Status: {res.status_code}")
        assert res.status_code == 200
        new_access_token = res.json()["access_token"]
        print(f"New Access Token: {new_access_token[:20]}...")
        print(f"Cookies after refresh: {dict(client.cookies)}")
        
        # Verify the database has two token records now (one active, one revoked)
        res_state = client.get("/api/debug/state")
        print(f"Tokens after rotation: {res_state.json()['refresh_tokens']}")
        assert len(res_state.json()['refresh_tokens']) == 2

        # 8. Attempt Replay Attack (using old refresh token)
        print("\n[+] Attempting replay attack with old revoked refresh token...")
        # Create a clean client without cookies to send old refresh token manually
        with httpx.Client(base_url=BASE_URL) as attacker_client:
            attacker_client.cookies.set("jwt_refresh_token", old_refresh_token)
            res_attack = attacker_client.post("/api/refresh")
            print(f"Status: {res_attack.status_code}, Response: {res_attack.json()['detail']}")
            assert res_attack.status_code == 401
            
        # Verify that because of RTR safety check, all tokens for the user have been revoked
        res_state = client.get("/api/debug/state")
        print(f"Tokens after replay prevention check: {res_state.json()['refresh_tokens']}")
        for t in res_state.json()['refresh_tokens']:
            assert t['is_revoked'] is True

        # 9. Log in again to get fresh tokens
        print("\n[+] Logging in again to get a fresh session...")
        res = client.post("/api/login", json=login_payload)
        access_token = res.json()["access_token"]
        headers = {"Authorization": f"Bearer {access_token}"}

        # 10. Rotate password (should invalidate active refresh tokens)
        print("\n[+] Changing password for 'bob'...")
        pwd_payload = {
            "current_password": "bobpassword",
            "new_password": "newbobpassword"
        }
        res = client.post("/api/change-password", json=pwd_payload, headers=headers)
        print(f"Status: {res.status_code}, Response: {res.json()['message']}")
        assert res.status_code == 200

        # Verify other refresh tokens are revoked, but the current cookie's refresh token remains active
        res_state = client.get("/api/debug/state")
        print(f"Tokens after password rotation: {res_state.json()['refresh_tokens']}")
        
        import jwt
        active_token_cookie = client.cookies.get("jwt_refresh_token")
        decoded = jwt.decode(active_token_cookie, options={"verify_signature": False})
        current_jti = decoded.get("jti")
        
        for t in res_state.json()['refresh_tokens']:
            if current_jti and t['jti'].startswith(current_jti[:8]):
                assert t['is_revoked'] is False, "Current refresh token should not be revoked."
            else:
                assert t['is_revoked'] is True, "Other refresh tokens must be revoked."

        # 11. Log out
        print("\n[+] Logging out...")
        res = client.post("/api/logout")
        print(f"Status: {res.status_code}, Response: {res.json()['message']}")
        print(f"Cookies after logout: {dict(client.cookies)}")
        assert res.status_code == 200

    print("\n=== Verification Finished - All Checks Passed ===")

if __name__ == "__main__":
    try:
        test_full_jwt_lifecycle()
    except AssertionError as ae:
        print("\n[!] AssertionError: Verification check failed!")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)
