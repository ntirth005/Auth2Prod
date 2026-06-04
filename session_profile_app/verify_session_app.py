import httpx
import sys

BASE_URL = "http://127.0.0.1:8000"

def test_full_lifecycle():
    print("=== Stateful Session Profile Application Verification ===")

    # Initialize httpx Client to automatically persist cookies
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
        
        # Confirm cookie was stored in client session
        cookies = client.cookies
        print(f"Cookies returned to client: {dict(cookies)}")
        assert "session_profile_id" in cookies

        # 4. Fetch profile
        print("\n[+] Fetching active profile...")
        res = client.get("/api/profile")
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
        res = client.put("/api/profile", json=update_payload)
        print(f"Status: {res.status_code}, Response: {res.json()['message']}")
        print(f"Updated profile: {res.json()['user']}")
        assert res.status_code == 200
        assert res.json()["user"]["display_name"] == "Robert Smith"
        assert res.json()["user"]["email"] == "robert.smith@example.com"
        assert res.json()["user"]["bio"] == "Principal Security Developer & Researcher"

        # 6. Check database debug states
        print("\n[+] Inspecting server DB tables...")
        res = client.get("/api/debug/state")
        print(f"Active Users in DB: {res.json()['users']}")
        print(f"Active Sessions in DB: {res.json()['sessions']}")
        assert len(res.json()["users"]) == 1
        assert len(res.json()["sessions"]) == 1

        # 7. Rotate password
        print("\n[+] Changing password for 'bob'...")
        pwd_payload = {
            "current_password": "bobpassword",
            "new_password": "newbobpassword"
        }
        res = client.post("/api/change-password", json=pwd_payload)
        print(f"Status: {res.status_code}, Response: {res.json()['message']}")
        assert res.status_code == 200

        # Verify we can still access the profile within the same session
        print("\n[+] Verifying session is maintained after password update...")
        res = client.get("/api/profile")
        print(f"Status: {res.status_code}, Profile: {res.json()['user']['display_name']}")
        assert res.status_code == 200

        # 8. Log out
        print("\n[+] Logging out...")
        res = client.post("/api/logout")
        print(f"Status: {res.status_code}, Response: {res.json()['message']}")
        print(f"Cookies after logout: {dict(client.cookies)}")
        assert res.status_code == 200

        # 9. Verify access is rejected
        print("\n[+] Accessing profile post-logout (should fail)...")
        res = client.get("/api/profile")
        print(f"Status: {res.status_code}, Detail: {res.json()['detail']}")
        assert res.status_code == 401

        # 10. Attempt login with old password (should fail)
        print("\n[+] Logging in with old password (should fail)...")
        login_payload["password"] = "bobpassword"
        res = client.post("/api/login", json=login_payload)
        print(f"Status: {res.status_code}, Detail: {res.json()['detail']}")
        assert res.status_code == 401

        # 11. Log in with new password (should succeed)
        print("\n[+] Logging in with rotated password (should succeed)...")
        login_payload["password"] = "newbobpassword"
        res = client.post("/api/login", json=login_payload)
        print(f"Status: {res.status_code}, Response: {res.json()['message']}")
        assert res.status_code == 200

    print("\n=== Verification Finished - All Checks Passed ===")

if __name__ == "__main__":
    try:
        test_full_lifecycle()
    except AssertionError as ae:
        print("\n[!] AssertionError: Verification check failed!")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)
