import httpx
import sys

BASE_URL = "http://127.0.0.1:8000"

# Color Codes for Terminal Logs
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

def log_pass(msg: str):
    print(f"{GREEN}[PASS] {msg}{RESET}")

def log_fail(msg: str):
    print(f"{RED}[FAIL] {msg}{RESET}")
    
def log_info(msg: str):
    print(f"{CYAN}[INFO] {msg}{RESET}")

def run_tests():
    log_info("Starting automated integration verification for RBAC boundaries...")
    
    client = httpx.Client(base_url=BASE_URL, timeout=10.0)
    
    # 0. Connection Check
    try:
        client.get("/api/debug/state")
    except httpx.ConnectError:
        log_fail(f"Could not connect to FastAPI server at {BASE_URL}.")
        log_info("Please start the server first by running:")
        print("  PYTHONPATH=. .venv/bin/uvicorn rbac_profile_app.main:app --reload --port 8000")
        sys.exit(1)

    # 1. Reset Database & Auto-Seed Users
    log_info("1. Triggering system database reset...")
    reset_resp = client.post("/api/debug/reset")
    if reset_resp.status_code == 200:
        log_pass("Database reset and seeded default Alice (Admin), Bob (Mod), and Charlie (User).")
    else:
        log_fail(f"Reset failed: {reset_resp.text}")
        sys.exit(1)

    # 2. Login Contexts
    log_info("2. Authenticating user contexts and retrieving JWT tokens...")
    
    # Alice (Admin)
    alice_login = client.post("/api/auth/login", json={"username": "alice", "password": "password123"})
    if alice_login.status_code != 200:
        log_fail("Failed to authenticate Alice (Admin)")
        sys.exit(1)
    alice_token = alice_login.json()["access_token"]
    alice_id = alice_login.json()["user"]["id"]
    log_pass("Alice (Admin) context authenticated successfully.")

    # Bob (Moderator)
    bob_login = client.post("/api/auth/login", json={"username": "bob", "password": "password123"})
    if bob_login.status_code != 200:
        log_fail("Failed to authenticate Bob (Moderator)")
        sys.exit(1)
    bob_token = bob_login.json()["access_token"]
    bob_id = bob_login.json()["user"]["id"]
    log_pass("Bob (Moderator) context authenticated successfully.")

    # Charlie (User)
    charlie_login = client.post("/api/auth/login", json={"username": "charlie", "password": "password123"})
    if charlie_login.status_code != 200:
        log_fail("Failed to authenticate Charlie (User)")
        sys.exit(1)
    charlie_token = charlie_login.json()["access_token"]
    charlie_id = charlie_login.json()["user"]["id"]
    log_pass("Charlie (User) context authenticated successfully.")

    # 3. Assert Standard Access Succeeds for All
    log_info("3. Asserting standard profile access succeeds for all active users...")
    
    # Alice reads own profile
    resp = client.get("/api/profile/me", headers={"Authorization": f"Bearer {alice_token}"})
    assert resp.status_code == 200, "Alice could not read own profile"
    # Bob reads own profile
    resp = client.get("/api/profile/me", headers={"Authorization": f"Bearer {bob_token}"})
    assert resp.status_code == 200, "Bob could not read own profile"
    # Charlie reads own profile
    resp = client.get("/api/profile/me", headers={"Authorization": f"Bearer {charlie_token}"})
    assert resp.status_code == 200, "Charlie could not read own profile"
    
    log_pass("All users successfully read their own profile details (user:read).")

    # 4. Assert Privilege Escalation is Blocked (403 Forbidden)
    log_info("4. Asserting standard users cannot perform privileged admin actions...")
    
    # Charlie tries to delete Bob's account (Gated by permission: user:delete)
    resp = client.delete(f"/api/admin/user/{bob_id}", headers={"Authorization": f"Bearer {charlie_token}"})
    if resp.status_code == 403:
        log_pass("Correctly blocked Charlie (User) from deleting Bob's account with 403 Forbidden.")
    else:
        log_fail(f"VULNERABILITY: Charlie deleted user with status {resp.status_code} instead of 403.")
        sys.exit(1)

    # Charlie tries to reassign roles to himself (Gated by role: Admin)
    resp = client.put(f"/api/admin/user/{charlie_id}/roles", json={"roles": ["Admin", "User"]}, headers={"Authorization": f"Bearer {charlie_token}"})
    if resp.status_code == 403:
        log_pass("Correctly blocked Charlie (User) from self-provisioning Admin privileges with 403 Forbidden.")
    else:
        log_fail(f"VULNERABILITY: Charlie escalated roles with status {resp.status_code} instead of 403.")
        sys.exit(1)

    # Bob (Moderator) tries to delete Charlie's account (Requires user:delete, which Bob lacks)
    resp = client.delete(f"/api/admin/user/{charlie_id}", headers={"Authorization": f"Bearer {bob_token}"})
    if resp.status_code == 403:
        log_pass("Correctly blocked Bob (Moderator) from deleting Charlie's account with 403 Forbidden.")
    else:
        log_fail(f"VULNERABILITY: Bob deleted user with status {resp.status_code} instead of 403.")
        sys.exit(1)

    # 5. Assert Administrative Actions are Executable only by Alice
    log_info("5. Asserting administrative actions execute successfully when run by Alice...")

    # Alice suspends/bans Charlie (Moderator action available to Admin/Moderator and user:write)
    resp = client.post(f"/api/admin/ban/{charlie_id}", headers={"Authorization": f"Bearer {alice_token}"})
    if resp.status_code == 200:
        log_pass("Alice (Admin) successfully suspended Charlie's account.")
    else:
        log_fail(f"Alice failed to suspend user: {resp.text}")
        sys.exit(1)

    # Alice deletes Bob (Requires user:delete)
    resp = client.delete(f"/api/admin/user/{bob_id}", headers={"Authorization": f"Bearer {alice_token}"})
    if resp.status_code == 200:
        log_pass("Alice (Admin) successfully deleted Bob's account.")
    else:
        log_fail(f"Alice failed to delete user: {resp.text}")
        sys.exit(1)

    # Confirm Bob's deletion in state
    state_resp = client.get("/api/debug/state").json()["state"]
    user_ids = [u["id"] for u in state_resp["users"]]
    if bob_id not in user_ids:
        log_pass("Verified Bob has been wiped from SQLite 'users' table.")
    else:
        log_fail("Bob remains in the SQLite table after successful deletion response.")
        sys.exit(1)

    # 6. Test New User Registration and Default Role Allocation
    log_info("6. Testing new user registration and role checks...")
    new_user_payload = {
        "username": "david",
        "password": "password123",
        "email": "david@auth2prod.org",
        "display_name": "David Standard"
    }
    reg_resp = client.post("/api/auth/register", json=new_user_payload)
    if reg_resp.status_code == 200:
        log_pass("Successfully registered new user 'david'.")
    else:
        log_fail(f"Failed to register 'david': {reg_resp.text}")
        sys.exit(1)

    # Log in as David
    david_login = client.post("/api/auth/login", json={"username": "david", "password": "password123"})
    david_token = david_login.json()["access_token"]
    david_id = david_login.json()["user"]["id"]
    
    # Try modifying David's profile details (Standard action requiring user:write)
    update_payload = {
        "display_name": "David Active",
        "email": "david_new@auth2prod.org",
        "bio": "Developer account."
    }
    update_resp = client.put("/api/profile/me", json=update_payload, headers={"Authorization": f"Bearer {david_token}"})
    if update_resp.status_code == 200:
        log_pass("David (User) successfully updated his profile (user:write).")
    else:
        log_fail(f"David failed to update his profile: {update_resp.text}")
        sys.exit(1)
        
    print(f"\n{GREEN}==============================================={RESET}")
    print(f"{GREEN}ALL INTEGRATION TESTS PASSED SUCCESSFULLY!{RESET}")
    print(f"{GREEN}==============================================={RESET}")

if __name__ == "__main__":
    run_tests()
