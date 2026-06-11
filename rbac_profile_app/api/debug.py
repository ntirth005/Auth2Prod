from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from rbac_profile_app.core.database import get_db
from rbac_profile_app.core.security import hash_password
from rbac_profile_app.models.models import User, Role, Permission, user_roles, role_permissions
from rbac_profile_app.api.utils import capture_debug_meta

router = APIRouter(prefix="/api/debug", tags=["debug"])

def seed_database(db: Session):
    """Utility function to clear database and seed initial permissions, roles, and test users."""
    # 1. Clear association rows first to avoid constraints issues
    db.execute(user_roles.delete())
    db.execute(role_permissions.delete())
    db.query(User).delete()
    db.query(Role).delete()
    db.query(Permission).delete()
    db.commit()

    # 2. Seed permissions
    p_read = Permission(name="user:read", description="Authorize reading profile details")
    p_write = Permission(name="user:write", description="Authorize updating profile details")
    p_delete = Permission(name="user:delete", description="Authorize deleting user profiles")
    p_reset = Permission(name="system:reset", description="Authorize system database resets")
    db.add_all([p_read, p_write, p_delete, p_reset])
    db.commit()

    # 3. Seed roles
    r_admin = Role(name="Admin", description="Administrative privileges")
    r_mod = Role(name="Moderator", description="Moderation privileges")
    r_user = Role(name="User", description="Standard user credentials")
    db.add_all([r_admin, r_mod, r_user])
    db.commit()

    # 4. Bind permissions to roles
    r_admin.permissions.extend([p_read, p_write, p_delete, p_reset])
    r_mod.permissions.extend([p_read, p_write])
    r_user.permissions.extend([p_read, p_write])  # user:write allows modifying own details
    db.commit()

    # 5. Seed default testing accounts
    # Alice (Admin)
    alice = User(
        username="alice",
        hashed_password=hash_password("password123"),
        email="alice@auth2prod.org",
        display_name="Alice (Admin)",
        bio="System Administrator."
    )
    alice.roles.append(r_admin)

    # Bob (Moderator)
    bob = User(
        username="bob",
        hashed_password=hash_password("password123"),
        email="bob@auth2prod.org",
        display_name="Bob (Moderator)",
        bio="Community Moderator."
    )
    bob.roles.append(r_mod)

    # Charlie (User)
    charlie = User(
        username="charlie",
        hashed_password=hash_password("password123"),
        email="charlie@auth2prod.org",
        display_name="Charlie (User)",
        bio="Regular user account."
    )
    charlie.roles.append(r_user)

    db.add_all([alice, bob, charlie])
    db.commit()

@router.get("/state")
async def get_state(request: Request, db: Session = Depends(get_db)):
    """Dumps all database entries in a structured format for the SQLite tables monitor."""
    users = db.query(User).all()
    roles = db.query(Role).all()
    perms = db.query(Permission).all()

    # Query association tables
    user_roles_links = db.execute(user_roles.select()).all()
    role_perms_links = db.execute(role_permissions.select()).all()

    state = {
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "display_name": u.display_name,
                "bio": u.bio,
                "roles": [r.name for r in u.roles]
            } for u in users
        ],
        "roles": [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "permissions": [p.name for p in r.permissions]
            } for r in roles
        ],
        "permissions": [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description
            } for p in perms
        ],
        "user_roles_associations": [
            {"user_id": link[0], "role_id": link[1]} for link in user_roles_links
        ],
        "role_permissions_associations": [
            {"role_id": link[0], "permission_id": link[1]} for link in role_perms_links
        ]
    }

    debug_meta = await capture_debug_meta(request)
    return {
        "state": state,
        "debug": debug_meta
    }

@router.post("/reset")
async def reset_database(request: Request, db: Session = Depends(get_db)):
    """Triggers database clearing and re-seeding."""
    seed_database(db)
    debug_meta = await capture_debug_meta(request)
    return {
        "message": "System database reset and successfully re-seeded default roles/users.",
        "debug": debug_meta
    }
