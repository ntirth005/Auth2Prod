# Role-Based Access Control (RBAC) Profile App

A production-grade, modular, and interactive **Role-Based Access Control (RBAC)** profile management sandbox. This application demonstrates the mechanics of granular permission structures, relational many-to-many associations, authorization checker guards, and request-scoped SQL query diagnostics.

---

## 1. Directory Structure

```text
rbac_profile_app/
├── core/
│   ├── config.py         # Global settings (secrets, expiry, connection paths)
│   ├── database.py       # Engine setup and ContextVar-based SQL event interceptor
│   ├── logging.py        # Structured JSON and plaintext formatters
│   └── security.py       # Direct bcrypt encryption and role/permission Checker guards
├── models/
│   └── models.py         # SQLAlchemy ORM models (User, Role, Permission)
├── schemas/
│   └── schemas.py        # Pydantic validation schemas
├── api/
│   ├── auth.py           # Register and login endpoints
│   ├── profile.py        # Gated profile retrieval and updates
│   ├── admin.py          # Admin/Moderator capabilities (delete, provision, ban)
│   ├── debug.py          # Database state inspector and reset flushes
│   └── utils.py          # Debug metadata aggregator
├── static/
│   ├── index.html        # Split-pane visual control dashboard
│   ├── style.css         # Visual styles and color-coded error formats
│   └── app.js            # Tab swappers, dynamic tables, and log formatters
├── main.py               # Bootstrapper that registers middlewares and routes
└── verify_rbac_app.py    # Integration test suite validating security boundaries
```

---

## 2. Many-to-Many Database Schema

The database model implements a classic relational Many-to-Many (M2M) RBAC configuration using SQLAlchemy:

```mermaid
erDiagram
    USERS ||--o{ USER_ROLES : has
    ROLES ||--o{ USER_ROLES : maps
    ROLES ||--o{ ROLE_PERMISSIONS : binds
    PERMISSIONS ||--o{ ROLE_PERMISSIONS : linked

    USERS {
        int id PK
        string username UNIQUE
        string hashed_password
        string email
        string display_name
        string avatar_url
        string bio
        datetime created_at
    }

    ROLES {
        int id PK
        string name UNIQUE
        string description
    }

    PERMISSIONS {
        int id PK
        string name UNIQUE
        string description
    }

    USER_ROLES {
        int user_id FK
        int role_id FK
    }

    ROLE_PERMISSIONS {
        int role_id FK
        int permission_id FK
    }
```

---

## 3. Backend Guard Dependencies

Secure endpoint access is handled programmatically via FastAPI dependencies:

* **Role Authorization (`RequireRole(["Admin"])`)**:
  Intercepts headers, decodes the user context, and asserts that the active user possesses a designated role name (e.g., `Admin`).
* **Permission Authorization (`RequirePermission("user:delete")`)**:
  Asserts that the user possesses a role linked to the required granular action permission (by tracing the user's active roles -> permissions mapping).

---

## 4. Setup & Running the Application

### Start the Application Server
Run the FastAPI development server from the repository root:
```bash
PYTHONPATH=. uv run uvicorn rbac_profile_app.main:app --reload --port 8000
```

### Access the Dashboard
Navigate your web browser to:
```text
http://127.0.0.1:8000/static/index.html
```

### Run the Verification Script
To assert authorization boundaries automatically, execute the integration script in a separate terminal:
```bash
PYTHONPATH=. uv run rbac_profile_app/verify_rbac_app.py
```
This script runs a full lifecycle test, asserting:
* Successful reads and updates for standard profiles.
* Privilege blockages (**403 Forbidden**) when user `Charlie` tries to delete users or modify roles.
* Administrative task execution when queried by `Alice` (Admin).
