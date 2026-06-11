# Role-Based Access Control (RBAC) System & Visual Guard Simulator

This repository contains a production-grade, interactive, and modular **Role-Based Access Control (RBAC)** profile management visualizer and guard simulator implemented inside the [rbac_profile_app](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app) directory.

The application demonstrates hierarchical roles, permission enforcement dependencies, SQLite database state inspection, and request-scoped SQL query logs capture in real-time.

---

## 1. Directory Structure

All components are located within the [rbac_profile_app/](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app) workspace directory:

* **`rbac_profile_app/core/`**:
  * [config.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/core/config.py): Configuration variables (secrets, SQLite DB file path, JWT token lifetime).
  * [database.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/core/database.py): SQLAlchemy engine setup and a request-scoped SQL listener that captures executed SQLite queries in real-time.
  * [security.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/core/security.py): Direct `bcrypt` password hashing, token encoding/decoding, and authorization dependencies (`RequireRole`, `RequirePermission`).
  * [logging.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/core/logging.py): Logging configurations producing JSON format logs (`rbac_app.log`) and simple text logs (`rbac_app_simple.log`).
* **`rbac_profile_app/models/`**:
  * [models.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/models/models.py): Declarative ORM schemas for `users`, `roles`, and `permissions` along with their many-to-many relationship association tables.
* **`rbac_profile_app/schemas/`**:
  * [schemas.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/schemas/schemas.py): Pydantic validation schemas.
* **`rbac_profile_app/api/`**:
  * [auth.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/api/auth.py): Gated endpoints for user registration, user logins, and token generation.
  * [profile.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/api/profile.py): Profile reads and edits.
  * [admin.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/api/admin.py): Role provisioning, account deletions, and suspensions/bans.
  * [debug.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/api/debug.py): Diagnostic table state inspects and database flushes.
  * [utils.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/api/utils.py): Request-scoped context compilers.
* **`rbac_profile_app/static/`**:
  * [index.html](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/static/index.html): Interactive visual console (split-pane layout).
  * [style.css](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/static/style.css): Dark theme CSS styling rules and log format styles.
  * [app.js](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/static/app.js): Visual control event listeners and state synchronization scripts.
* **[main.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/main.py)**: Bootstrapper registering middlewares and routers.
* **[verify_rbac_app.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/verify_rbac_app.py)**: Automated integration testing script asserting authorization boundaries.

---

## 2. Many-to-Many Relational Database Schema

The database models map a classic Many-to-Many (M2M) RBAC configuration:

```mermaid
erDiagram
    USERS ||--o{ USER_ROLES : links
    ROLES ||--o{ USER_ROLES : links
    ROLES ||--o{ ROLE_PERMISSIONS : link
    PERMISSIONS ||--o{ ROLE_PERMISSIONS : link

    USERS {
        int id PK
        string username UNIQUE
        string hashed_password
        string email
        string display_name
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

## 3. Backend Permission Enforcement (Guard Dependencies)

Access checks are executed using reusable FastAPI dependencies:

* **Role Authorization Check (`RequireRole(["Admin"])`)**:
  Inspects the active context and asserts that the user possesses a designated role name (e.g., `Admin`).
* **Permission Authorization Check (`RequirePermission("user:delete")`)**:
  Asserts that the user holds a role that is bound to the target granular action permission.

Failing check conditions automatically return a detailed `403 Forbidden` JSON response explaining which roles or permissions are missing.

---

## 4. Detailed Engineering Resolutions & Resolved Errors

During the design, development, and testing of this RBAC application, the following issues were encountered and resolved:

### 1. PyJWT Subject Claim Validation Type Constraints (RFC 7519)
* **Error / Symptom**: During profile retrieval requests, the server returned `401 Unauthorized`. Internal trace logs revealed a `jwt.exceptions.InvalidSubjectError: Subject must be a string` raised by `jwt.decode()`.
* **Root Cause**: The User's integer ID was serialized directly into the JWT `sub` (subject) claim. Under RFC 7519 guidelines, standard compliance checks in newer PyJWT versions mandate that the `sub` claim value MUST be a string containing a StringOrURI. Passing an raw integer triggers a validation failure.
* **Resolution**: Updated `create_access_token` inside [security.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/core/security.py) to explicitly cast the subject claim to a string:
  
  ```python
  # Before
  to_encode = data.copy()
  
  # After
  to_encode = data.copy()
  if "sub" in to_encode:
      to_encode["sub"] = str(to_encode["sub"])
  ```
  
  Correspondingly, the subject value is cast back to an integer during user context resolution in the `get_current_user` dependency:
  
  ```python
  # Safe extraction and conversion back to integer
  user_id = int(claims["sub"])
  user = db.query(User).filter(User.id == user_id).first()
  ```

### 2. Passlib Bcrypt Context Deprecation & Password Length Bug
* **Error / Symptom**: Creating database users failed with `ValueError: password cannot be longer than 72 bytes` during standard `pwd_context.hash` operations, crashing the server process. In addition, Python 3.12 raised deprecation warnings regarding passlib's internal bcrypt library loaders.
* **Root Cause**: Passlib's legacy `CryptContext` handler runs into compatibility issues on Python 3.12. When newer versions of the `bcrypt` binary library are installed, passlib struggles to inspect the package signature and falls back to a buggy wrapper context that throws type and length checking exceptions.
* **Resolution**: Bypassed passlib's `CryptContext` entirely. Implemented direct password hashing and verification using the python `bcrypt` package directly inside [security.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/core/security.py):
  
  ```python
  import bcrypt

  def hash_password(password: str) -> str:
      pwd_bytes = password.encode('utf-8')
      salt = bcrypt.gensalt()
      return bcrypt.hashpw(pwd_bytes, salt).decode('utf-8')

  def verify_password(plain_password: str, hashed_password: str) -> bool:
      try:
          return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
      except Exception:
          return False
  ```

### 3. Database Association Table Import Placement Error
* **Error / Symptom**: Server boot crashed with the traceback:
  ```text
  ImportError: cannot import name 'user_roles' from 'rbac_profile_app.core.database'
  ```
* **Root Cause**: The database model code was refactored so that association tables `user_roles` and `role_permissions` were declared within the ORM schema [models.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/models/models.py) instead of `database.py`. However, the debug router [debug.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/api/debug.py) was still attempting to import them from the core database connection module.
* **Resolution**: Corrected the import statements inside [debug.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/api/debug.py) to import the tables from the models namespace:
  
  ```python
  # Before
  from rbac_profile_app.core.database import get_db, user_roles, role_permissions

  # After
  from rbac_profile_app.core.database import get_db
  from rbac_profile_app.models.models import User, Role, Permission, user_roles, role_permissions
  ```

### 4. Reloader Port Binding Conflicts
* **Error / Symptom**: The server failed to run locally on port 8000, terminating with the traceback error:
  ```text
  ERROR: [Errno 98] Address already in use
  ```
* **Root Cause**: A prior testing or development server process did not terminate correctly, leaving a background Python thread actively listening on port 8000 and blocking new bindings.
* **Resolution**: Located the pid using `fuser` and killed the overlapping background server task to free up the port:
  ```bash
  fuser -k 8000/tcp
  ```

### 5. CDP Port Resolution Error in Browser Subagent
* **Error / Symptom**: The automated browser subagent crashed during visual user testing with the error:
  ```text
  failed to resolve CDP URLs: failed to parse CDP port
  ```
* **Root Cause**: The sandboxed execution environment lacked necessary system permissions to expose the Chrome DevTools Protocol (CDP) debugging interface.
* **Resolution**: Pivoted validation strategy from automated browser GUI execution to a local automated integration test script ([verify_rbac_app.py](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/verify_rbac_app.py)) that fully executes api authentication, database updates, and permission boundaries using standard HTTP clients.

### 6. SQLite Database Table Inspector Tab Visibility Bug
* **Error / Symptom**: Clicking on database inspector tabs (e.g. `roles`, `permissions`, `user_roles`, `role_perms`) loaded empty panels, and clicking back to the `users` tab left the users panel hidden as well.
* **Root Cause**: The layout template combined two display paradigms: hidden state toggles using a `.hidden` utility class, and active panels using an `.active` display class. On tab changes, the handler added `.hidden` to all panels. However, the users tab was not having its `.hidden` class removed, and non-user tabs did not receive `.active`, leaving them with a default `display: none` style from `.db-table-panel`.
* **Resolution**: Cleaned up the stylesheet [style.css](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/static/style.css) to rely solely on the `.hidden` class for layout visibilities. Reconfigured [app.js](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/static/app.js) to dynamically target the selected panel using `document.getElementById("db-view-" + tabId)` and call `classList.remove("hidden")` uniformly across all inspector tabs.

### 7. Three-Column Visual Interaction Log Column Compression & Scroll Limits
* **Error / Symptom**: When transactions logged long SQL statements or large JSON bodies, the columns in the Three-Column Log were too narrow and difficult to read. In addition, the scrollbar for the log was clipped on shorter screen heights.
* **Root Cause**: The columns in the log card grid used `1fr 1fr 1fr` which caused columns to compress on small screens. The parent `.server-panel` layout was set to `overflow: hidden;`, cutting off Card 3's timeline container and scrollbar when the combined elements exceeded the available screen space.
* **Resolution**: Modified [style.css](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/static/style.css) to set `overflow-y: auto` on `.server-panel` so it scrolls cleanly on smaller viewports. Configured the log card column grid with `repeat(3, minmax(240px, 1fr))` and set `overflow-x: auto` to prevent column squishing on narrow layouts. Finally, increased `.log-data-box`'s `max-height` to `160px` to display more payload content without excessive inner vertical scrolling.

### 8. Log Card Height Collapse (Squishing) and Small Scroll Grab Areas
* **Error / Symptom**: Individual log cards inside the interaction log collapsed to very small heights (showing only 1-2 lines), clipping content. Also, the scrollbar was almost invisible and too thin (6px) to click or grab easily, leading to a poor area of interaction.
* **Root Cause**: The log cards are children of a vertical flexbox container (`.network-timeline`). Since the inner `.log-data-box` blocks are configured with scrollbars, the flex layout engine compressed the cards in size when the total height exceeded the viewport. Additionally, the scrollbar style used a very low background opacity (`0.08`) and narrow width.
* **Resolution**: Added `flex-shrink: 0;` to `.log-card` in [style.css](file:///home/ntirth005/Documents/Auth2Prod/rbac_profile_app/static/style.css) to prevent the flex container from squishing the cards. Re-styled scrollbars to be `10px` wide and increased thumb opacity to `0.25` (hovering to `0.45`), providing a comfortable visual area of interaction.

---

## 5. Setup & Running the Application

### Start the Application Server
Run the FastAPI development server from the repository root:
```bash
PYTHONPATH=. uv run uvicorn rbac_profile_app.main:app --reload --port 8000
```

### Access the Dashboard
Open your web browser and navigate to:
```text
http://127.0.0.1:8000/static/index.html
```

### Run the Integration Verification Script
To assert authorization boundaries automatically, execute the verification script in a separate terminal:
```bash
PYTHONPATH=. uv run rbac_profile_app/verify_rbac_app.py
```
This script executes a full lifecycle assertion:
1. Resets the database state.
2. Authenticates Alice (Admin), Bob (Moderator), and Charlie (User).
3. Asserts profile reads succeed.
4. Asserts that Charlie cannot delete Bob's account or provision roles (expects `403 Forbidden`).
5. Asserts administrative functions are executable only by Alice.
6. Tests registration of new users and default role mappings.