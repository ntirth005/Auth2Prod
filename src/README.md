# Raw Authentication Protocol Playground (src/ Prototype)

This folder contains a sandbox prototype constructed during the initial stages of the repository. It serves as a visual playground and comparative analysis tool demonstrating standard web authentication protocols, request header mechanics, and raw credential transmission behaviors.

---

## 1. Directory Structure & File Guide

### App Core Layers
* **`main.py`**: The application bootstrapper. It sets up database engines, mounts the user interface assets, and registers the individual raw protocol routers (`basic`, `digest`, `api_key`, `session`).
* **`database.py`**: Establishes SQLite engine configurations and connection thread factories.
* **`models.py`**: Outlines ORM user models and basic session databases.
* **`security.py`**: Enforces password salting, verification, and basic encryption.
* **`session_store.py`**: Manages stateful cookie resolution, session insertions, and expirations.

### Protocol Routers (`auth/`)
* **`auth/basic.py`**: Implements HTTP Basic Authentication. Illustrates how usernames and passwords are base64-encoded and sent in the plain `Authorization: Basic <hash>` header.
* **`auth/digest.py`**: Implements HTTP Digest Authentication. Validates incoming challenge-response md5 signatures inside the `Authorization: Digest ...` header to avoid plain credentials transmission.
* **`auth/api_key.py`**: Implements simple API key validation via headers (`X-API-Key`) or query parameters.
* **`auth/session.py`**: Implements standard stateful cookie sessions.
* **`auth/README.md`**: Provides a deep comparative study contrasting HTTP Basic, Digest, API Key, and Cookie authentication.

### Frontend UI Sandbox (`static/`)
* **`static/index.html`**: A dual-pane dashboard demonstrating the layout panel to request resources under different schemes.
* **`static/style.css`**: Styling rules for the visual dashboard panels.
* **`static/app.js`**: Triggers network requests for each scheme, logs response headers, and prints the raw data passing through the console.

---

## 2. Core Differences (Prototype vs. Production Module)

While the `session_profile_app/` module is structured for **production-grade enterprise use**, this `src/` prototype is specifically designed to be **transparent and exploratory**:
* It explicitly exposes raw headers and passwords in response log frames to help developers analyze transmission behaviors.
* It sets up simple HTTP handlers side-by-side to ease comparing network sniff characteristics of different protocols.
