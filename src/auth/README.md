# Developer Guide: Authentication Failures & Evolution

This document outlines the failure modes of each authentication method we implemented and the solutions introduced to address them.

---

## 1. HTTP Basic Authentication

### ❌ How & Why it Fails
* **Cleartext Transmission**: Credentials are sent as Base64-encoded strings (`Authorization: Basic <blob>`). Anyone sniffing network traffic can instantly decode it.
* **No Built-in Logout**: Browsers cache the credentials for the lifetime of the session. You cannot programmatically log a user out (the browser will keep sending the header).
* **Credential Exposure**: The client must store the raw username and password and send it on **every single request**, increasing the attack surface.

### 🛡️ The Solution
* **HTTPS (TLS)**: Encrypts the entire HTTP request payload, making cleartext Base64 transmission secure in transit.
* **Cookie/Token Session Auth**: Allows the client to exchange credentials *once* for a temporary session ID or token, so the raw password is never stored or sent repeatedly.

---

## 2. HTTP Digest Authentication

### ❌ How & Why it Fails
* **Broken Cryptography**: Relies on MD5 hashing, which is cryptographically broken and vulnerable to fast offline brute-force attacks if database hashes are leaked.
* **Incompatibility with Modern Hashing**: The server must store either the plaintext password or the precomputed `HA1 = MD5(username:realm:password)` hash. This prevents the server from using modern, slow hashing algorithms like **bcrypt** or **Argon2id** for password storage.
* **No Confidentiality**: While it protects the password from being sniffed, the rest of the request body (sensitive data) is sent in plaintext (unless TLS is used).

### 🛡️ The Solution
* **HTTPS (TLS) + Standard Post-Login Tokens**: Once HTTPS became ubiquitous and computationally cheap, challenge-response handshakes became unnecessary. Sending passwords over TLS and returning a secure session token became the standard.

---

## 3. API Key Authentication

### ❌ How & Why it Fails
* **Long-Lived/Static**: Unlike sessions, API Keys rarely expire automatically. If leaked (e.g., hardcoded in source control or exposed in server logs), they remain valid indefinitely.
* **Plaintext Leaks**: Often passed in URLs (e.g., `/api?key=xyz`), exposing them to server logs, proxy logs, and browser histories.
* **Lack of Scope**: Basic API Keys often grant full account access rather than restricted, read-only permissions.

### 🛡️ The Solution
* **SHA-256 Hashing**: Storing keys hashed in the database (never in plaintext) so a DB breach does not expose active keys.
* **Secret Scanning**: Tools like Trufflehog or GitLeaks to detect keys in commit histories.
* **Short-lived Signatures / Scoped Tokens**: Exchanging a master key for short-lived, scoped access tokens (like OAuth tokens) or signing requests using HMAC (e.g., AWS Signature V4).

---

## 4. Session-Based Authentication

### ❌ How & Why it Fails
* **State Bottleneck / Horizontal Scaling**: The server must check the session store on every request. If stored in-memory (RAM), requests routed to a different server instance will fail (causing sudden logouts).
* **CSRF Vulnerability**: Browsers automatically attach cookies to requests targeting the domain. An attacker can trick a logged-in user's browser into sending a state-changing request (Cross-Site Request Forgery).
* **Database/Cache Dependency**: Centralizing session state in Redis or SQL adds latency and introduces a single point of failure.

### 🛡️ The Solution
* **Centralized Session Caches**: Storing sessions in shared Redis clusters to handle horizontal scaling.
* **SameSite Cookie Attribute**: Mitigates CSRF by preventing the browser from sending cookies on cross-site requests.
* **JSON Web Tokens (JWT)**: Cryptographically signed, stateless tokens that contain user claims, allowing the server to authenticate requests without performing database or cache lookups.
