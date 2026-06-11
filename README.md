# Auth2Prod

> Understanding Authentication & Authorization Systems Through Engineering, Implementation, Benchmarking, and Architectural Analysis.

---

## Motivation

While designing **RAG2Prod**, I realized that authentication and authorization are not implementation details—they are architectural decisions.

Modern systems rely on a combination of:

* Session-Based Authentication
* JWT Authentication
* Refresh Token Strategies
* OAuth 2.0 / OpenID Connect
* API Keys
* Role-Based Access Control (RBAC)

Most developers learn how to use these mechanisms.

Few understand:

* Why one architecture is chosen over another.
* How they scale.
* What security assumptions they make.
* What operational complexity they introduce.
* Where they fail.

This repository exists to close that gap.

The objective is not to build another login system.

The objective is to develop enough understanding to make informed architectural decisions when building production systems.

---

## The Question

Instead of asking:

> "How do I implement JWT?"

I want to answer:

> "When should JWT be used instead of Sessions?"

Instead of asking:

> "How do I add Google Login?"

I want to answer:

> "What architectural problem does OAuth solve?"

Instead of asking:

> "How do I protect an endpoint?"

I want to answer:

> "What authorization model best fits my system?"

The goal is to understand the trade-offs behind every decision.

---

## Project Objectives

### Technical Objectives

* Implement common authentication mechanisms.
* Implement common authorization mechanisms.
* Analyze request flows.
* Compare stateful and stateless architectures.
* Understand token lifecycle management.
* Study security vulnerabilities and mitigations.
* Evaluate scalability characteristics.
* Measure operational complexity.

### Engineering Objectives

* Build intuition for authentication design.
* Learn to justify architectural choices.
* Create a reusable decision framework.
* Understand production trade-offs.
* Avoid cargo-cult engineering.

---

## Systems To Explore

### 1. Session-Based Authentication

Topics

* Cookies
* Server-Side Sessions
* Session Stores
* Sticky Sessions
* Session Invalidation

Questions

* Why were sessions the industry standard?
* What breaks when systems scale horizontally?
* How do distributed systems manage session state?
* What are the attack vectors?

Evaluation

* Scalability
* Security
* Simplicity
* Operational Cost

---

### 2. JWT Authentication

Topics

* Access Tokens
* Claims
* Signature Verification
* Stateless Authentication

Questions

* Why did JWT become popular?
* What does statelessness actually provide?
* What security problems does JWT introduce?
* When should JWT not be used?

Evaluation

* Scalability
* Token Size
* Verification Cost
* Revocation Complexity

---

### 3. Refresh Token Architecture

Topics

* Access Token Rotation
* Refresh Token Rotation
* Token Revocation
* Session Continuity

Questions

* How do modern systems maintain long-lived sessions?
* How can token theft be mitigated?
* What happens when refresh tokens are compromised?

Evaluation

* Security
* User Experience
* Operational Complexity

---

### 4. OAuth 2.0

Topics

* Authorization Code Flow
* Identity Providers
* Third-Party Login
* Consent Management

Questions

* How does Sign In With Google work internally?
* What problems does OAuth solve?
* What problems does OAuth not solve?
* When is OAuth unnecessary?

Evaluation

* Security
* Complexity
* Integration Cost

---

### 5. API Key Authentication

Topics

* Machine-to-Machine Communication
* Service Authentication
* Key Rotation
* Key Management

Questions

* When should API Keys be preferred over JWT?
* How should keys be managed securely?
* What are the limitations?

Evaluation

* Simplicity
* Security
* Operational Overhead

---

## Authorization Systems

Authentication answers:

> Who are you?

Authorization answers:

> What are you allowed to do?

This repository treats them as separate concerns.

### RBAC

Topics

* Roles
* Permissions
* Access Policies

Example

```text
Admin
Researcher
Viewer
```

Questions

* How should permissions be modeled?
* How does RBAC scale?
* What are its limitations?

---

## Comparison Dimensions

Every implementation will be evaluated using the same framework.

### Security

* Replay Attacks
* Session Hijacking
* Token Theft
* CSRF
* XSS Exposure
* Privilege Escalation

### Scalability

* Horizontal Scaling
* Distributed Systems Compatibility
* Microservice Compatibility

### Performance

* Authentication Latency
* Verification Cost
* Memory Consumption
* Database Dependency

### Operations

* Deployment Complexity
* Rotation Strategy
* Revocation Strategy
* Monitoring Requirements

### Developer Experience

* Ease of Integration
* Maintainability
* Debugging Complexity

---

## Expected Deliverables

Each implementation should include:

* Architecture Diagram
* Authentication Flow
* Authorization Flow
* Threat Analysis
* Security Considerations
* Performance Observations
* Advantages
* Disadvantages
* Recommended Use Cases

---

## Success Criteria

At the conclusion of this project, I should be able to justify answers to questions such as:

* Why Sessions instead of JWT?
* Why JWT instead of Sessions?
* Why Refresh Tokens?
* When is OAuth necessary?
* When are API Keys sufficient?
* When should RBAC be used?
* What scales best?
* What is easiest to operate?
* What is most secure for a given context?

The objective is not to memorize technologies.

The objective is to develop engineering judgment.

---

## Relationship To RAG2Prod

This repository exists because security architecture decisions should not be based on trends.

The findings from Auth2Prod will directly influence the authentication and authorization architecture of RAG2Prod.

Target Outcome:

```text
Authentication:
JWT + Refresh Tokens

Authorization:
RBAC

External Identity:
OAuth2 (Future)

Service Authentication:
API Keys (Future)
```

The final decision may change.

That is the purpose of this repository.

The goal is to discover the correct architecture through implementation, experimentation, and analysis.

---

## Implementations Status & Branch Map

We have successfully engineered, implemented, and documented the core authentication protocols across dedicated Git branches. Below is the mapping of each implementation phase:

| Phase / Branch | Target Architecture | Key Components & Directory | Status |
| :--- | :--- | :--- | :--- |
| **`session`** | API Key & Classic Stateful Auth | HTTP Basic, HTTP Digest, Query/Header API Keys, Stateful SQLite Sessions | **Merged/Complete** |
| **`jwt`** | Stateless JWT & Rotation | HS256 Token Signatures, Access/Refresh Token Rotation (RTR), Revocation Families | **Merged/Complete** |
| **`oauth`** | Federated Identity (OAuth 2.0) | Interactive Handshake Sandbox, Real GitHub, Google, Microsoft, and Discord IDP login (`oauth_profile_app/`) | **Merged/Complete** |

---

## Architectural Analysis & Success Criteria

Through hands-on implementation and benchmarking, we have formulated the following architectural trade-offs to guide production decisions:

### 1. Why Sessions instead of JWT?
* **Instant Revocation**: If a user logs out, rotates their password, or their account is suspended, the server can instantly delete the session from the backend database (or memory store), terminating access immediately.
* **Minimal Bandwidth**: A session cookie carries a simple session identifier (e.g., a 32-character string), keeping HTTP headers small.
* **XSS Immunity**: Session cookies marked with `HttpOnly` cannot be read by browser-side JavaScript, rendering them immune to XSS token theft.

### 2. Why JWT instead of Sessions?
* **Stateless Verification**: The server verifies tokens mathematically using a secret key without querying a database on every request, reducing authentication latency.
* **Decoupled Scaling**: Eliminates the need for shared session stores (such as Redis) or sticky sessions across horizontal clusters.
* **Microservices-Native**: Multiple decentralized services can verify claims independently if they possess the token's signing key.

### 3. Why Refresh Tokens?
* **Security-Lifetime Trade-off**: Allows access tokens to be extremely short-lived (e.g., 5 minutes) to minimize the window of abuse if stolen, while long-lived refresh tokens (e.g., 30 days) maintain session continuity.
* **Refresh Token Rotation (RTR)**: Every time a refresh token is used, it is rotated. If a compromised/used refresh token is presented, the server revokes the entire token family to prevent replay attacks.

### 4. When is OAuth 2.0 necessary?
* **Delegated Access**: When a client application needs to authorize third-party integrations (e.g., fetching a user's Google Calendar) without access to their credentials.
* **Federated Identity**: Offloading identity management and password hashing to external secure Providers (e.g., "Sign In with Google/GitHub/Microsoft/Discord").

### 5. When are API Keys sufficient?
* **Machine-to-Machine (M2M)**: Server-to-server calls, CLI tools, or developer-facing APIs where user-interactive login is absent.
* **High-Performance Integrations**: Simple authorization checks with low signing overhead.

### 6. When should RBAC be used?
* **Role-Based Provisioning**: When permissions are groupable into structural roles (Admin, Editor, Viewer). Scale limit: becomes complex ("role explosion") in setups needing fine-grained attribute-based access (where ABAC is preferred).

### 7. Core Benchmarks Summary
* **What scales best?** **Stateless JWTs** scale best. No database checks are required to verify the authentication signature.
* **What is easiest to operate?** **Stateful Sessions** are easiest. Key rotation, client-side XSS mitigation, and token revocation logic are non-issues.
* **What is most secure?**
  - *Browsers*: **Session Cookies** (SameSite, HttpOnly, Secure) prevent XSS token theft.
  - *APIs/Mobile*: **JWT Access + Refresh Tokens** utilizing RTR and secure storage (Keychain/Keystore).