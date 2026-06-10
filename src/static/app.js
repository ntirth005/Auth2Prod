// State variables
let accessToken = null;
let idToken = null;

// Helper to decode a JWT payload client-side for diagnostic display
function decodeJwt(token) {
    try {
        const parts = token.split('.');
        const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        return { header, payload };
    } catch (e) {
        return null;
    }
}

// DOM Elements
const cardStep1 = document.getElementById("card-step1");
const cardStep2 = document.getElementById("card-step2");
const cardStep3 = document.getElementById("card-step3");
const cardStep4 = document.getElementById("card-step4");
const cardStep5 = document.getElementById("card-step5");

const btnInitiateAuth = document.getElementById("btn-initiate-auth");
const btnConsentApprove = document.getElementById("btn-consent-approve");
const btnConsentDeny = document.getElementById("btn-consent-deny");
const btnExchangeCode = document.getElementById("btn-exchange-code");
const btnQueryUserinfo = document.getElementById("btn-query-userinfo");
const btnQueryResource = document.getElementById("btn-query-resource");
const btnResetDb = document.getElementById("reset-db-btn");
const btnClearLogs = document.getElementById("clear-logs-btn");
const btnRefreshState = document.getElementById("refresh-state-btn");

const consentBox = document.getElementById("consent-box");
const consentClientName = document.getElementById("consent-client-name");
const consentScopesList = document.getElementById("consent-scopes-list");

const capturedCode = document.getElementById("captured-code");
const capturedState = document.getElementById("captured-state");

const codeStatusBadge = document.getElementById("code-status-badge");
const jwtStatusBadge = document.getElementById("jwt-status-badge");
const jwtRawVal = document.getElementById("jwt-raw-val");
const idRawVal = document.getElementById("id-raw-val");
const jwtDecodedClaims = document.getElementById("jwt-decoded-claims");

const usersList = document.getElementById("users-list");
const clientsList = document.getElementById("clients-list");
const codesList = document.getElementById("codes-list");
const tokensList = document.getElementById("tokens-list");

const networkTimeline = document.getElementById("network-timeline");

// Initialize on page load
document.addEventListener("DOMContentLoaded", () => {
    setupEventListeners();
    checkUrlParameters();
    pollState();
    setInterval(pollState, 3000);
});

function setupEventListeners() {
    btnInitiateAuth.addEventListener("click", handleInitiateAuth);
    btnConsentApprove.addEventListener("click", handleConsentApprove);
    btnConsentDeny.addEventListener("click", handleConsentDeny);
    btnExchangeCode.addEventListener("click", handleExchangeCode);
    btnQueryUserinfo.addEventListener("click", handleQueryUserInfo);
    btnQueryResource.addEventListener("click", handleQueryResource);
    btnResetDb.addEventListener("click", handleResetSystem);
    btnRefreshState.addEventListener("click", pollState);
    btnClearLogs.addEventListener("click", () => {
        networkTimeline.innerHTML = '<div class="empty-network">No interactions captured yet. Perform an action on the client workspace.</div>';
    });

    // Registration Tab Switching
    const tabRegUser = document.getElementById("tab-reg-user");
    const tabRegClient = document.getElementById("tab-reg-client");
    const regUserForm = document.getElementById("reg-user-form");
    const regClientForm = document.getElementById("reg-client-form");

    tabRegUser.addEventListener("click", () => {
        tabRegUser.style.background = "rgba(59, 130, 246, 0.15)";
        tabRegUser.style.borderColor = "rgba(59, 130, 246, 0.3)";
        tabRegClient.style.background = "transparent";
        tabRegClient.style.borderColor = "transparent";
        regUserForm.classList.remove("hidden");
        regClientForm.classList.add("hidden");
    });

    tabRegClient.addEventListener("click", () => {
        tabRegClient.style.background = "rgba(59, 130, 246, 0.15)";
        tabRegClient.style.borderColor = "rgba(59, 130, 246, 0.3)";
        tabRegUser.style.background = "transparent";
        tabRegUser.style.borderColor = "transparent";
        regClientForm.classList.remove("hidden");
        regUserForm.classList.add("hidden");
    });

    // Form Submissions
    regUserForm.addEventListener("submit", handleRegisterUser);
    regClientForm.addEventListener("submit", handleRegisterClient);
}

async function handleRegisterUser(e) {
    e.preventDefault();
    const username = document.getElementById("reg-username").value;
    const password = document.getElementById("reg-password").value;

    const payload = { username, password };

    try {
        const response = await fetch("/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await response.json();

        addLogCard({
            method: "POST",
            url: "/register",
            requestHeaders: { "Content-Type": "application/json" },
            requestBody: { ...payload, password: "••••••••" },
            responseStatus: response.status,
            responseHeaders: Object.fromEntries(response.headers.entries()),
            responseBody: data,
            dbQueries: [
                `SELECT * FROM users WHERE username = '${username}'`,
                `INSERT INTO users (username, hashed_password, email, display_name, bio) VALUES ('${username}', 'pbkdf2_sha256$...', '${username}@example.com', '${username.charAt(0).toUpperCase() + username.slice(1)}', 'Playground user account')`
            ],
            explanation: "Client browser registers a new Sandbox User account. User credentials are submitted, checked for conflicts in the database, password hashed using PBKDF2-SHA256, and stored in the 'users' table."
        });

        if (response.ok) {
            alert(`User '${username}' created successfully!`);
            document.getElementById("reg-username").value = "";
            document.getElementById("reg-password").value = "";
            pollState();
        } else {
            alert("Registration failed: " + (data.detail || "Unknown error"));
        }
    } catch (error) {
        console.error("Register user error:", error);
    }
}

async function handleRegisterClient(e) {
    e.preventDefault();
    const client_id = document.getElementById("reg-client-id").value;
    const client_name = document.getElementById("reg-client-name").value;
    const client_secret = document.getElementById("reg-client-secret").value;
    const redirect_uri = document.getElementById("reg-client-redirect").value;

    const payload = { client_id, client_name, client_secret, redirect_uri };

    try {
        const response = await fetch("/api/oauth/register_client", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await response.json();

        addLogCard({
            method: "POST",
            url: "/api/oauth/register_client",
            requestHeaders: { "Content-Type": "application/json" },
            requestBody: { ...payload, client_secret: "••••••••" },
            responseStatus: response.status,
            responseHeaders: Object.fromEntries(response.headers.entries()),
            responseBody: data,
            dbQueries: data.debug?.db_actions || [],
            explanation: "Registers a new OAuth Client Application in the database. The client's unique client_id, client_secret, client_name, and redirect_uri are stored in the 'oauth_clients' table."
        });

        if (response.ok) {
            alert(`OAuth Client '${client_name}' registered successfully!`);
            document.getElementById("reg-client-id").value = "";
            document.getElementById("reg-client-name").value = "";
            document.getElementById("reg-client-secret").value = "";
            pollState();
        } else {
            alert("Client registration failed: " + (data.detail || "Unknown error"));
        }
    } catch (error) {
        console.error("Register client error:", error);
    }
}

// Check if code was returned in query params (simulating redirects)
function checkUrlParameters() {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");

    if (code) {
        // Recover state from sessionStorage to continue flow seamlessly
        const savedClientId = sessionStorage.getItem("oauth_client_id");
        if (savedClientId) {
            document.getElementById("oauth-client-id").value = savedClientId;
        }

        codeStatusBadge.textContent = "CODE ACTIVE";
        codeStatusBadge.className = "hud-status status-green";

        transitionToStep3(code, state);
    }
}

// Poll SQLite DB state
async function pollState() {
    try {
        const response = await fetch("/api/debug/state");
        if (!response.ok) return;
        const data = await response.json();

        // Render Users
        if (data.users.length === 0) {
            usersList.innerHTML = '<div class="empty-state">No database records</div>';
        } else {
            usersList.innerHTML = data.users.map(u => `
                <div class="state-item">
                    <div class="state-item-header">
                        <span>ID: ${u.id} - ${u.username}</span>
                    </div>
                    <div class="state-item-detail">Email: ${u.email || 'None'}</div>
                </div>
            `).join("");
        }

        // Render Clients
        if (data.clients.length === 0) {
            clientsList.innerHTML = '<div class="empty-state">No clients registered</div>';
        } else {
            clientsList.innerHTML = data.clients.map(c => `
                <div class="state-item">
                    <div class="state-item-header">
                        <span>${c.client_name}</span>
                    </div>
                    <div class="state-item-detail">ID: ${c.client_id}</div>
                    <div class="state-item-detail">Redirect: ${c.redirect_uri}</div>
                </div>
            `).join("");
        }

        // Render Auth Codes
        if (data.auth_codes.length === 0) {
            codesList.innerHTML = '<div class="empty-state">No authorization codes issued</div>';
        } else {
            codesList.innerHTML = data.auth_codes.map(cd => `
                <div class="state-item">
                    <div class="state-item-header">
                        <span>Code: ${cd.code_prefix}</span>
                        <span class="hud-status ${cd.is_used ? 'status-red' : 'status-green'}">${cd.is_used ? 'Used' : 'Active'}</span>
                    </div>
                    <div class="state-item-detail">User: ${cd.username} | Client: ${cd.client_id}</div>
                </div>
            `).join("");
        }

        // Render Access Tokens
        if (data.access_tokens.length === 0) {
            tokensList.innerHTML = '<div class="empty-state">No access tokens active</div>';
        } else {
            tokensList.innerHTML = data.access_tokens.map(t => `
                <div class="state-item">
                    <div class="state-item-header">
                        <span>Token: ${t.token_prefix}</span>
                        <span class="hud-status ${t.is_revoked ? 'status-red' : 'status-green'}">${t.is_revoked ? 'Revoked' : 'Active'}</span>
                    </div>
                    <div class="state-item-detail">User: ${t.username} | Client: ${t.client_id}</div>
                </div>
            `).join("");
        }

    } catch (err) {
        console.error("Error polling database state:", err);
    }
}

// Step 1: Initiate Auth Flow
async function handleInitiateAuth() {
    const clientId = document.getElementById("oauth-client-id").value;
    const redirectUri = document.getElementById("oauth-redirect-uri").value;
    const scope = document.getElementById("oauth-scope").value;
    const state = document.getElementById("oauth-state").value;

    const queryUrl = `/api/oauth/authorize?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${encodeURIComponent(scope)}&state=${encodeURIComponent(state)}`;

    try {
        const response = await fetch(queryUrl);
        const data = await response.json();

        // Log request in 3-column layout
        addLogCard({
            method: "GET",
            url: "/api/oauth/authorize",
            requestHeaders: { "Accept": "application/json" },
            requestBody: { client_id: clientId, redirect_uri: redirectUri, scope, state },
            responseStatus: response.status,
            responseHeaders: Object.fromEntries(response.headers.entries()),
            responseBody: data,
            dbQueries: data.debug?.db_actions || [],
            explanation: `Client browser initiates request to Authorization Server (/oauth/authorize). Server validates client registration ('${clientId}') and checks redirect_uri. Returns scopes for user approval.`
        });

        if (!response.ok) {
            alert("Authorization error: " + (data.detail || "Unknown error"));
            return;
        }

        // Display consent UI
        consentClientName.textContent = data.client_name;
        consentScopesList.innerHTML = data.scope.split(" ").map(s => `<li>✔️ ${s}</li>`).join("");
        
        cardStep1.classList.remove("active");
        cardStep1.classList.add("success");
        
        cardStep2.classList.remove("disabled");
        cardStep2.classList.add("active");
        consentBox.classList.remove("hidden");

        // Save flow metadata
        sessionStorage.setItem("oauth_client_id", clientId);
        sessionStorage.setItem("oauth_redirect_uri", redirectUri);
        sessionStorage.setItem("oauth_state", state);
        sessionStorage.setItem("oauth_scope", scope);

        pollState();

    } catch (error) {
        console.error("Initiation error:", error);
    }
}

// Step 2: Consent approval
async function handleConsentApprove() {
    await submitConsent("approve");
}

async function handleConsentDeny() {
    await submitConsent("deny");
}

async function submitConsent(action) {
    const clientId = sessionStorage.getItem("oauth_client_id");
    const redirectUri = sessionStorage.getItem("oauth_redirect_uri");
    const scope = sessionStorage.getItem("oauth_scope");
    const state = sessionStorage.getItem("oauth_state");
    const username = document.getElementById("consent-username").value || "alice";
    const password = document.getElementById("consent-password").value;

    if (action === "approve" && !password) {
        alert("Please enter your password to authorize consent.");
        return;
    }

    const payload = {
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: scope,
        state: state,
        username: username,
        password: password,
        action: action
    };

    try {
        const response = await fetch("/api/oauth/consent", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await response.json();

        addLogCard({
            method: "POST",
            url: "/api/oauth/consent",
            requestHeaders: { "Content-Type": "application/json" },
            requestBody: { ...payload, password: "••••••••" },
            responseStatus: response.status,
            responseHeaders: Object.fromEntries(response.headers.entries()),
            responseBody: data,
            dbQueries: data.debug?.db_actions || [],
            explanation: `Resource Owner submits credentials and approval. Server verifies user credentials against database, generates a short-lived authorization code, writes it to 'oauth_auth_codes' table, and responds with a 302 Redirect URL.`
        });

        if (!response.ok) {
            alert("Consent authorization failed: " + (data.detail || "Unknown error"));
            return;
        }

        // Simulate redirection by modifying URL search params without reloading
        const redirectUrl = new URL(data.redirect_url);
        window.history.pushState({}, "", redirectUrl.pathname + redirectUrl.search);
        
        // Complete Step 2
        cardStep2.classList.remove("active");
        cardStep2.classList.add("success");
        consentBox.classList.add("hidden");

        // Transition to Step 3 using URL parameters
        checkUrlParameters();
        pollState();

    } catch (error) {
        console.error("Consent error:", error);
    }
}

function transitionToStep3(code, state) {
    capturedCode.textContent = code;
    capturedState.textContent = state;

    cardStep3.classList.remove("disabled");
    cardStep3.classList.add("success");

    cardStep4.classList.remove("disabled");
    cardStep4.classList.add("active");
}

// Step 4: Exchange code for tokens
async function handleExchangeCode() {
    const code = capturedCode.textContent;
    const clientId = sessionStorage.getItem("oauth_client_id");
    const redirectUri = sessionStorage.getItem("oauth_redirect_uri");
    const clientSecret = document.getElementById("exchange-client-secret").value;

    const payload = {
        grant_type: "authorization_code",
        code: code,
        redirect_uri: redirectUri,
        client_id: clientId,
        client_secret: clientSecret
    };

    try {
        const response = await fetch("/api/oauth/token", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await response.json();

        addLogCard({
            method: "POST",
            url: "/api/oauth/token",
            requestHeaders: { "Content-Type": "application/json" },
            requestBody: { ...payload, client_secret: "••••••••" },
            responseStatus: response.status,
            responseHeaders: Object.fromEntries(response.headers.entries()),
            responseBody: data,
            dbQueries: data.debug?.db_actions || [],
            explanation: `Client backend exchanges authorization code for tokens. Authorization Server validates client credentials and matches the authorization code. Code is marked as used in DB. Signed Access JWT and OIDC ID JWT are returned.`
        });

        if (!response.ok) {
            alert("Token exchange failed: " + (data.detail || "Unknown error"));
            return;
        }

        // Save tokens
        accessToken = data.access_token;
        idToken = data.id_token;

        // Update Client HUD details
        jwtStatusBadge.textContent = "ACTIVE TOKEN";
        jwtStatusBadge.className = "hud-status status-green";
        jwtRawVal.textContent = accessToken.slice(0, 24) + "...";
        idRawVal.textContent = idToken.slice(0, 24) + "...";

        // Decode and inspect tokens
        const decodedId = decodeJwt(idToken);
        if (decodedId) {
            jwtDecodedClaims.textContent = JSON.stringify(decodedId.payload, null, 2);
        }

        // Complete Step 4
        cardStep4.classList.remove("active");
        cardStep4.classList.add("success");

        // Activate Step 5
        cardStep5.classList.remove("disabled");
        cardStep5.classList.add("active");

        pollState();

    } catch (error) {
        console.error("Token exchange error:", error);
    }
}

// Step 5: UserInfo
async function handleQueryUserInfo() {
    if (!accessToken) {
        alert("Access Token missing. Complete token exchange first.");
        return;
    }

    const queryUrl = "/api/oauth/userinfo";
    try {
        const response = await fetch(queryUrl, {
            headers: { "Authorization": `Bearer ${accessToken}` }
        });
        const data = await response.json();

        addLogCard({
            method: "GET",
            url: queryUrl,
            requestHeaders: { "Authorization": `Bearer ${accessToken.slice(0, 12)}...` },
            requestBody: null,
            responseStatus: response.status,
            responseHeaders: Object.fromEntries(response.headers.entries()),
            responseBody: data,
            dbQueries: data.debug?.db_actions || [],
            explanation: `Client queries UserInfo endpoint using stateless Bearer Access Token. Identity Provider decodes and verifies JWT signature without contacting database (unless fetching fresh profile data).`
        });

        if (!response.ok) {
            alert("UserInfo request failed: " + (data.detail || "Unknown error"));
            return;
        }

        cardStep5.classList.add("success");

    } catch (error) {
        console.error("UserInfo error:", error);
    }
}

// Step 5: Resource API
async function handleQueryResource() {
    if (!accessToken) {
        alert("Access Token missing. Complete token exchange first.");
        return;
    }

    const queryUrl = "/api/resource";
    try {
        const response = await fetch(queryUrl, {
            headers: { "Authorization": `Bearer ${accessToken}` }
        });
        const data = await response.json();

        addLogCard({
            method: "GET",
            url: queryUrl,
            requestHeaders: { "Authorization": `Bearer ${accessToken.slice(0, 12)}...` },
            requestBody: null,
            responseStatus: response.status,
            responseHeaders: Object.fromEntries(response.headers.entries()),
            responseBody: data,
            dbQueries: data.debug?.db_actions || [],
            explanation: `Client makes authorized request to Resource Server endpoint. Server verifies access token validity (stateless signature validation) and optionally checks DB token revocation, returning sensitive resources.`
        });

        if (!response.ok) {
            alert("Resource request failed: " + (data.detail || "Unknown error"));
            return;
        }

        cardStep5.classList.add("success");

    } catch (error) {
        console.error("Resource error:", error);
    }
}

// System Reset
async function handleResetSystem() {
    if (!confirm("Are you sure you want to reset all data and logs?")) return;

    try {
        const response = await fetch("/api/debug/reset", { method: "POST" });
        const data = await response.json();

        // Clear states
        accessToken = null;
        idToken = null;
        jwtStatusBadge.textContent = "NO TOKEN";
        jwtStatusBadge.className = "hud-status status-red";
        codeStatusBadge.textContent = "NO CODE";
        codeStatusBadge.className = "hud-status status-red";
        jwtRawVal.textContent = "None";
        idRawVal.textContent = "None";
        jwtDecodedClaims.textContent = "{}";
        capturedCode.textContent = "None";
        capturedState.textContent = "None";

        // Reset URL
        window.history.pushState({}, "", "/static/index.html");

        // Reset flow cards styling
        [cardStep1, cardStep2, cardStep3, cardStep4, cardStep5].forEach(c => {
            c.classList.remove("active", "success", "disabled");
        });
        cardStep1.classList.add("active");
        [cardStep2, cardStep3, cardStep4, cardStep5].forEach(c => c.classList.add("disabled"));

        // Clear logs
        networkTimeline.innerHTML = '<div class="empty-network">No transactions captured yet. Click "Initiate Authorization Flow" to begin.</div>';

        // Re-register seeded clients & users
        location.reload();

    } catch (error) {
        console.error("Reset error:", error);
    }
}

// Add traffic log card in the exact 3-column layout shown in screenshot
function addLogCard({ method, url, requestHeaders, requestBody, responseStatus, responseHeaders, responseBody, dbQueries, explanation }) {
    const emptyMsg = networkTimeline.querySelector(".empty-network");
    if (emptyMsg) emptyMsg.remove();

    const card = document.createElement("div");
    card.className = "log-card";

    let statusClass = "status-success";
    if (responseStatus >= 400) statusClass = "status-error";

    const formatObj = (obj) => {
        if (!obj) return "{}";
        return JSON.stringify(obj, null, 2);
    };

    let dbQueriesList = "No Database actions performed (Stateless)";
    if (dbQueries && dbQueries.length > 0) {
        dbQueriesList = dbQueries.map(q => `<span class="sql-statement">${q}</span>`).join("\n\n");
    }

    const timestamp = new Date().toLocaleTimeString();

    card.innerHTML = `
        <div class="log-title">
            <div class="log-meta">
                <span class="log-method">${method}</span>
                <span class="log-url">${url}</span>
            </div>
            <div>
                <span class="log-status ${statusClass}">${responseStatus}</span>
                <span class="log-time" style="margin-left: 0.5rem;">${timestamp}</span>
            </div>
        </div>
        <div class="log-grid">
            <div class="log-block">
                <h5>Outgoing HTTP Headers & Body</h5>
                <div class="log-headers-box"><strong>Headers:</strong>\n${formatObj(requestHeaders)}\n\n<strong>Body:</strong>\n${formatObj(requestBody)}</div>
            </div>
            <div class="log-block">
                <h5>DB Operations (SQLite)</h5>
                <div class="log-headers-box">${dbQueriesList}</div>
            </div>
            <div class="log-block">
                <h5>Incoming HTTP Response</h5>
                <div class="log-headers-box"><strong>Headers:</strong>\n${formatObj(responseHeaders)}\n\n<strong>Body:</strong>\n${formatObj(responseBody)}</div>
            </div>
        </div>
        <div class="log-explanation">
            <strong>Protocol Analysis:</strong> ${explanation}
        </div>
    `;

    // Prepend to top of timeline
    networkTimeline.insertBefore(card, networkTimeline.firstChild);
}
