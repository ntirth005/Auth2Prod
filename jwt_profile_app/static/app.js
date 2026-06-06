// State variables
let accessToken = null;
let currentUser = null;

// Helper to decode a JWT payload client-side for diagnostic display
function decodeJwt(token) {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(window.atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));

        return JSON.parse(jsonPayload);
    } catch (e) {
        return null;
    }
}

function formatError(detail) {
    if (!detail) return null;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) {
        return detail.map(e => {
            const field = e.loc ? e.loc.slice(1).join(".") : "";
            return `${field ? field + ": " : ""}${e.msg}`;
        }).join("\n");
    }
    if (typeof detail === "object") {
        return JSON.stringify(detail);
    }
    return String(detail);
}

// DOM Elements
const authContainer = document.getElementById("auth-container");
const profileContainer = document.getElementById("profile-container");

const loginForm = document.getElementById("login-form");
const registerForm = document.getElementById("register-form");
const profileUpdateForm = document.getElementById("profile-update-form");
const passwordChangeForm = document.getElementById("password-change-form");

const tabLoginBtn = document.getElementById("tab-login-btn");
const tabRegisterBtn = document.getElementById("tab-register-btn");

const greetName = document.getElementById("greet-name");
const greetUsername = document.getElementById("greet-username");

const profileDisplayName = document.getElementById("profile-display-name");
const profileEmail = document.getElementById("profile-email");
const profileBio = document.getElementById("profile-bio");

const jwtStatusBadge = document.getElementById("jwt-status-badge");
const jwtRawVal = document.getElementById("jwt-raw-val");
const jwtDecodedClaims = document.getElementById("jwt-decoded-claims");
const refreshStatusBadge = document.getElementById("refresh-status-badge");
const refreshRawVal = document.getElementById("refresh-raw-val");

const usersList = document.getElementById("users-list");
const sessionsList = document.getElementById("sessions-list");
const networkTimeline = document.getElementById("network-timeline");

const refreshStateBtn = document.getElementById("refresh-state-btn");
const resetDbBtn = document.getElementById("reset-db-btn");
const clearLogsBtn = document.getElementById("clear-logs-btn");
const logoutBtn = document.getElementById("logout-btn");
const refreshTokenBtn = document.getElementById("refresh-token-btn");

// Initial Setup
document.addEventListener("DOMContentLoaded", () => {
    // Attempt an initial silent refresh on startup (in case they have an active refresh cookie)
    silentRefreshOnStartup();
    pollState();
    setInterval(pollState, 2500);
});

// Event Listeners for Tab Switching
tabLoginBtn.addEventListener("click", () => {
    tabLoginBtn.classList.add("active");
    tabRegisterBtn.classList.remove("active");
    loginForm.classList.remove("hidden");
    registerForm.classList.add("hidden");
});

tabRegisterBtn.addEventListener("click", () => {
    tabRegisterBtn.classList.add("active");
    tabLoginBtn.classList.remove("active");
    registerForm.classList.remove("hidden");
    loginForm.classList.add("hidden");
});

// Event Listeners for Action Buttons
refreshStateBtn.addEventListener("click", pollState);
clearLogsBtn.addEventListener("click", () => {
    networkTimeline.innerHTML = '<div class="empty-network">No interactions captured yet. Perform an action on the client workspace.</div>';
});
resetDbBtn.addEventListener("click", resetDatabase);
logoutBtn.addEventListener("click", performLogout);
if (refreshTokenBtn) {
    refreshTokenBtn.addEventListener("click", performManualRotation);
}

// Form Submit Handlers
registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("reg-username").value;
    const display_name = document.getElementById("reg-display-name").value || null;
    const email = document.getElementById("reg-email").value || null;
    const bio = document.getElementById("reg-bio").value || null;
    const password = document.getElementById("reg-password").value;

    try {
        const response = await fetch("/api/register", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, display_name, email, bio, password })
        });
        const data = await response.json();
        
        if (response.ok) {
            logTransaction("POST /api/register", 200, data.debug, "Successful registration of new user profile.");
            alert(data.message);
            registerForm.reset();
            tabLoginBtn.click(); // switch back to login
        } else {
            alert(formatError(data.detail) || "Registration failed.");
        }
    } catch (err) {
        alert("Error connecting to server.");
    }
    pollState();
});

loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("login-username").value;
    const password = document.getElementById("login-password").value;

    try {
        const response = await fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();
        
        if (response.ok) {
            accessToken = data.access_token;
            currentUser = data.user;
            
            updateJWTHUD(accessToken);
            logTransaction(
                "POST /api/login", 
                200, 
                data.debug, 
                "User authenticated. Server returned stateless JWT access token in body, and set HttpOnly refresh token cookie."
            );
            
            showProfileUI(data.user);
            loginForm.reset();
        } else {
            alert(formatError(data.detail) || "Authentication failed.");
        }
    } catch (err) {
        alert("Error connecting to server.");
    }
    pollState();
});

// Authenticated Requests Wrapper (Interceptor Loop)
async function fetchAuthorized(url, options = {}) {
    if (!options.headers) {
        options.headers = {};
    }
    
    // Inject the stateless JWT Access Token into the Authorization Bearer header
    if (accessToken) {
        options.headers["Authorization"] = `Bearer ${accessToken}`;
    }
    
    try {
        let response = await fetch(url, options);
        let data = await response.json();
        
        // Interceptor: If access token is expired (returns 401 with "Token expired"), trigger auto-refresh
        if (response.status === 401 && data.detail === "Token expired") {
            logTransaction(
                `${options.method || 'GET'} ${url} (Failed)`, 
                401, 
                data.debug || {}, 
                "Stateless JWT Access Token has expired! Attempting automatic background refresh using HttpOnly Refresh Cookie..."
            );
            
            const refreshed = await performSilentRefresh();
            if (refreshed) {
                // Retry the request with the new access token
                options.headers["Authorization"] = `Bearer ${accessToken}`;
                response = await fetch(url, options);
                data = await response.json();
            } else {
                // Refresh failed or revoked, kick to login
                throw new Error("Refresh token expired or revoked. Please login again.");
            }
        }
        
        return { response, data };
    } catch (error) {
        console.error(error);
        performLogoutCleanup();
        alert(error.message || "Session expired. Please log in again.");
        throw error;
    }
}

profileUpdateForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const display_name = profileDisplayName.value || null;
    const email = profileEmail.value || null;
    const bio = profileBio.value || null;

    try {
        const { response, data } = await fetchAuthorized("/api/profile", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ display_name, email, bio })
        });
        
        if (response.ok) {
            logTransaction("PUT /api/profile", 200, data.debug, "Stateless JWT signature validated. Bio updated in database.");
            alert(data.message);
            showProfileUI(data.user);
        } else {
            alert(formatError(data.detail) || "Update failed.");
        }
    } catch (err) {
        // Handled by interceptor
    }
    pollState();
});

passwordChangeForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const current_password = document.getElementById("pwd-current").value;
    const new_password = document.getElementById("pwd-new").value;

    try {
        const { response, data } = await fetchAuthorized("/api/change-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ current_password, new_password })
        });
        
        if (response.ok) {
            logTransaction("POST /api/change-password", 200, data.debug, "Current password verified. Updated password hash and marked all user's refresh tokens as revoked in DB.");
            alert(data.message);
            passwordChangeForm.reset();
        } else {
            alert(formatError(data.detail) || "Password change failed.");
        }
    } catch (err) {
        // Handled by interceptor
    }
    pollState();
});

// Helper Functions
async function silentRefreshOnStartup() {
    try {
        const success = await performSilentRefresh(true);
        if (success) {
            // Get user profile once refreshed
            const { response, data } = await fetchAuthorized("/api/profile");
            if (response.ok) {
                currentUser = data.user;
                showProfileUI(data.user);
            }
        }
    } catch (e) {}
}

async function performSilentRefresh(isStartup = false) {
    try {
        const response = await fetch("/api/refresh", { method: "POST" });
        const data = await response.json();
        
        if (response.ok) {
            accessToken = data.access_token;
            updateJWTHUD(accessToken);
            logTransaction(
                "POST /api/refresh", 
                200, 
                data.debug, 
                isStartup ? "Silent login successful. Rotated HttpOnly refresh token and generated new access token." : "Rotated HttpOnly refresh token and generated new access token."
            );
            return true;
        } else {
            if (!isStartup) {
                logTransaction("POST /api/refresh", 401, data.debug || {}, "Failed to refresh token: Refresh Token expired or revoked.");
            }
            return false;
        }
    } catch (e) {
        return false;
    }
}

async function performManualRotation() {
    const rotated = await performSilentRefresh();
    if (rotated) {
        alert("Tokens rotated successfully! Look at the SQL actions list to see current refresh token revoked and new refresh token inserted.");
    } else {
        alert("Failed to rotate token. Refresh token might be expired or invalid.");
        performLogoutCleanup();
    }
    pollState();
}

function showProfileUI(user) {
    authContainer.classList.add("hidden");
    profileContainer.classList.remove("hidden");
    greetName.textContent = `Hello, ${user.display_name || user.username}`;
    greetUsername.textContent = `@${user.username}`;
    
    profileDisplayName.value = user.display_name || "";
    profileEmail.value = user.email || "";
    profileBio.value = user.bio || "";
}

function showLoginUI() {
    authContainer.classList.remove("hidden");
    profileContainer.classList.add("hidden");
}

function performLogoutCleanup() {
    accessToken = null;
    currentUser = null;
    updateJWTHUD(null);
    updateCookieHUD(null);
    showLoginUI();
}

async function performLogout() {
    try {
        const response = await fetch("/api/logout", { method: "POST" });
        const data = await response.json();
        logTransaction("POST /api/logout", 200, data.debug, "Logged out. Cleared HttpOnly cookie and marked refresh token revoked in DB.");
    } catch (e) {}
    performLogoutCleanup();
    pollState();
}

async function resetDatabase() {
    if (!confirm("Are you sure you want to reset the database? This wipes all users and refresh tokens.")) return;
    try {
        const response = await fetch("/api/debug/reset", { method: "POST" });
        const data = await response.json();
        alert(data.message);
    } catch (e) {}
    performLogoutCleanup();
    pollState();
}

// Diagnostic polling
async function pollState() {
    try {
        const response = await fetch("/api/debug/state");
        const state = await response.json();
        
        // Update Cookie HUD based on reflected server state
        updateCookieHUD(state.client_refresh_cookie);
        
        // Render Users
        if (state.users.length === 0) {
            usersList.innerHTML = '<div class="empty-state">No database records</div>';
        } else {
            usersList.innerHTML = state.users.map(u => `
                <div class="state-item">
                    <div class="state-item-header">
                        <span>ID: ${u.id} - <strong>${u.username}</strong></span>
                    </div>
                    <div class="state-item-detail">
                        Display: ${u.display_name}<br>
                        Email: ${u.email || 'None'}<br>
                        Bio: ${u.bio || 'None'}
                    </div>
                </div>
            `).join('');
        }

        // Render Active Refresh Tokens
        if (state.refresh_tokens.length === 0) {
            sessionsList.innerHTML = '<div class="empty-state">No active sessions</div>';
        } else {
            sessionsList.innerHTML = state.refresh_tokens.map(t => {
                const statusClass = t.is_revoked ? "status-red" : "status-green";
                const statusLabel = t.is_revoked ? "Revoked" : "Active";
                return `
                    <div class="state-item">
                        <div class="state-item-header">
                            <span>ID: ${t.user_id} (@${t.username})</span>
                            <span class="hud-status ${statusClass}" style="padding: 2px 6px; font-size: 10px;">${statusLabel}</span>
                        </div>
                        <div class="state-item-detail">
                            JTI ID: ${t.jti}<br>
                            Expires: ${new Date(t.expires_at).toLocaleTimeString()}
                        </div>
                    </div>
                `;
            }).join('');
        }
    } catch (err) {}
}

function updateJWTHUD(token) {
    if (token) {
        jwtStatusBadge.textContent = "ACTIVE TOKEN";
        jwtStatusBadge.className = "hud-status status-green";
        jwtRawVal.textContent = token.substring(0, 20) + "..." + token.substring(token.length - 20);
        
        const decoded = decodeJwt(token);
        jwtDecodedClaims.textContent = JSON.stringify(decoded, null, 2);
    } else {
        jwtStatusBadge.textContent = "NO ACCESS TOKEN";
        jwtStatusBadge.className = "hud-status status-red";
        jwtRawVal.textContent = "None (Stored in JS memory)";
        jwtDecodedClaims.textContent = "{}";
    }
}

function updateCookieHUD(refreshCookie) {
    if (refreshCookie) {
        refreshStatusBadge.textContent = "ACTIVE COOKIE";
        refreshStatusBadge.className = "hud-status status-green";
        refreshRawVal.textContent = `jwt_refresh_token=${refreshCookie.substring(0, 12)}... (HttpOnly protected)`;
    } else {
        refreshStatusBadge.textContent = "NO COOKIE";
        refreshStatusBadge.className = "hud-status status-red";
        refreshRawVal.textContent = "None (No cookie detected by server)";
    }
}

// Log builder
function logTransaction(actionName, status, debugMeta, description) {
    // Remove empty-state message if present
    const emptyMsg = networkTimeline.querySelector(".empty-network");
    if (emptyMsg) {
        emptyMsg.remove();
    }

    const logCard = document.createElement("div");
    logCard.className = "log-card";
    
    const timestamp = new Date().toLocaleTimeString();
    const isSuccess = status >= 200 && status < 300;
    const statusClass = isSuccess ? "status-success" : "status-error";
    
    // Safety check for debugMeta (preventing crashes on errors/500/401 responses)
    if (!debugMeta) {
        debugMeta = {};
    }
    const request = debugMeta.request || { headers: {}, body: {} };
    const db_actions = debugMeta.db_actions || [];
    const response_headers = debugMeta.response_headers || {};

    // Format JSON objects
    const formatObj = (obj) => {
        if (!obj || Object.keys(obj).length === 0) return "{}";
        return JSON.stringify(obj, null, 2);
    };

    // Format DB logs
    let dbLogsHtml = "No database transactions";
    if (db_actions.length > 0) {
        dbLogsHtml = db_actions.map(action => `
            <div class="sql-statement">${action}</div>
        `).join('');
    }

    logCard.innerHTML = `
        <div class="log-title">
            <div class="log-meta">
                <span class="log-method">${actionName}</span>
                <span class="log-status ${statusClass}">${status}</span>
            </div>
            <span class="log-time">${timestamp}</span>
        </div>
        <div class="log-grid">
            <div class="log-block">
                <h5>Outgoing HTTP Headers & Body</h5>
                <div class="log-headers-box"><strong>Headers:</strong>\n${formatObj(request.headers)}\n\n<strong>Body:</strong>\n${formatObj(request.body)}</div>
            </div>
            <div class="log-block">
                <h5>DB Operations (SQLite)</h5>
                <div class="log-headers-box">${dbLogsHtml}</div>
            </div>
            <div class="log-block">
                <h5>Incoming HTTP Response</h5>
                <div class="log-headers-box"><strong>Set-Cookie:</strong>\n${formatObj(response_headers)}\n\n<strong>Body Description:</strong>\n${description}</div>
            </div>
        </div>
    `;

    networkTimeline.insertBefore(logCard, networkTimeline.firstChild);
}
