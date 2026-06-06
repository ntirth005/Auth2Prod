// State variables
let currentUser = null;

async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
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

const cookieStatusBadge = document.getElementById("cookie-status-badge");
const cookieRawVal = document.getElementById("cookie-raw-val");

const usersList = document.getElementById("users-list");
const sessionsList = document.getElementById("sessions-list");
const networkTimeline = document.getElementById("network-timeline");

const refreshStateBtn = document.getElementById("refresh-state-btn");
const resetDbBtn = document.getElementById("reset-db-btn");
const clearLogsBtn = document.getElementById("clear-logs-btn");
const logoutBtn = document.getElementById("logout-btn");

// Initial Setup
document.addEventListener("DOMContentLoaded", () => {
    checkActiveSession();
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
    const secure_cookie = document.getElementById("login-secure-cookie").checked;
    const auth_mode = document.getElementById("login-auth-mode").value;

    if (auth_mode === "standard") {
        try {
            const response = await fetch("/api/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password, secure_cookie })
            });
            const data = await response.json();
            
            if (response.ok) {
                let desc = "User verified. Server generated session token and responded with Set-Cookie header.";
                if (secure_cookie) {
                    desc += " WARNING: Cookie configured with 'Secure' flag. Since this sandbox is running over insecure HTTP, your browser will reject/discard this cookie!";
                }
                logTransaction("POST /api/login", 200, data.debug, desc);
                currentUser = data.user;
                showProfileUI(data.user);
                loginForm.reset();
                
                if (secure_cookie) {
                    setTimeout(() => {
                        alert("⚠️ Educational Warning:\nYou enabled the 'Secure' flag (HTTPS-only) on the session cookie.\n\nBecause this workspace is running over local HTTP (http://127.0.0.1:8000), your browser will reject and discard the session cookie.\n\nYou will notice that you are immediately forced back to the log-in page or subsequent profile operations fail with a 401!");
                    }, 100);
                }
            } else {
                alert(formatError(data.detail) || "Authentication failed.");
            }
        } catch (err) {
            alert("Error connecting to server.");
        }
    } else {
        // Zero-Transmitted-Password Cryptographic Challenge-Response flow
        try {
            // Step 1: Request random challenge nonce and user-specific salt
            const challResponse = await fetch("/api/auth/challenge", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username })
            });
            const challData = await challResponse.json();
            
            if (!challResponse.ok) {
                alert(formatError(challData.detail) || "Failed to retrieve authentication challenge.");
                return;
            }
            
            logTransaction(
                "POST /api/auth/challenge", 
                200, 
                challData.debug, 
                `Retrieved unique single-use login nonce: ${challData.nonce.substring(0,6)}... and client salt: ${challData.salt.substring(0,8)}...`
            );
            
            // Step 2: Compute cryptographic client-side response
            // key = SHA256(password + salt)
            // auth_hash = SHA256(key + nonce)
            const client_key = await sha256(password + challData.salt);
            const auth_hash = await sha256(client_key + challData.nonce);
            
            // Step 3: Complete cryptographic login handshake
            const loginResponse = await fetch("/api/auth/challenge-login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    username,
                    nonce: challData.nonce,
                    auth_hash,
                    secure_cookie
                })
            });
            const loginData = await loginResponse.json();
            
            if (loginResponse.ok) {
                let desc = `Zero-Password-Transmission Success! Client signature verified. Server set session cookie. NO PASSWORD WAS TRANSMITTED over the network.`;
                if (secure_cookie) {
                    desc += " WARNING: Cookie configured with 'Secure' flag. Since this sandbox is running over insecure HTTP, your browser will reject/discard this cookie!";
                }
                logTransaction("POST /api/auth/challenge-login", 200, loginData.debug, desc);
                currentUser = loginData.user;
                showProfileUI(loginData.user);
                loginForm.reset();
                
                if (secure_cookie) {
                    setTimeout(() => {
                        alert("⚠️ Educational Warning:\nYou enabled the 'Secure' flag (HTTPS-only) on the session cookie.\n\nBecause this workspace is running over local HTTP (http://127.0.0.1:8000), your browser will reject and discard the session cookie.\n\nYou will notice that you are immediately forced back to the log-in page or subsequent profile operations fail with a 401!");
                    }, 100);
                }
            } else {
                alert(formatError(loginData.detail) || "Authentication challenge verification failed.");
            }
        } catch (err) {
            console.error(err);
            alert("Error connecting to server during cryptographic handshake.");
        }
    }
    pollState();
});

profileUpdateForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const display_name = profileDisplayName.value || null;
    const email = profileEmail.value || null;
    const bio = profileBio.value || null;

    try {
        const response = await fetch("/api/profile", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ display_name, email, bio })
        });
        const data = await response.json();
        
        if (response.ok) {
            logTransaction("PUT /api/profile", 200, data.debug, "Session checked and validated. User model updated in the SQLite database.");
            alert(data.message);
            showProfileUI(data.user);
        } else {
            alert(formatError(data.detail) || "Update failed.");
        }
    } catch (err) {
        alert("Error updating profile.");
    }
    pollState();
});

passwordChangeForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const current_password = document.getElementById("pwd-current").value;
    const new_password = document.getElementById("pwd-new").value;

    try {
        const response = await fetch("/api/change-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ current_password, new_password })
        });
        const data = await response.json();
        
        if (response.ok) {
            logTransaction("POST /api/change-password", 200, data.debug, "Verified current password. Saved new hashed password in DB and deleted other active user sessions.");
            alert(data.message);
            passwordChangeForm.reset();
        } else {
            alert(formatError(data.detail) || "Password change failed.");
        }
    } catch (err) {
        alert("Error updating password.");
    }
    pollState();
});

// Helper Functions
async function checkActiveSession() {
    try {
        const response = await fetch("/api/profile");
        const data = await response.json();
        if (response.ok) {
            currentUser = data.user;
            showProfileUI(data.user);
        } else {
            showLoginUI();
        }
    } catch (e) {
        showLoginUI();
    }
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
    currentUser = null;
}

async function performLogout() {
    try {
        const response = await fetch("/api/logout", { method: "POST" });
        const data = await response.json();
        logTransaction("POST /api/logout", 200, data.debug, "Deleted session ID from database and returned deleted Set-Cookie headers to browser.");
    } catch (e) {}
    showLoginUI();
    pollState();
}

async function resetDatabase() {
    if (!confirm("Are you sure you want to reset the database? This wipes all users and sessions.")) return;
    try {
        const response = await fetch("/api/debug/reset", { method: "POST" });
        const data = await response.json();
        alert(data.message);
    } catch (e) {}
    showLoginUI();
    pollState();
}

// Diagnostic polling
async function pollState() {
    try {
        const response = await fetch("/api/debug/state");
        const state = await response.json();
        
        // Update Cookie HUD based on reflected server state
        updateCookieHUD(state.client_session_cookie);
        
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

        // Render Sessions
        if (state.sessions.length === 0) {
            sessionsList.innerHTML = '<div class="empty-state">No active sessions</div>';
        } else {
            sessionsList.innerHTML = state.sessions.map(s => `
                <div class="state-item">
                    <div class="state-item-header">
                        <span>ID: ${s.user_id} (@${s.username})</span>
                    </div>
                    <div class="state-item-detail">
                        Token: ${s.session_id}<br>
                        Expires: ${new Date(s.expires_at).toLocaleTimeString()}
                    </div>
                </div>
            `).join('');
        }
    } catch (err) {}
}

function updateCookieHUD(sessionCookie) {
    if (sessionCookie) {
        cookieStatusBadge.textContent = "ACTIVE SESSION";
        cookieStatusBadge.className = "hud-status status-green";
        cookieRawVal.textContent = `session_profile_id=${sessionCookie.substring(0, 10)}... (HttpOnly protected)`;
    } else {
        cookieStatusBadge.textContent = "NO SESSION";
        cookieStatusBadge.className = "hud-status status-red";
        cookieRawVal.textContent = "None (No cookie detected by server)";
    }
}

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
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
    
    // Format JSON objects
    const formatObj = (obj) => {
        if (!obj || Object.keys(obj).length === 0) return "{}";
        return JSON.stringify(obj, null, 2);
    };

    // Format DB logs
    let dbLogsHtml = "No database transactions";
    if (debugMeta.db_actions && debugMeta.db_actions.length > 0) {
        dbLogsHtml = debugMeta.db_actions.map(action => `
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
                <div class="log-headers-box"><strong>Headers:</strong>\n${formatObj(debugMeta.request.headers)}\n\n<strong>Body:</strong>\n${formatObj(debugMeta.request.body)}</div>
            </div>
            <div class="log-block">
                <h5>DB Operations (SQLite)</h5>
                <div class="log-headers-box">${dbLogsHtml}</div>
            </div>
            <div class="log-block">
                <h5>Incoming HTTP Response</h5>
                <div class="log-headers-box"><strong>Set-Cookie:</strong>\n${formatObj(debugMeta.response_headers)}\n\n<strong>Body Description:</strong>\n${description}</div>
            </div>
        </div>
    `;

    networkTimeline.insertBefore(logCard, networkTimeline.firstChild);
}
