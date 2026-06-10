// State variables
let currentUser = null;

// DOM Elements
const authContainer = document.getElementById("auth-container");
const profileContainer = document.getElementById("profile-container");

const profileUpdateForm = document.getElementById("profile-update-form");
const greetName = document.getElementById("greet-name");
const greetUsername = document.getElementById("greet-username");
const userAvatar = document.getElementById("user-avatar");

const profileDisplayName = document.getElementById("profile-display-name");
const profileEmail = document.getElementById("profile-email");
const profileBio = document.getElementById("profile-bio");

const sessionStatusBadge = document.getElementById("session-status-badge");
const sessionProfileBadge = document.getElementById("session-profile-badge");
const sessionProviderVal = document.getElementById("session-provider-val");
const sessionEmailVal = document.getElementById("session-email-val");

const usersList = document.getElementById("users-list");
const networkTimeline = document.getElementById("network-timeline");

const btnRefreshState = document.getElementById("refresh-state-btn");
const btnResetDb = document.getElementById("reset-db-btn");
const btnClearLogs = document.getElementById("clear-logs-btn");
const btnLogout = document.getElementById("logout-btn");

// Initial setup on DOM ready
document.addEventListener("DOMContentLoaded", () => {
    setupEventListeners();
    fetchProfile();
    pollState();
    setInterval(pollState, 3000);
});

function setupEventListeners() {
    profileUpdateForm.addEventListener("submit", handleProfileUpdate);
    btnLogout.addEventListener("click", handleLogout);
    btnResetDb.addEventListener("click", handleResetDatabase);
    btnRefreshState.addEventListener("click", pollState);
    btnClearLogs.addEventListener("click", () => {
        networkTimeline.innerHTML = '<div class="empty-network">No interactions captured yet. Perform an action on the client workspace.</div>';
    });
}

// Fetch current authenticated user profile
async function fetchProfile() {
    try {
        const response = await fetch("/api/profile/me");
        const data = await response.json();

        if (response.ok) {
            currentUser = data;
            
            // Toggle view visibility
            authContainer.classList.add("hidden");
            profileContainer.classList.remove("hidden");

            // Update UI elements
            greetName.textContent = currentUser.display_name || currentUser.username;
            greetUsername.textContent = `@${currentUser.username}`;
            userAvatar.src = currentUser.avatar_url || "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?auto=format&fit=crop&w=150&h=150";
            
            profileDisplayName.value = currentUser.display_name || "";
            profileEmail.value = currentUser.email || "";
            profileBio.value = currentUser.bio || "";

            // Update HUD
            sessionStatusBadge.textContent = "AUTHENTICATED";
            sessionStatusBadge.className = "hud-status status-green";
            sessionProfileBadge.textContent = `@${currentUser.username}`;
            sessionProfileBadge.className = "hud-status status-green";
            
            let provider = "Local";
            if (currentUser.github_id) provider = "GitHub";
            else if (currentUser.google_id) provider = "Google";
            
            sessionProviderVal.textContent = provider;
            sessionEmailVal.textContent = currentUser.email || "None";

            addLogCard({
                method: "GET",
                url: "/api/profile/me",
                requestHeaders: { "Accept": "application/json" },
                requestBody: null,
                responseStatus: response.status,
                responseHeaders: Object.fromEntries(response.headers.entries()),
                responseBody: data,
                dbQueries: [
                    `SELECT * FROM users WHERE id = ${currentUser.id} LIMIT 1`
                ],
                explanation: "Client checks for an active session. The browser sends the HTTP Session Cookie. Server decodes the cookie and fetches the matching user profile record from the SQLite database."
            });
        } else {
            currentUser = null;
            authContainer.classList.remove("hidden");
            profileContainer.classList.add("hidden");

            // Reset HUD
            sessionStatusBadge.textContent = "ANONYMOUS";
            sessionStatusBadge.className = "hud-status status-red";
            sessionProfileBadge.textContent = "None";
            sessionProfileBadge.className = "hud-status status-red";
            sessionProviderVal.textContent = "None";
            sessionEmailVal.textContent = "None";

            addLogCard({
                method: "GET",
                url: "/api/profile/me",
                requestHeaders: { "Accept": "application/json" },
                requestBody: null,
                responseStatus: response.status,
                responseHeaders: Object.fromEntries(response.headers.entries()),
                responseBody: data,
                dbQueries: [],
                explanation: "Client checks for session cookie. No active cookie is found, or the signature verification failed. Access is denied (401), prompting the User to Sign In."
            });
        }
    } catch (error) {
        console.error("Profile fetch error:", error);
    }
}

// Update profile details
async function handleProfileUpdate(e) {
    e.preventDefault();
    const display_name = profileDisplayName.value;
    const email = profileEmail.value;
    const bio = profileBio.value;

    const payload = { display_name, email, bio };

    try {
        const response = await fetch("/api/profile/update", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await response.json();

        addLogCard({
            method: "PUT",
            url: "/api/profile/update",
            requestHeaders: { "Content-Type": "application/json" },
            requestBody: payload,
            responseStatus: response.status,
            responseHeaders: Object.fromEntries(response.headers.entries()),
            responseBody: data,
            dbQueries: [
                `UPDATE users SET display_name = '${display_name}', email = '${email}', bio = '${bio}' WHERE id = ${currentUser.id}`
            ],
            explanation: "Authorized profile fields edit. The server validates the session cookie, parses changes, executes the database UPDATE command, and returns the modified profile schema."
        });

        if (response.ok) {
            alert("Profile updated successfully!");
            fetchProfile();
            pollState();
        } else {
            alert("Profile update failed: " + (data.detail || "Unknown error"));
        }

    } catch (error) {
        console.error("Profile update error:", error);
    }
}

// Log out user
async function handleLogout() {
    try {
        const response = await fetch("/api/auth/logout", { method: "POST" });
        const data = await response.json();

        addLogCard({
            method: "POST",
            url: "/api/auth/logout",
            requestHeaders: {},
            requestBody: null,
            responseStatus: response.status,
            responseHeaders: Object.fromEntries(response.headers.entries()),
            responseBody: data,
            dbQueries: [],
            explanation: "Client triggers user logout. The server deletes the session cookie locally and instructs the browser to expire the cookie header."
        });

        if (response.ok) {
            setTimeout(() => {
                location.reload();
            }, 500);
        }
    } catch (error) {
        console.error("Logout error:", error);
    }
}

// Poll state database table
async function pollState() {
    try {
        const response = await fetch("/api/debug/state");
        if (!response.ok) return;
        const data = await response.json();

        if (data.users.length === 0) {
            usersList.innerHTML = '<div class="empty-state">No database records</div>';
        } else {
            usersList.innerHTML = data.users.map(u => `
                <div class="state-item">
                    <div style="display: flex; align-items: center; gap: 0.5rem; justify-content: space-between;">
                        <span style="font-weight:600;">ID: ${u.id} - ${u.display_name || u.username}</span>
                        <span class="badge" style="background: rgba(139, 92, 246, 0.15); color: var(--color-secondary); font-size: 0.65rem; padding: 1px 6px;">${u.provider}</span>
                    </div>
                    <div class="state-item-detail">Username: @${u.username}</div>
                    <div class="state-item-detail">Email: ${u.email || 'None'}</div>
                    ${u.avatar_url ? `<div class="state-item-detail" style="color:var(--color-primary); word-break:break-all;">Avatar: ${u.avatar_url.slice(0, 50)}...</div>` : ''}
                </div>
            `).join("");
        }
    } catch (error) {
        console.error("State poll error:", error);
    }
}

// Reset sandbox database
async function handleResetDatabase() {
    if (!confirm("Are you sure you want to delete all user profiles and active sessions?")) return;

    try {
        const response = await fetch("/api/debug/reset", { method: "POST" });
        const data = await response.json();

        addLogCard({
            method: "POST",
            url: "/api/debug/reset",
            requestHeaders: {},
            requestBody: null,
            responseStatus: response.status,
            responseHeaders: Object.fromEntries(response.headers.entries()),
            responseBody: data,
            dbQueries: [
                "DELETE FROM users"
            ],
            explanation: "Diagnostics utility reset. Clear all profiles and sessions from the sqlite database."
        });

        if (response.ok) {
            alert("Database records reset successfully!");
            setTimeout(() => {
                location.reload();
            }, 500);
        }
    } catch (error) {
        console.error("Database reset error:", error);
    }
}

// 3-Column transaction log renderer
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
