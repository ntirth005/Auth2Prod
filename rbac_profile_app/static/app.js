// App Authentication and Visual State
let activeToken = "";
let activeUser = null;
let databaseState = null;

// DOM Elements
const authLoginForm = document.getElementById("auth-login-form");
const authRegisterForm = document.getElementById("auth-register-form");
const loginUsernameInput = document.getElementById("login-username");
const loginPasswordInput = document.getElementById("login-password");

const profileUsername = document.getElementById("profile-username");
const profileDisplayName = document.getElementById("profile-displayname");
const profileEmail = document.getElementById("profile-email");
const profileBio = document.getElementById("profile-bio");
const profileAvatar = document.getElementById("profile-avatar");
const profileUpdateForm = document.getElementById("profile-update-form");

const provisionUserSelect = document.getElementById("provision-user-select");
const roleProvisionForm = document.getElementById("role-provision-form");

const sandboxTargetUser = document.getElementById("sandbox-target-user");
const sandboxDeleteUser = document.getElementById("sandbox-delete-user");

const btnSandboxRead = document.getElementById("btn-sandbox-read");
const btnSandboxWrite = document.getElementById("btn-sandbox-write");
const btnSandboxBan = document.getElementById("btn-sandbox-ban");
const btnSandboxDelete = document.getElementById("btn-sandbox-delete");

const btnRefreshState = document.getElementById("btn-refresh-state");
const btnResetDb = document.getElementById("btn-reset-db");
const btnClearLogs = document.getElementById("btn-clear-logs");
const interactionTimeline = document.getElementById("interaction-timeline");

// Core Bootloader
document.addEventListener("DOMContentLoaded", () => {
    initAuthListeners();
    initSandboxListeners();
    initDatabaseInspector();
    
    // Initial fetch of DB State
    refreshState(false);
});

// 1. Auth and Identity Context
function initAuthListeners() {
    // Quick Logins
    document.querySelectorAll(".btn-quick-login").forEach(btn => {
        btn.addEventListener("click", () => {
            const username = btn.getAttribute("data-username");
            loginUsernameInput.value = username;
            loginPasswordInput.value = "password123";
            performLogin(username, "password123");
        });
    });

    // Login Form Submit
    authLoginForm.addEventListener("submit", (e) => {
        e.preventDefault();
        performLogin(loginUsernameInput.value.trim(), loginPasswordInput.value);
    });

    // Register Form Submit
    authRegisterForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const username = document.getElementById("reg-username").value.trim();
        const password = document.getElementById("reg-password").value;
        const email = document.getElementById("reg-email").value.trim() || null;

        try {
            const response = await fetch("/api/auth/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password, email })
            });
            const data = await response.json();
            const resHeaders = {};
            response.headers.forEach((v, k) => resHeaders[k] = v);

            if (response.ok) {
                logTransaction(
                    "POST",
                    "/api/auth/register",
                    { username, password: "••••••••", email },
                    data.debug?.db_actions || [],
                    response.status,
                    resHeaders,
                    data,
                    `New user '${username}' registered. SQLite triggered user insertions and assigned the default role 'User' in the 'user_roles' association table.`
                );
                alert(`User '${username}' registered successfully! You can now log in as them.`);
                document.getElementById("reg-username").value = "";
                document.getElementById("reg-password").value = "";
                document.getElementById("reg-email").value = "";
                refreshState();
            } else {
                logTransaction(
                    "POST",
                    "/api/auth/register",
                    { username, password: "••••••••", email },
                    data.debug?.db_actions || [],
                    response.status,
                    resHeaders,
                    data,
                    `Registration failed: ${data.detail}`
                );
                alert(data.detail || "Registration failed.");
            }
        } catch (err) {
            console.error(err);
        }
    });

    // Profile update submit
    profileUpdateForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        if (!activeToken) {
            alert("Please login first to establish user context.");
            return;
        }

        const payload = {
            display_name: profileDisplayName.value.trim() || null,
            email: profileEmail.value.trim() || null,
            bio: profileBio.value.trim() || null,
            avatar_url: profileAvatar.value.trim() || null
        };

        try {
            const response = await fetch("/api/profile/me", {
                method: "PUT",
                headers: { 
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${activeToken}`
                },
                body: JSON.stringify(payload)
            });
            const data = await response.json();
            const resHeaders = {};
            response.headers.forEach((v, k) => resHeaders[k] = v);

            if (response.ok) {
                logTransaction(
                    "PUT",
                    "/api/profile/me",
                    payload,
                    data.debug?.db_actions || [],
                    response.status,
                    resHeaders,
                    data,
                    `User '${activeUser.username}' updated their profile fields. SQLite modified the user row in the database.`
                );
                activeUser = data.user;
                updateActiveProfileHUD(activeUser);
                refreshState();
            } else {
                logTransaction(
                    "PUT",
                    "/api/profile/me",
                    payload,
                    data.debug?.db_actions || [],
                    response.status,
                    resHeaders,
                    data,
                    `Failed to update profile. Details: ${data.detail}`
                );
                alert(data.detail || "Profile update failed.");
            }
        } catch (err) {
            console.error(err);
        }
    });

    // Role provision submit
    roleProvisionForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        if (!activeToken) {
            alert("Please login first to establish user context.");
            return;
        }

        const targetUserId = provisionUserSelect.value;
        if (!targetUserId) {
            alert("Please choose a target user to provision roles.");
            return;
        }

        const selectedRoles = [];
        document.querySelectorAll("input[name='provision-roles']:checked").forEach(cb => {
            selectedRoles.push(cb.value);
        });

        try {
            const response = await fetch(`/api/admin/user/${targetUserId}/roles`, {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${activeToken}`
                },
                body: JSON.stringify({ roles: selectedRoles })
            });
            const data = await response.json();
            const resHeaders = {};
            response.headers.forEach((v, k) => resHeaders[k] = v);

            if (response.ok) {
                logTransaction(
                    "PUT",
                    `/api/admin/user/${targetUserId}/roles`,
                    { roles: selectedRoles },
                    data.debug?.db_actions || [],
                    response.status,
                    resHeaders,
                    data,
                    `Admin successfully reassigned user roles. SQLAlchemy flushed association rows and inserted new configurations in 'user_roles' link table.`
                );
                alert(data.message);
                refreshState();
            } else {
                logTransaction(
                    "PUT",
                    `/api/admin/user/${targetUserId}/roles`,
                    { roles: selectedRoles },
                    data.debug?.db_actions || [],
                    response.status,
                    resHeaders,
                    data,
                    `Role provisioning blocked: ${data.detail}`
                );
                alert(data.detail || "Operation failed.");
            }
        } catch (err) {
            console.error(err);
        }
    });
}

// Perform Login Request
async function performLogin(username, password) {
    try {
        const response = await fetch("/api/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();
        const resHeaders = {};
        response.headers.forEach((v, k) => resHeaders[k] = v);

        if (response.ok) {
            activeToken = data.access_token;
            activeUser = data.user;
            
            // Prefill update profile forms
            updateActiveProfileHUD(activeUser);

            logTransaction(
                "POST",
                "/api/auth/login",
                { username, password: "••••••••" },
                data.debug?.db_actions || [],
                response.status,
                resHeaders,
                data,
                `Security context established. Issued signed JWT Bearer Access Token. Loaded user roles: [${activeUser.roles.map(r => r.name).join(", ")}].`
            );
            refreshState();
        } else {
            logTransaction(
                "POST",
                "/api/auth/login",
                { username, password: "••••••••" },
                data.debug?.db_actions || [],
                response.status,
                resHeaders,
                data,
                `Login failed: incorrect credentials.`
            );
            alert(data.detail || "Incorrect username or password.");
        }
    } catch (err) {
        console.error(err);
    }
}

function updateActiveProfileHUD(user) {
    profileUsername.value = `${user.username} (Roles: ${user.roles.map(r => r.name).join(", ")})`;
    profileDisplayName.value = user.display_name || "";
    profileEmail.value = user.email || "";
    profileBio.value = user.bio || "";
    profileAvatar.value = user.avatar_url || "";
}

// 2. Sandbox action checkers
function initSandboxListeners() {
    // Read Sandbox
    btnSandboxRead.addEventListener("click", async () => {
        const authHeader = activeToken ? `Bearer ${activeToken}` : "";
        try {
            const response = await fetch("/api/profile/me", {
                method: "GET",
                headers: { "Authorization": authHeader }
            });
            const data = await response.json();
            const resHeaders = {};
            response.headers.forEach((v, k) => resHeaders[k] = v);

            let comment = "";
            if (response.ok) {
                comment = `Gated Read Profile action passed. Token contains required permission 'user:read'.`;
            } else {
                comment = `Blocked Gated Read Profile action (403 Forbidden). Authenticated user does not possess required permission 'user:read'.`;
            }

            logTransaction(
                "GET",
                "/api/profile/me",
                null,
                data.debug?.db_actions || [],
                response.status,
                resHeaders,
                data,
                comment
            );
        } catch (err) {
            console.error(err);
        }
    });

    // Write Sandbox
    btnSandboxWrite.addEventListener("click", async () => {
        const authHeader = activeToken ? `Bearer ${activeToken}` : "";
        try {
            // Mock empty update
            const response = await fetch("/api/profile/me", {
                method: "PUT",
                headers: { 
                    "Content-Type": "application/json",
                    "Authorization": authHeader 
                },
                body: JSON.stringify({})
            });
            const data = await response.json();
            const resHeaders = {};
            response.headers.forEach((v, k) => resHeaders[k] = v);

            let comment = "";
            if (response.ok) {
                comment = `Gated Update Profile action passed. Token contains required permission 'user:write'.`;
            } else {
                comment = `Blocked Gated Update Profile action (403 Forbidden). Authenticated user does not possess required permission 'user:write'.`;
            }

            logTransaction(
                "PUT",
                "/api/profile/me",
                {},
                data.debug?.db_actions || [],
                response.status,
                resHeaders,
                data,
                comment
            );
        } catch (err) {
            console.error(err);
        }
    });

    // Ban Sandbox
    btnSandboxBan.addEventListener("click", async () => {
        const authHeader = activeToken ? `Bearer ${activeToken}` : "";
        const targetUserId = sandboxTargetUser.value;
        if (!targetUserId) {
            alert("Please select a target user to ban.");
            return;
        }

        try {
            const response = await fetch(`/api/admin/ban/${targetUserId}`, {
                method: "POST",
                headers: { "Authorization": authHeader }
            });
            const data = await response.json();
            const resHeaders = {};
            response.headers.forEach((v, k) => resHeaders[k] = v);

            let comment = "";
            if (response.ok) {
                comment = `Ban action verified successfully. User possesses Moderator/Admin role and permission 'user:write'. Target user has been flagged as [BANNED] in SQLite.`;
                alert(data.message);
                refreshState();
            } else {
                comment = `Blocked Ban action (403 Forbidden). Requires 'user:write' permission and 'Admin' or 'Moderator' role.`;
                alert(data.detail || "Operation denied.");
            }

            logTransaction(
                "POST",
                `/api/admin/ban/${targetUserId}`,
                null,
                data.debug?.db_actions || [],
                response.status,
                resHeaders,
                data,
                comment
            );
        } catch (err) {
            console.error(err);
        }
    });

    // Delete Sandbox
    btnSandboxDelete.addEventListener("click", async () => {
        const authHeader = activeToken ? `Bearer ${activeToken}` : "";
        const targetUserId = sandboxDeleteUser.value;
        if (!targetUserId) {
            alert("Please select a target user to delete.");
            return;
        }

        try {
            const response = await fetch(`/api/admin/user/${targetUserId}`, {
                method: "DELETE",
                headers: { "Authorization": authHeader }
            });
            const data = await response.json();
            const resHeaders = {};
            response.headers.forEach((v, k) => resHeaders[k] = v);

            let comment = "";
            if (response.ok) {
                comment = `Delete action verified successfully. User possesses required permission 'user:delete' (Admin only). User records deleted from database.`;
                alert(data.message);
                refreshState();
            } else {
                comment = `Blocked Delete action (403 Forbidden). Requires 'user:delete' permission (linked to Admin).`;
                alert(data.detail || "Operation denied.");
            }

            logTransaction(
                "DELETE",
                `/api/admin/user/${targetUserId}`,
                null,
                data.debug?.db_actions || [],
                response.status,
                resHeaders,
                data,
                comment
            );
        } catch (err) {
            console.error(err);
        }
    });
}

// 3. Database Inspector and Tabs
function initDatabaseInspector() {
    // Tabs clicking
    document.querySelectorAll(".db-tab-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".db-tab-btn").forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".db-table-panel").forEach(p => p.classList.add("hidden"));

            btn.classList.add("active");
            const tabId = btn.getAttribute("data-db-tab");
            const targetPanel = document.getElementById(`db-view-${tabId}`);
            if (targetPanel) {
                targetPanel.classList.remove("hidden");
            }
        });
    });

    btnRefreshState.addEventListener("click", () => refreshState(true));
    
    // Clear logs console
    btnClearLogs.addEventListener("click", () => {
        interactionTimeline.innerHTML = `<div class="empty-network">No transactions captured yet. Perform login, registration, edits, or sandbox actions to trace client-server pipeline.</div>`;
    });

    // Reset database
    btnResetDb.addEventListener("click", async () => {
        if (!confirm("Are you sure you want to flush the SQLite database and restore default Alice, Bob, and Charlie accounts?")) return;

        try {
            const response = await fetch("/api/debug/reset", { method: "POST" });
            const data = await response.json();
            
            // Reset state variables
            activeToken = "";
            activeUser = null;
            profileUsername.value = "Guest";
            profileDisplayName.value = "";
            profileEmail.value = "";
            profileBio.value = "";
            profileAvatar.value = "";

            interactionTimeline.innerHTML = `<div class="empty-network">Database successfully flusheed & seeded. Interaction logs cleared.</div>`;
            refreshState();
            alert("Database flusheed and seeded successfully!");
        } catch (err) {
            console.error(err);
        }
    });
}

// Fetch database state and update UI monitors
async function refreshState(logAction = false) {
    try {
        const response = await fetch("/api/debug/state");
        const data = await response.json();
        
        if (response.ok) {
            databaseState = data.state;
            renderDatabaseState(databaseState);
            updateSelectDropdowns(databaseState.users);

            if (logAction) {
                const resHeaders = {};
                response.headers.forEach((v, k) => resHeaders[k] = v);
                logTransaction(
                    "GET",
                    "/api/debug/state",
                    null,
                    data.debug?.db_actions || [],
                    response.status,
                    resHeaders,
                    data,
                    "SQLite Database tables queried to render visual diagnostic table panels."
                );
            }
        }
    } catch (err) {
        console.error("Error fetching db state:", err);
    }
}

// Render SQLite tables side-by-side
function renderDatabaseState(state) {
    // 1. Users Tab
    const usersView = document.getElementById("db-view-users");
    usersView.innerHTML = state.users.map(u => `
        <div class="db-grid-row">
            👤 ID: <strong>${u.id}</strong> | Username: <strong>${u.username}</strong> <br>
            Display Name: <code>${u.display_name}</code> <br>
            Email: <code>${u.email || 'None'}</code> | Bio: <code>${u.bio || 'None'}</code> <br>
            Assigned Roles: <span style="color:#a78bfa;">[${u.roles.join(", ")}]</span>
        </div>
    `).join("");

    // 2. Roles Tab
    const rolesView = document.getElementById("db-view-roles");
    rolesView.innerHTML = state.roles.map(r => `
        <div class="db-grid-row">
            🔑 ID: <strong>${r.id}</strong> | Name: <strong>${r.name}</strong> <br>
            Description: <code>${r.description}</code> <br>
            Granted Permissions: <span style="color:#f472b6;">[${r.permissions.join(", ")}]</span>
        </div>
    `).join("");

    // 3. Permissions Tab
    const permsView = document.getElementById("db-view-permissions");
    permsView.innerHTML = state.permissions.map(p => `
        <div class="db-grid-row">
            🔓 ID: <strong>${p.id}</strong> | Name: <strong>${p.name}</strong> <br>
            Description: <code>${p.description}</code>
        </div>
    `).join("");

    // 4. User-Roles associations
    const urView = document.getElementById("db-view-user-roles");
    if (state.user_roles_associations.length === 0) {
        urView.innerHTML = `<div class="empty-state">No links established</div>`;
    } else {
        urView.innerHTML = state.user_roles_associations.map(link => `
            <div class="db-grid-row" style="color:#818cf8;">
                🔗 user_id: <strong>${link.user_id}</strong> &lt;====&gt; role_id: <strong>${link.role_id}</strong>
            </div>
        `).join("");
    }

    // 5. Role-Permissions associations
    const rpView = document.getElementById("db-view-role-perms");
    if (state.role_permissions_associations.length === 0) {
        rpView.innerHTML = `<div class="empty-state">No links established</div>`;
    } else {
        rpView.innerHTML = state.role_permissions_associations.map(link => `
            <div class="db-grid-row" style="color:#ec4899;">
                🔗 role_id: <strong>${link.role_id}</strong> &lt;====&gt; permission_id: <strong>${link.permission_id}</strong>
            </div>
        `).join("");
    }
}

// Update select user lists dynamically
function updateSelectDropdowns(users) {
    const listOptions = users.map(u => `<option value="${u.id}">${u.username} (ID: ${u.id})</option>`).join("");
    
    const prevSelectVal = provisionUserSelect.value;
    provisionUserSelect.innerHTML = `<option value="">-- Choose User --</option>${listOptions}`;
    provisionUserSelect.value = prevSelectVal;

    const prevTargetVal = sandboxTargetUser.value;
    sandboxTargetUser.innerHTML = `<option value="">-- Select Target User --</option>${listOptions}`;
    sandboxTargetUser.value = prevTargetVal;

    const prevDelVal = sandboxDeleteUser.value;
    sandboxDeleteUser.innerHTML = `<option value="">-- Select Target User --</option>${listOptions}`;
    sandboxDeleteUser.value = prevDelVal;
}

// 4. Three-Column Log Console
function logTransaction(method, url, requestBody, sqlQueries, responseStatus, responseHeaders, responseBody, explanation) {
    // Remove empty timeline notice
    const emptyMsg = interactionTimeline.querySelector(".empty-network");
    if (emptyMsg) {
        emptyMsg.remove();
    }

    const logCard = document.createElement("div");
    const isForbidden = responseStatus === 403;
    logCard.className = `log-card ${isForbidden ? 'forbidden-error' : ''}`;

    const timestamp = new Date().toLocaleTimeString();
    const statusClass = responseStatus >= 200 && responseStatus < 300 ? "status-success" : (isForbidden ? "status-forbidden" : "status-forbidden");

    const formatObj = (obj) => {
        if (!obj) return "{}";
        return JSON.stringify(obj, null, 2);
    };

    // Format SQL column
    let sqlColumnContent = "";
    if (sqlQueries.length === 0) {
        sqlColumnContent = `<div class="empty-state" style="font-size:0.65rem; color:var(--text-dark); text-align:center;">No SQL statements triggered (cached or check failed early)</div>`;
    } else {
        sqlColumnContent = `
            <div class="log-sql-list">
                ${sqlQueries.map(q => `<div class="log-sql-stmt">${q}</div>`).join("")}
            </div>
        `;
    }

    logCard.innerHTML = `
        <div class="log-title">
            <div class="log-meta">
                <span class="log-method">${method}</span>
                <span class="log-url">${url}</span>
            </div>
            <div>
                <span class="log-status ${statusClass}">${responseStatus}</span>
                <span class="log-time" style="margin-left:8px;">${timestamp}</span>
            </div>
        </div>
        <div class="log-three-col-grid">
            <!-- Column 1: Outgoing Request Details -->
            <div class="log-col">
                <h5>1. Request Parameters</h5>
                <div class="log-data-box"><strong>Headers:</strong>\n${formatObj(responseHeaders ? {"Authorization": activeToken ? `Bearer ${activeToken.substring(0,12)}...` : "None"} : {})}\n\n<strong>JSON Payload:</strong>\n${formatObj(requestBody)}</div>
            </div>
            
            <!-- Column 2: Intercepted SQL Operations -->
            <div class="log-col col-sql">
                <h5>2. SQL Operations (SQLite)</h5>
                <div class="log-data-box">${sqlColumnContent}</div>
            </div>

            <!-- Column 3: Server HTTP Response -->
            <div class="log-col">
                <h5>3. Server Response</h5>
                <div class="log-data-box"><strong>Headers:</strong>\n${formatObj(responseHeaders)}\n\n<strong>JSON Body:</strong>\n${formatObj(responseBody)}</div>
            </div>
        </div>
        <div class="log-explain">
            <strong>RBAC Security Analysis:</strong> ${explanation}
        </div>
    `;

    // Insert at the top of timeline
    interactionTimeline.insertBefore(logCard, interactionTimeline.firstChild);
}
