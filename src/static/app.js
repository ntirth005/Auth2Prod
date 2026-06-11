// State Variables
let roles = ["Admin"];
let customPermissions = [];
let currentToken = "";

// DOM Elements
const rolesTagsContainer = document.getElementById("roles-tags-container");
const rolesTagInput = document.getElementById("roles-tag-input");
const permissionsTagsContainer = document.getElementById("permissions-tags-container");
const permissionsTagInput = document.getElementById("permissions-tag-input");

const generateForm = document.getElementById("generate-form");
const btnRotateSecret = document.getElementById("btn-rotate-secret");
const signingSecret = document.getElementById("signing-secret");
const signingAlg = document.getElementById("signing-alg");
const claimSub = document.getElementById("claim-sub");
const claimUsername = document.getElementById("claim-username");
const claimExpiry = document.getElementById("claim-expiry");

const jwtSegmentedBox = document.getElementById("jwt-segmented-box");
const tamperTokenArea = document.getElementById("tamper-token-area");

const routePreset = document.getElementById("route-preset");
const guardRole = document.getElementById("guard-role");
const guardPermission = document.getElementById("guard-permission");
const verifySecret = document.getElementById("verify-secret");
const verifyAlg = document.getElementById("verify-alg");
const btnEvaluateSubmit = document.getElementById("btn-evaluate-submit");
const gatewayOverallBadge = document.getElementById("gateway-overall-badge");

const networkTimeline = document.getElementById("network-timeline");
const clearLogsBtn = document.getElementById("clear-logs-btn");
const resetWorkspaceBtn = document.getElementById("reset-workspace-btn");

// Initialization on Load
document.addEventListener("DOMContentLoaded", () => {
    initTagEditors();
    initPresets();
    initEventListeners();
    
    // Initial token generation
    triggerTokenGeneration(false);
});

// 1. Tag Editors logic
function initTagEditors() {
    // Render initial role tags
    renderTags(rolesTagsContainer, roles, (tag) => {
        roles = roles.filter(t => t !== tag);
        triggerTokenGeneration(false);
    });

    rolesTagInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === ",") {
            e.preventDefault();
            const tagVal = rolesTagInput.value.trim().replace(/,/g, "");
            if (tagVal && !roles.includes(tagVal)) {
                roles.push(tagVal);
                renderTags(rolesTagsContainer, roles, (tag) => {
                    roles = roles.filter(t => t !== tag);
                    triggerTokenGeneration(false);
                });
                rolesTagInput.value = "";
                triggerTokenGeneration(false);
            }
        }
    });

    // Render initial custom permission tags
    renderTags(permissionsTagsContainer, customPermissions, (tag) => {
        customPermissions = customPermissions.filter(t => t !== tag);
        triggerTokenGeneration(false);
    });

    permissionsTagInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === ",") {
            e.preventDefault();
            const tagVal = permissionsTagInput.value.trim().replace(/,/g, "");
            if (tagVal && !customPermissions.includes(tagVal)) {
                customPermissions.push(tagVal);
                renderTags(permissionsTagsContainer, customPermissions, (tag) => {
                    customPermissions = customPermissions.filter(t => t !== tag);
                    triggerTokenGeneration(false);
                });
                permissionsTagInput.value = "";
                triggerTokenGeneration(false);
            }
        }
    });
}

function renderTags(container, tagList, onRemove) {
    // Keep the input box, remove existing pills
    const pills = container.querySelectorAll(".tag-pill");
    pills.forEach(p => p.remove());

    const inputElement = container.querySelector("input");

    tagList.forEach(tag => {
        const pill = document.createElement("span");
        pill.className = "tag-pill";
        pill.innerHTML = `${tag} <span class="tag-remove" data-tag="${tag}">×</span>`;
        
        pill.querySelector(".tag-remove").addEventListener("click", (e) => {
            const tagToRemove = e.target.getAttribute("data-tag");
            onRemove(tagToRemove);
        });

        container.insertBefore(pill, inputElement);
    });
}

// 2. Presets Manager
function initPresets() {
    routePreset.addEventListener("change", () => {
        const preset = routePreset.value;
        if (preset === "custom") {
            // Keep user custom selections
            return;
        }

        switch (preset) {
            case "profile-read":
                guardRole.value = "";
                guardPermission.value = "profile:read";
                break;
            case "profile-edit":
                guardRole.value = "";
                guardPermission.value = "profile:edit";
                break;
            case "system-delete":
                guardRole.value = "";
                guardPermission.value = "system:delete";
                break;
            case "admin-only":
                guardRole.value = "Admin";
                guardPermission.value = "";
                break;
            case "moderator-only":
                guardRole.value = "Moderator";
                guardPermission.value = "";
                break;
        }
    });

    // Customizing guard values shifts select back to "custom"
    guardRole.addEventListener("input", () => routePreset.value = "custom");
    guardPermission.addEventListener("input", () => routePreset.value = "custom");
}

// 3. Event Listeners & Buttons
function initEventListeners() {
    // Generate Form Submit
    generateForm.addEventListener("submit", (e) => {
        e.preventDefault();
        triggerTokenGeneration(true);
    });

    // Rotate Secret key
    btnRotateSecret.addEventListener("click", () => {
        const randomChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let newKey = "secret_";
        for (let i = 0; i < 24; i++) {
            newKey += randomChars.charAt(Math.floor(Math.random() * randomChars.length));
        }
        signingSecret.value = newKey;
        // Sync verifier secret automatically for better user experience
        verifySecret.value = newKey;
        triggerTokenGeneration(false);
    });

    // Sync alg selections
    signingAlg.addEventListener("change", () => {
        verifyAlg.value = signingAlg.value;
        triggerTokenGeneration(false);
    });

    // Tamper Area edits
    tamperTokenArea.addEventListener("input", () => {
        renderSegmentedToken(tamperTokenArea.value.trim());
    });

    // Submit for Verification
    btnEvaluateSubmit.addEventListener("click", handleEvaluate);

    // Clear Logs
    clearLogsBtn.addEventListener("click", () => {
        networkTimeline.innerHTML = `<div class="empty-network">No traffic requests captured. Generate and evaluate a token to monitor transmissions.</div>`;
    });

    // Reset workspace
    resetWorkspaceBtn.addEventListener("click", () => {
        if (confirm("Reset all inputs and clear transmissions history?")) {
            roles = ["Admin"];
            customPermissions = [];
            claimSub.value = "usr_928";
            claimUsername.value = "charlie";
            claimExpiry.value = "15";
            signingSecret.value = "super-secret-key-share-between-services-987";
            signingAlg.value = "HS256";
            
            document.getElementById("perm-read").checked = true;
            document.getElementById("perm-edit").checked = false;
            document.getElementById("perm-delete").checked = false;

            verifySecret.value = "super-secret-key-share-between-services-987";
            verifyAlg.value = "HS256";
            guardRole.value = "";
            guardPermission.value = "profile:read";
            routePreset.value = "profile-read";

            initTagEditors();
            triggerTokenGeneration(false);
            
            // Clear logs
            networkTimeline.innerHTML = `<div class="empty-network">No traffic requests captured. Generate and evaluate a token to monitor transmissions.</div>`;
            resetGatewayCheckUI();
        }
    });

    // Setup detail toggles for evaluation steps
    document.querySelectorAll(".step-detail-toggle").forEach(btn => {
        btn.addEventListener("click", (e) => {
            e.stopPropagation();
            const stepBox = e.target.closest(".guard-step-box");
            const stepNum = stepBox.getAttribute("data-step");
            const detailBox = document.getElementById(`step-detail-${stepNum}`);
            if (detailBox.classList.contains("hidden")) {
                detailBox.classList.remove("hidden");
                e.target.textContent = "Hide";
            } else {
                detailBox.classList.add("hidden");
                e.target.textContent = "View";
            }
        });
    });
}

// 4. Token Generation Actions
async function triggerTokenGeneration(notifyUser = false) {
    const sub = claimSub.value;
    const username = claimUsername.value;
    const expiry = parseInt(claimExpiry.value) || 15;
    const secret = signingSecret.value;
    const alg = signingAlg.value;

    // Collect standard checkbox permissions
    const permissions = [];
    if (document.getElementById("perm-read").checked) permissions.push("profile:read");
    if (document.getElementById("perm-edit").checked) permissions.push("profile:edit");
    if (document.getElementById("perm-delete").checked) permissions.push("system:delete");

    // Merge custom tag permissions
    customPermissions.forEach(p => {
        if (!permissions.includes(p)) permissions.push(p);
    });

    const payload = {
        sub,
        username,
        roles,
        permissions,
        secret_key: secret,
        algorithm: alg,
        expiry
    };

    try {
        const response = await fetch("/api/playground/generate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await response.json();

        if (response.ok) {
            currentToken = data.token;
            tamperTokenArea.value = currentToken;
            renderSegmentedToken(currentToken);
            
            // Sync verifier variables automatically
            verifySecret.value = secret;
            verifyAlg.value = alg;

            logTransaction(
                "POST /api/playground/generate", 
                200, 
                data.debug, 
                `Signed JWT payload successfully using ${alg}. Stateless Token constructed in-memory. Roles: [${roles.join(", ")}], Permissions: [${permissions.join(", ")}].`
            );

            if (notifyUser) {
                alert("New signed JWT successfully compiled!");
            }
        } else {
            console.error("Token generation error:", data.detail);
        }
    } catch (err) {
        console.error("Failed to connect to backend:", err);
    }
}

// Color-coding token segment parsing
function renderSegmentedToken(token) {
    const parts = token.split('.');
    if (parts.length !== 3) {
        jwtSegmentedBox.innerHTML = `<span class="empty-state-text" style="color: var(--color-danger); font-weight: 500;">Invalid JWT segments format (needs 3 dot-separated fields)</span>`;
        return;
    }

    const header = parts[0];
    const payload = parts[1];
    const signature = parts[2];

    jwtSegmentedBox.innerHTML = `
        <span class="jwt-segment" style="color: #ff4a5a; font-weight: 600; word-break: break-all;" title="Segment 1: Base64Url Header">${header}</span>
        <span style="color: #fff; font-weight: bold;">.</span>
        <span class="jwt-segment" style="color: #bc69ff; font-weight: 600; word-break: break-all;" title="Segment 2: Base64Url Payload Claims">${payload}</span>
        <span style="color: #fff; font-weight: bold;">.</span>
        <span class="jwt-segment" style="color: #3ca2f3; font-weight: 600; word-break: break-all;" title="Segment 3: Cryptographic Signature">${signature}</span>
    `;
}

// 5. Evaluate/Verify Claims Access Handler
async function handleEvaluate() {
    const token = tamperTokenArea.value.trim();
    const secret = verifySecret.value;
    const alg = verifyAlg.value;
    const reqRole = guardRole.value;
    const reqPerm = guardPermission.value;

    if (!token) {
        alert("Please generate or paste a JWT first.");
        return;
    }

    const payload = {
        token,
        secret_key: secret,
        algorithm: alg,
        required_role: reqRole || null,
        required_permission: reqPerm || null
    };

    try {
        const response = await fetch("/api/playground/evaluate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
        });
        const data = await response.json();

        if (response.ok) {
            // Render Step visualizer logs
            renderGatewaySteps(data.evaluation_logs, data.is_valid, data.message);
            
            // Add HTTP request-response log
            logTransaction(
                "POST /api/playground/evaluate",
                200,
                data.debug,
                `Stateless Route Guard evaluation finished. Status: ${data.is_valid ? 'Authorized' : 'Unauthorized'}. Detail: ${data.message}`
            );
        } else {
            alert(data.detail || "Failed to evaluate token.");
        }
    } catch (err) {
        console.error("Evaluation server request failed:", err);
    }
}

// Reset gateway visualizer to default state
function resetGatewayCheckUI() {
    gatewayOverallBadge.className = "badge";
    gatewayOverallBadge.style.background = "rgba(255, 255, 255, 0.05)";
    gatewayOverallBadge.style.color = "var(--text-muted)";
    gatewayOverallBadge.style.borderColor = "var(--border-card)";
    gatewayOverallBadge.textContent = "Awaiting Token";

    for (let step = 1; step <= 4; step++) {
        const box = document.querySelector(`.guard-step-box[data-step="${step}"]`);
        box.style.borderColor = "var(--border-card)";
        box.style.background = "rgba(255, 255, 255, 0.02)";
        box.querySelector(".step-indicator").textContent = "⚪";
        
        const toggleBtn = box.querySelector(".step-detail-toggle");
        toggleBtn.classList.add("hidden");
        toggleBtn.textContent = "View";

        const detailBox = document.getElementById(`step-detail-${step}`);
        detailBox.classList.add("hidden");
        detailBox.textContent = "";
    }
}

// Renders the step-by-step verification pipeline in UI
function renderGatewaySteps(logs, isValid, overallMessage) {
    // 1. Overall Status Badge
    gatewayOverallBadge.className = "badge";
    if (isValid) {
        gatewayOverallBadge.style.background = "rgba(16, 185, 129, 0.15)";
        gatewayOverallBadge.style.color = "var(--color-success)";
        gatewayOverallBadge.style.borderColor = "var(--color-success)";
        gatewayOverallBadge.textContent = "ACCESS GRANTED";
    } else {
        gatewayOverallBadge.style.background = "rgba(239, 68, 68, 0.15)";
        gatewayOverallBadge.style.color = "var(--color-danger)";
        gatewayOverallBadge.style.borderColor = "var(--color-danger)";
        gatewayOverallBadge.textContent = "ACCESS DENIED";
    }

    // 2. Format individual Steps
    logs.forEach(log => {
        const step = log.step;
        const box = document.querySelector(`.guard-step-box[data-step="${step}"]`);
        const indicator = box.querySelector(".step-indicator");
        const toggleBtn = box.querySelector(".step-detail-toggle");
        const detailBox = document.getElementById(`step-detail-${step}`);

        // Set message text
        box.querySelector(".step-message").textContent = log.message;

        // Reset details
        detailBox.textContent = log.detail || "No details provided for this step.";
        
        // Show Toggle button if details exist
        if (log.detail) {
            toggleBtn.classList.remove("hidden");
        } else {
            toggleBtn.classList.add("hidden");
        }

        // Apply visual classes and indicator icons
        if (log.status === "success") {
            box.style.borderColor = "rgba(16, 185, 129, 0.4)";
            box.style.background = "rgba(16, 185, 129, 0.04)";
            indicator.textContent = "🟢";
        } else if (log.status === "failed") {
            box.style.borderColor = "rgba(239, 68, 68, 0.4)";
            box.style.background = "rgba(239, 68, 68, 0.04)";
            indicator.textContent = "🔴";
            // Auto open failed step details for debug helper
            detailBox.classList.remove("hidden");
            toggleBtn.textContent = "Hide";
        } else { // skipped
            box.style.borderColor = "var(--border-card)";
            box.style.background = "rgba(255, 255, 255, 0.01)";
            indicator.textContent = "➖";
            detailBox.classList.add("hidden");
            toggleBtn.classList.add("hidden");
        }
    });
}

// 6. Network logs printing console
function logTransaction(actionName, status, debugMeta, protocolComment) {
    const timeline = document.getElementById("network-timeline");
    const emptyMsg = timeline.querySelector(".empty-network");
    if (emptyMsg) {
        emptyMsg.remove();
    }

    const logCard = document.createElement("div");
    logCard.className = "log-card";
    logCard.style.marginBottom = "0.75rem";

    const timestamp = new Date().toLocaleTimeString();
    const statusClass = status >= 200 && status < 300 ? "status-success" : "status-error";
    
    // Parse methods and url
    const requestDetails = debugMeta?.request || {};
    const method = requestDetails.method || "POST";
    const url = requestDetails.url || `/api/playground/${actionName.split('/').pop()}`;
    const reqHeaders = requestDetails.headers || {};
    const reqBody = requestDetails.body || {};
    
    const resHeaders = debugMeta?.response_headers || {};
    // Extract actual result content for displaying
    const resBody = {
        is_valid: debugMeta?.request?.body ? undefined : undefined
    };

    const formatObj = (obj) => {
        if (!obj) return "{}";
        return JSON.stringify(obj, null, 2);
    };

    logCard.innerHTML = `
        <div class="log-title">
            <div class="log-meta">
                <span class="log-method">${method}</span>
                <span class="log-url">${url}</span>
            </div>
            <div>
                <span class="log-status ${statusClass}">${status}</span>
                <span class="log-time" style="margin-left:8px;">${timestamp}</span>
            </div>
        </div>
        <div class="log-grid">
            <div class="log-block">
                <h5>Outgoing Request Parameters</h5>
                <div class="log-headers-box"><strong>Headers:</strong>\n${formatObj(reqHeaders)}\n\n<strong>Body / Payloads:</strong>\n${formatObj(reqBody)}</div>
            </div>
            <div class="log-block">
                <h5>Incoming Stateless Response</h5>
                <div class="log-headers-box"><strong>Headers:</strong>\n${formatObj(resHeaders)}\n\n<strong>Analysis Metrics:</strong>\n${formatObj(debugMeta?.db_actions ? { explanation: protocolComment } : {})}</div>
            </div>
        </div>
        <div class="log-explain">
            <strong>Stateless Mechanics Analysis:</strong> ${protocolComment}
        </div>
    `;

    timeline.insertBefore(logCard, timeline.firstChild);
}
