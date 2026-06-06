// State variable to hold current token
let currentToken = "";

// DOM Elements
const generateForm = document.getElementById("generate-form");
const tamperTokenArea = document.getElementById("tamper-token-area");
const jwtSegmentedBox = document.getElementById("jwt-segmented-box");

const verifySecretInput = document.getElementById("verify-secret");
const verifyAlgSelect = document.getElementById("verify-alg");
const btnVerifySubmit = document.getElementById("btn-verify-submit");

const verifyStatusBadge = document.getElementById("verify-status-badge");
const verifyMessage = document.getElementById("verify-message");
const decodedViewers = document.getElementById("decoded-viewers");
const verifyHeaderPre = document.getElementById("verify-header");
const verifyPayloadPre = document.getElementById("verify-payload");

const networkTimeline = document.getElementById("network-timeline");
const clearLogsBtn = document.getElementById("clear-logs-btn");

// Event Listeners
generateForm.addEventListener("submit", handleGenerate);
btnVerifySubmit.addEventListener("click", handleVerify);
clearLogsBtn.addEventListener("click", () => {
    networkTimeline.innerHTML = '<div class="empty-network">No traffic requests captured. Generate and submit a token to monitor requests.</div>';
});

// Generate Token Handler
async function handleGenerate(e) {
    e.preventDefault();
    const sub = document.getElementById("claim-sub").value;
    const username = document.getElementById("claim-username").value;
    const role = document.getElementById("claim-role").value;
    const expires_in = document.getElementById("claim-expiry").value;
    const secret = document.getElementById("signing-secret").value;
    const alg = document.getElementById("signing-alg").value;

    try {
        const response = await fetch("/api/playground/generate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ sub, username, role, expires_in, secret, alg })
        });
        const data = await response.json();
        
        if (response.ok) {
            currentToken = data.token;
            tamperTokenArea.value = currentToken;
            renderSegmentedToken(currentToken);
            
            // Sync the verify secret with the signing secret for convenience
            verifySecretInput.value = secret;
            verifyAlgSelect.value = alg;
            
            logTransaction("POST /api/playground/generate", 200, data.debug, "JWT compiled and signed on server. Returned raw token to client.");
            alert("JWT Token compiled and signed successfully!");
        } else {
            alert(data.detail || "Failed to generate token.");
        }
    } catch (err) {
        alert("Error connecting to server.");
    }
}

// Verify Token Handler
async function handleVerify() {
    const token = tamperTokenArea.value.trim();
    const secret = verifySecretInput.value;
    const alg = verifyAlgSelect.value;

    if (!token) {
        alert("Please generate or paste a token first.");
        return;
    }

    try {
        const response = await fetch("/api/playground/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ token, secret, alg })
        });
        const data = await response.json();
        
        // Update Verifier result panel
        decodedViewers.classList.remove("hidden");
        verifyHeaderPre.textContent = JSON.stringify(data.header, null, 2);
        verifyPayloadPre.textContent = JSON.stringify(data.payload, null, 2);

        if (data.is_valid) {
            verifyStatusBadge.textContent = "SIGNATURE VALID";
            verifyStatusBadge.className = "hud-status status-green";
            verifyMessage.textContent = "✅ Success: " + data.message;
            logTransaction("POST /api/playground/verify", 200, data.debug, "Token signature is valid. Server verified it statelessly without hitting the database!");
        } else {
            verifyStatusBadge.textContent = "VERIFICATION FAILED";
            verifyStatusBadge.className = "hud-status status-red";
            verifyMessage.textContent = "❌ Error: " + data.message;
            logTransaction("POST /api/playground/verify", 401, data.debug, `Token verification failed (${data.error_type || 'Error'}): ${data.message}`);
        }
    } catch (err) {
        console.error(err);
        alert("Error connecting to server.");
    }
}

// Color-coded token builder
function renderSegmentedToken(token) {
    const parts = token.split('.');
    if (parts.length !== 3) {
        jwtSegmentedBox.innerHTML = `<span class="empty-state-text">Invalid token format</span>`;
        return;
    }

    const header = parts[0];
    const payload = parts[1];
    const signature = parts[2];

    jwtSegmentedBox.innerHTML = `
        <span class="jwt-segment jwt-header-segment" style="color: #ff4a5a; font-weight: 600; word-break: break-all;">${header}</span>
        <span style="color: #fff; font-weight: bold;">.</span>
        <span class="jwt-segment jwt-payload-segment" style="color: #bc69ff; font-weight: 600; word-break: break-all;">${payload}</span>
        <span style="color: #fff; font-weight: bold;">.</span>
        <span class="jwt-segment jwt-sig-segment" style="color: #3ca2f3; font-weight: 600; word-break: break-all;">${signature}</span>
    `;
}

// Watch textarea to update segmented coloring when tampered manually
tamperTokenArea.addEventListener("input", () => {
    renderSegmentedToken(tamperTokenArea.value.trim());
});

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
                <h5>DB Operations (Stateless)</h5>
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
