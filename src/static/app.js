// Pure JS MD5 implementation for client-side Digest Auth calculations
function md5(string) {
    function RotateLeft(lValue, iShiftBits) {
        return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
    }
    function AddUnsigned(lX, lY) {
        var lX4, lY4, lX8, lY8, lResult;
        lX8 = (lX & 0x80000000);
        lY8 = (lY & 0x80000000);
        lX4 = (lX & 0x40000000);
        lY4 = (lY & 0x40000000);
        lResult = (lX & 0x3FFFFFFF) + (lY & 0x3FFFFFFF);
        if (lX4 & lY4) {
            return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
        }
        if (lX4 | lY4) {
            if (lResult & 0x40000000) {
                return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
            } else {
                return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
            }
        } else {
            return (lResult ^ lX8 ^ lY8);
        }
    }
    function F(x, y, z) { return (x & y) | ((~x) & z); }
    function G(x, y, z) { return (x & z) | (y & (~z)); }
    function H(x, y, z) { return (x ^ y ^ z); }
    function I(x, y, z) { return (y ^ (x | (~z))); }
    function FF(a, b, c, d, x, s, ac) {
        a = AddUnsigned(a, AddUnsigned(AddUnsigned(F(b, c, d), x), ac));
        return AddUnsigned(RotateLeft(a, s), b);
    }
    function GG(a, b, c, d, x, s, ac) {
        a = AddUnsigned(a, AddUnsigned(AddUnsigned(G(b, c, d), x), ac));
        return AddUnsigned(RotateLeft(a, s), b);
    }
    function HH(a, b, c, d, x, s, ac) {
        a = AddUnsigned(a, AddUnsigned(AddUnsigned(H(b, c, d), x), ac));
        return AddUnsigned(RotateLeft(a, s), b);
    }
    function II(a, b, c, d, x, s, ac) {
        a = AddUnsigned(a, AddUnsigned(AddUnsigned(I(b, c, d), x), ac));
        return AddUnsigned(RotateLeft(a, s), b);
    }
    function ConvertToWordArray(string) {
        var lWordCount;
        var lMessageLength = string.length;
        var lNumberOfWords_temp1 = lMessageLength + 8;
        var lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
        var lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
        var lWordArray = Array(lNumberOfWords);
        var lBytePosition = 0;
        var lByteCount = 0;
        while (lByteCount < lMessageLength) {
            lWordCount = (lByteCount - (lByteCount % 4)) / 4;
            lBytePosition = (lByteCount % 4) * 8;
            lWordArray[lWordCount] = (lWordArray[lWordCount] | (string.charCodeAt(lByteCount) << lBytePosition));
            lByteCount++;
        }
        lWordCount = (lByteCount - (lByteCount % 4)) / 4;
        lBytePosition = (lByteCount % 4) * 8;
        lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
        lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
        lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
        return lWordArray;
    }
    function WordToHex(lValue) {
        var WordToHexValue = "", WordToHexValue_temp = "", lByte, lCount;
        for (lCount = 0; lCount <= 3; lCount++) {
            lByte = (lValue >>> (lCount * 8)) & 255;
            WordToHexValue_temp = "0" + lByte.toString(16);
            WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length - 2, 2);
        }
        return WordToHexValue;
    }
    function Utf8Encode(string) {
        string = string.replace(/\r\n/g, "\n");
        var utftext = "";
        for (var n = 0; n < string.length; n++) {
            var c = string.charCodeAt(n);
            if (c < 128) {
                utftext += String.fromCharCode(c);
            } else if ((c > 127) && (c < 2048)) {
                utftext += String.fromCharCode((c >> 6) | 192);
                utftext += String.fromCharCode((c & 63) | 128);
            } else {
                utftext += String.fromCharCode((c >> 12) | 224);
                utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                utftext += String.fromCharCode((c & 63) | 128);
            }
        }
        return utftext;
    }
    var x = Array();
    var k, S11, S12, S13, S14, S21, S22, S23, S24, S31, S32, S33, S34, S41, S42, S43, S44;
    var a = 0x67452301; var b = 0xEFCDAB89; var c = 0x98BADCFE; var d = 0x10325476;
    string = Utf8Encode(string);
    x = ConvertToWordArray(string);
    S11 = 7; S12 = 12; S13 = 17; S14 = 22;
    S21 = 5; S22 = 9; S23 = 14; S24 = 20;
    S31 = 4; S32 = 11; S33 = 16; S34 = 23;
    S41 = 6; S42 = 10; S43 = 15; S44 = 21;
    for (k = 0; k < x.length; k += 16) {
        var AA = a; var BB = b; var CC = c; var DD = d;
        a = FF(a, b, c, d, x[k + 0], S11, 0xD76AA478);
        d = FF(d, a, b, c, x[k + 1], S12, 0xE8C7B756);
        c = FF(c, d, a, b, x[k + 2], S13, 0x242070DB);
        b = FF(b, c, d, a, x[k + 3], S14, 0xC1BDCEEE);
        a = FF(a, b, c, d, x[k + 4], S11, 0xF57C0FAF);
        d = FF(d, a, b, c, x[k + 5], S12, 0x4787C62A);
        c = FF(c, d, a, b, x[k + 6], S13, 0xA8304613);
        b = FF(b, c, d, a, x[k + 7], S14, 0xFD469501);
        a = FF(a, b, c, d, x[k + 8], S11, 0x698098D8);
        d = FF(d, a, b, c, x[k + 9], S12, 0x8B44F7AF);
        c = FF(c, d, a, b, x[k + 10], S13, 0xFFFF5BB1);
        b = FF(b, c, d, a, x[k + 11], S14, 0x895CD7BE);
        a = FF(a, b, c, d, x[k + 12], S11, 0x6B901122);
        d = FF(d, a, b, c, x[k + 13], S12, 0xFD987193);
        c = FF(c, d, a, b, x[k + 14], S13, 0xA679438E);
        b = FF(b, c, d, a, x[k + 15], S14, 0x49B40821);
        a = GG(a, b, c, d, x[k + 1], S21, 0xF61E2562);
        d = GG(d, a, b, c, x[k + 6], S22, 0xC040B340);
        c = GG(c, d, a, b, x[k + 11], S23, 0x265E5A51);
        b = GG(b, c, d, a, x[k + 0], S24, 0xE9B6C7AA);
        a = GG(a, b, c, d, x[k + 5], S21, 0xD62F105D);
        d = GG(d, a, b, c, x[k + 10], S22, 0x2441453);
        c = GG(c, d, a, b, x[k + 15], S23, 0xD8A1E681);
        b = GG(b, c, d, a, x[k + 4], S24, 0xE7D3FBC8);
        a = GG(a, b, c, d, x[k + 9], S21, 0x21E1CDE6);
        d = GG(d, a, b, c, x[k + 14], S22, 0xC33707D6);
        c = GG(c, d, a, b, x[k + 3], S23, 0xF4D50D87);
        b = GG(b, c, d, a, x[k + 8], S24, 0x455A14ED);
        a = GG(a, b, c, d, x[k + 13], S21, 0xA9E3E905);
        d = GG(d, a, b, c, x[k + 2], S22, 0xFCEFA3F8);
        c = GG(c, d, a, b, x[k + 7], S23, 0x676F02D9);
        b = GG(b, c, d, a, x[k + 12], S24, 0x8D2A4C8A);
        a = HH(a, b, c, d, x[k + 5], S31, 0xFFFA3942);
        d = HH(d, a, b, c, x[k + 8], S32, 0x8771F681);
        c = HH(c, d, a, b, x[k + 11], S33, 0x6D9D6122);
        b = HH(b, c, d, a, x[k + 14], S34, 0xFDE5380C);
        a = HH(a, b, c, d, x[k + 1], S31, 0xA4BEEA44);
        d = HH(d, a, b, c, x[k + 4], S32, 0x4BDECFA9);
        c = HH(c, d, a, b, x[k + 7], S33, 0xF6BB4B60);
        b = HH(b, c, d, a, x[k + 10], S34, 0xBEBFBC70);
        a = HH(a, b, c, d, x[k + 13], S31, 0x289B7EC6);
        d = HH(d, a, b, c, x[k + 0], S32, 0xEAA127FA);
        c = HH(c, d, a, b, x[k + 3], S33, 0xD4EF3085);
        b = HH(b, c, d, a, x[k + 6], S34, 0x4881D05);
        a = HH(a, b, c, d, x[k + 9], S31, 0xD9D4D039);
        d = HH(d, a, b, c, x[k + 12], S32, 0xE6DB99E5);
        c = HH(c, d, a, b, x[k + 15], S33, 0x1FA27CF8);
        b = HH(b, c, d, a, x[k + 2], S34, 0xC4AC5665);
        a = II(a, b, c, d, x[k + 0], S41, 0xF4292244);
        d = II(d, a, b, c, x[k + 7], S42, 0x432AFF97);
        c = II(c, d, a, b, x[k + 14], S43, 0xAB9423A7);
        b = II(b, c, d, a, x[k + 5], S44, 0xFC93A039);
        a = II(a, b, c, d, x[k + 12], S41, 0x655B59C3);
        d = II(d, a, b, c, x[k + 3], S42, 0x8F0CCC92);
        c = II(c, d, a, b, x[k + 10], S43, 0xFFEFF47D);
        b = II(b, c, d, a, x[k + 1], S44, 0x85845DD1);
        a = II(a, b, c, d, x[k + 8], S41, 0x6FA87E4F);
        d = II(d, a, b, c, x[k + 15], S42, 0xFE2CE6E0);
        c = II(c, d, a, b, x[k + 6], S43, 0xA3014314);
        b = II(b, c, d, a, x[k + 13], S44, 0x4E0811A1);
        a = II(a, b, c, d, x[k + 4], S41, 0xF7537E82);
        d = II(d, a, b, c, x[k + 11], S42, 0xBD3AF235);
        c = II(c, d, a, b, x[k + 2], S43, 0x2AD7D2BB);
        b = II(b, c, d, a, x[k + 9], S44, 0xEB86D391);
        a = AddUnsigned(a, AA); b = AddUnsigned(b, BB); c = AddUnsigned(c, CC); d = AddUnsigned(d, DD);
    }
    var temp = WordToHex(a) + WordToHex(b) + WordToHex(c) + WordToHex(d);
    return temp.toLowerCase();
}

// Application State Management
document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    initForms();
    refreshServerState();
    
    // Auto-refresh server state panel every 4 seconds
    setInterval(refreshServerState, 4000);
});

// 1. Tabs Management
function initTabs() {
    const tabs = document.querySelectorAll(".tab-btn");
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active"));
            document.querySelectorAll(".tab-content").forEach(tc => tc.classList.remove("active"));
            
            tab.classList.add("active");
            const tabId = `tab-${tab.getAttribute("data-tab")}`;
            document.getElementById(tabId).classList.add("active");
        });
    });
}

// 2. Refresh Server Storage State
async function refreshServerState() {
    try {
        const response = await fetch("/api/debug/state");
        if (!response.ok) return;
        const state = await response.json();
        
        // Render Users
        const usersList = document.getElementById("users-list");
        if (state.users.length === 0) {
            usersList.innerHTML = `<div class="empty-state">No users registered yet</div>`;
        } else {
            usersList.innerHTML = state.users.map(u => `
                <div class="state-item">
                    <div class="state-item-header">
                        <span>👤 ID ${u.id}: <strong>${u.username}</strong></span>
                    </div>
                    <div class="state-item-detail">
                        bcrypt hash: ✅ Active <br>
                        digest HA1: MD5("${u.username}:Auth2Prod Realm:...") -> <code>${u.has_digest_ha1 ? 'precalculated' : 'missing'}</code>
                    </div>
                </div>
            `).join("");
        }

        // Render API Keys
        const keysList = document.getElementById("apikeys-list");
        if (state.api_keys.length === 0) {
            keysList.innerHTML = `<div class="empty-state">No API Keys generated</div>`;
        } else {
            keysList.innerHTML = state.api_keys.map(k => `
                <div class="state-item">
                    <div class="state-item-header">
                        <span>🔑 Prefix: <strong>${k.prefix}</strong></span>
                        <span class="badge" style="background:${k.is_active ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)'};color:${k.is_active ? '#10b981' : '#ef4444'};border:1px solid ${k.is_active ? '#10b981' : '#ef4444'}">${k.is_active ? 'Active' : 'Revoked'}</span>
                    </div>
                    <div class="state-item-detail">
                        User: ${k.username} (ID: ${k.user_id})<br>
                        SHA-256 Hash: <code>${k.hashed_key}</code>
                    </div>
                </div>
            `).join("");
        }

        // Render DB Sessions
        const dbSessionsList = document.getElementById("db-sessions-list");
        if (state.db_sessions.length === 0) {
            dbSessionsList.innerHTML = `<div class="empty-state">No active DB sessions</div>`;
        } else {
            dbSessionsList.innerHTML = state.db_sessions.map(s => `
                <div class="state-item">
                    <div class="state-item-header">
                        <span>🍪 ID: <strong>${s.session_id}</strong></span>
                    </div>
                    <div class="state-item-detail">
                        User: ${s.username} (ID: ${s.user_id})<br>
                        Expires: ${new Date(s.expires_at).toLocaleTimeString()}
                    </div>
                </div>
            `).join("");
        }

        // Render In-Memory Sessions
        const memorySessionsList = document.getElementById("memory-sessions-list");
        const memSessionIds = Object.keys(state.in_memory_sessions);
        if (memSessionIds.length === 0) {
            memorySessionsList.innerHTML = `<div class="empty-state">No active in-memory sessions</div>`;
        } else {
            memorySessionsList.innerHTML = memSessionIds.map(sid => {
                const s = state.in_memory_sessions[sid];
                return `
                    <div class="state-item">
                        <div class="state-item-header">
                            <span>🍪 ID: <strong>${sid.substring(0, 12)}...</strong></span>
                        </div>
                        <div class="state-item-detail">
                            User ID: ${s.user_id}<br>
                            Expires: ${new Date(s.expires_at).toLocaleTimeString()}
                        </div>
                    </div>
                `;
            }).join("");
        }
        
    } catch (err) {
        console.error("Error refreshing server state:", err);
    }
}

// 3. Traffic Logs Renderer
function addLogCard({ method, url, requestHeaders, requestBody, responseStatus, responseHeaders, responseBody, explanation, isDigestStep2 = false }) {
    const timeline = document.getElementById("network-timeline");
    const emptyMsg = timeline.querySelector(".empty-network");
    if (emptyMsg) emptyMsg.remove();
    
    // Determine status class
    let statusClass = "status-success";
    if (responseStatus === 401) statusClass = "status-challenge";
    else if (responseStatus >= 400) statusClass = "status-error";
    
    const timestamp = new Date().toLocaleTimeString();
    
    const card = document.createElement("div");
    card.className = "log-card";
    
    // Format objects nicely
    const formatObj = (obj) => {
        if (!obj) return "{}";
        if (typeof obj === "string") {
            try {
                return JSON.stringify(JSON.parse(obj), null, 2);
            } catch {
                return obj;
            }
        }
        return JSON.stringify(obj, null, 2);
    };

    const expClass = responseStatus === 401 ? "log-explain log-explain-digest" : "log-explain";
    
    card.innerHTML = `
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
        <div class="log-grid">
            <div class="log-block">
                <h5>Outgoing Request Headers & Body</h5>
                <div class="log-headers-box"><strong>Headers:</strong>\n${formatObj(requestHeaders)}\n\n<strong>Body:</strong>\n${formatObj(requestBody)}</div>
            </div>
            <div class="log-block">
                <h5>Incoming Response Headers & Body</h5>
                <div class="log-headers-box"><strong>Headers:</strong>\n${formatObj(responseHeaders)}\n\n<strong>Body:</strong>\n${formatObj(responseBody)}</div>
            </div>
        </div>
        <div class="${expClass}">
            <strong>Protocol Analysis:</strong> ${explanation}
        </div>
    `;
    
    // Add to top of timeline
    timeline.insertBefore(card, timeline.firstChild);
}

// 4. Forms & Requests Logic
function initForms() {
    // A. User Registration
    const regForm = document.getElementById("register-form");
    regForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const username = document.getElementById("reg-username").value;
        const password = document.getElementById("reg-password").value;
        
        try {
            const reqBody = { username, password };
            const response = await fetch("/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(reqBody)
            });
            const resBody = await response.json();
            
            // Extract headers
            const resHeaders = {};
            response.headers.forEach((v, k) => resHeaders[k] = v);

            const explanation = `Client sent username and password in plaintext in a JSON POST body. The server received it, hashed the password via bcrypt (for stateless Basic/Session Auth) and computed a precomputed MD5 HA1 hash <code>MD5(${username}:Auth2Prod Realm:${password})</code> for stateless Digest Auth, and saved both to SQLite database.`;

            addLogCard({
                method: "POST",
                url: "/register",
                requestHeaders: { "Content-Type": "application/json" },
                requestBody: reqBody,
                responseStatus: response.status,
                responseHeaders: resHeaders,
                responseBody: resBody,
                explanation: explanation
            });
            
            // Clear inputs
            document.getElementById("reg-username").value = "";
            document.getElementById("reg-password").value = "";
            refreshServerState();
            
        } catch (err) {
            console.error(err);
        }
    });

    // B. Basic Auth Test
    document.getElementById("btn-basic-submit").addEventListener("click", async () => {
        const username = document.getElementById("basic-username").value;
        const password = document.getElementById("basic-password").value;
        
        // Base64 encode credentials
        const creds = b64EncodeUnicode(`${username}:${password}`);
        const reqHeaders = {
            "Authorization": `Basic ${creds}`
        };

        try {
            const response = await fetch("/auth/basic/protected", {
                method: "GET",
                headers: reqHeaders
            });
            const resBody = await response.json();
            const resHeaders = {};
            response.headers.forEach((v, k) => resHeaders[k] = v);

            let explanation = "";
            if (response.status === 200) {
                explanation = `Client encoded credentials <code>"${username}:${password}"</code> into Base64 <code>"${creds}"</code> and sent it in the standard header <code>Authorization: Basic ${creds}</code>. The server parsed this, verified the credentials against the database using bcrypt verification, and granted access.`;
            } else {
                explanation = `Client sent basic authorization token <code>"${creds}"</code>. The server was unable to verify the username/password in the SQLite database, returning a 401 Unauthorized status.`;
            }

            addLogCard({
                method: "GET",
                url: "/auth/basic/protected",
                requestHeaders: reqHeaders,
                requestBody: null,
                responseStatus: response.status,
                responseHeaders: resHeaders,
                responseBody: resBody,
                explanation: explanation
            });
            
        } catch (err) {
            console.error(err);
        }
    });

    // C. Digest Auth Test (Challenge-Response Handshake)
    document.getElementById("btn-digest-submit").addEventListener("click", async () => {
        const username = document.getElementById("digest-username").value;
        const password = document.getElementById("digest-password").value;
        const url = "/auth/digest/protected";

        try {
            // STEP 1: Send Request without credentials
            const step1Response = await fetch(url, { method: "GET" });
            const step1Headers = {};
            step1Response.headers.forEach((v, k) => step1Headers[k] = v);
            const step1Body = await step1Response.json();

            let explanation1 = `Client sent a standard GET request without any authentication headers. The server denied access, returning <strong>401 Unauthorized</strong> along with a <code>WWW-Authenticate: Digest ...</code> header containing a timed cryptographically-signed server <strong>nonce</strong>.`;

            addLogCard({
                method: "GET",
                url: url,
                requestHeaders: {},
                requestBody: null,
                responseStatus: step1Response.status,
                responseHeaders: step1Headers,
                responseBody: step1Body,
                explanation: explanation1
            });

            if (step1Response.status !== 401) {
                return; // Stop if server didn't challenge
            }

            // Extract WWW-Authenticate header params
            const wwwAuth = step1Headers["www-authenticate"];
            const params = parseDigestParams(wwwAuth);
            const nonce = params["nonce"];
            const realm = params["realm"] || "Auth2Prod Realm";
            const qop = params["qop"];

            // Calculate client Digest Auth parameters
            const cnonce = Math.random().toString(36).substring(2, 10); // client nonce
            const nc = "00000001"; // nonce count
            const method = "GET";

            // Computations
            // HA1 = MD5(username:realm:password)
            const ha1 = md5(`${username}:${realm}:${password}`);
            // HA2 = MD5(method:uri)
            const ha2 = md5(`${method}:${url}`);
            
            // Response hash = MD5(HA1:nonce:nc:cnonce:qop:HA2)
            let responseHash = "";
            if (qop === "auth") {
                responseHash = md5(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`);
            } else {
                responseHash = md5(`${ha1}:${nonce}:${ha2}`);
            }

            // Formulate step 2 Auth header
            const digestHeader = `Digest username="${username}", realm="${realm}", nonce="${nonce}", uri="${url}", qop="${qop}", nc=${nc}, cnonce="${cnonce}", response="${responseHash}"`;
            const step2Headers = { "Authorization": digestHeader };

            // STEP 2: Send second request with Computed Response Hash
            const step2Response = await fetch(url, {
                method: "GET",
                headers: step2Headers
            });
            const step2HeadersObj = {};
            step2Response.headers.forEach((v, k) => step2HeadersObj[k] = v);
            const step2Body = await step2Response.json();

            let explanation2 = "";
            if (step2Response.status === 200) {
                explanation2 = `Client computed MD5 hashes locally. <code>HA1 = MD5(${username}:${realm}:${password})</code>, <code>HA2 = MD5(GET:${url})</code>, and client response <code>response = MD5(HA1:${nonce}:${nc}:${cnonce}:auth:HA2)</code>. The client sent this response hash in the second request. The server loaded the precomputed HA1 hash for this user from SQLite, performed the same hash verification locally, and confirmed match. **The plaintext password was never sent over the network!**`;
            } else {
                explanation2 = `Client sent response hash <code>"${responseHash}"</code>, but the server verification failed. This means the password or username was incorrect, or the signed server nonce had expired.`;
            }

            addLogCard({
                method: "GET",
                url: url,
                requestHeaders: step2Headers,
                requestBody: null,
                responseStatus: step2Response.status,
                responseHeaders: step2HeadersObj,
                responseBody: step2Body,
                explanation: explanation2
            });

        } catch (err) {
            console.error(err);
        }
    });

    // D. API Key Generation
    document.getElementById("btn-apikey-generate").addEventListener("click", async () => {
        const username = document.getElementById("apikey-gen-username").value;
        const password = document.getElementById("apikey-gen-password").value;
        
        const creds = b64EncodeUnicode(`${username}:${password}`);
        const reqHeaders = {
            "Authorization": `Basic ${creds}`
        };

        try {
            const response = await fetch("/auth/apikey/generate?description=Visualizer+Key", {
                method: "POST",
                headers: reqHeaders
            });
            const resBody = await response.json();
            const resHeaders = {};
            response.headers.forEach((v, k) => resHeaders[k] = v);

            let explanation = "";
            if (response.status === 200) {
                explanation = `Client authenticated via HTTP Basic Auth. The server generated a secure API Key prefixed with <code>"ap_"</code>, saved a SHA-256 hash of it in SQLite, and returned the raw key <code>${resBody.api_key}</code> to the client. This key is displayed once and cannot be retrieved again from the server.`;
                
                // Show in visualizer box
                const keyBox = document.getElementById("generated-key-container");
                keyBox.classList.remove("hidden");
                document.getElementById("generated-key-value").textContent = resBody.api_key;
                
                // Prefill API Key test input
                document.getElementById("apikey-value").value = resBody.api_key;
            } else {
                explanation = `Server rejected generation request. Basic Authentication failed.`;
            }

            addLogCard({
                method: "POST",
                url: "/auth/apikey/generate",
                requestHeaders: reqHeaders,
                requestBody: null,
                responseStatus: response.status,
                responseHeaders: resHeaders,
                responseBody: resBody,
                explanation: explanation
            });
            
            refreshServerState();

        } catch (err) {
            console.error(err);
        }
    });

    // E. API Key Test
    document.getElementById("btn-apikey-submit").addEventListener("click", async () => {
        const apiKey = document.getElementById("apikey-value").value;
        const reqHeaders = {
            "X-API-Key": apiKey
        };

        try {
            const response = await fetch("/auth/apikey/protected", {
                method: "GET",
                headers: reqHeaders
            });
            const resBody = await response.json();
            const resHeaders = {};
            response.headers.forEach((v, k) => resHeaders[k] = v);

            let explanation = "";
            if (response.status === 200) {
                explanation = `Client sent the API key in the custom header <code>X-API-Key: ${apiKey}</code>. The server computed the SHA-256 hash of the incoming key and matched it against the stored keys in SQLite. Since the record is active, access was granted immediately (stateless check).`;
            } else {
                explanation = `Client sent API Key <code>"${apiKey}"</code>. The server computed the hash but found no active, matching record in the SQLite database, returning 401 Unauthorized.`;
            }

            addLogCard({
                method: "GET",
                url: "/auth/apikey/protected",
                requestHeaders: reqHeaders,
                requestBody: null,
                responseStatus: response.status,
                responseHeaders: resHeaders,
                responseBody: resBody,
                explanation: explanation
            });

        } catch (err) {
            console.error(err);
        }
    });

    // F. Session Login
    document.getElementById("btn-session-login").addEventListener("click", async () => {
        const username = document.getElementById("session-username").value;
        const password = document.getElementById("session-password").value;
        const store_type = document.getElementById("session-store-type").value;
        
        const reqBody = { username, password, store_type };

        try {
            const response = await fetch("/auth/session/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(reqBody)
            });
            const resBody = await response.json();
            const resHeaders = {};
            response.headers.forEach((v, k) => resHeaders[k] = v);

            let explanation = "";
            if (response.status === 200) {
                explanation = `Client logged in. Server validated credentials, generated session ID <code>"${resBody.session_id}"</code>, and stored it in the **${store_type === 'db' ? 'SQLite Database' : 'RAM In-Memory store'}**. The response includes <code>Set-Cookie</code> headers, telling the browser to save the session ID and automatically attach it to future requests.`;
            } else {
                explanation = `Server rejected credentials, session not created.`;
            }

            addLogCard({
                method: "POST",
                url: "/auth/session/login",
                requestHeaders: { "Content-Type": "application/json" },
                requestBody: reqBody,
                responseStatus: response.status,
                responseHeaders: resHeaders,
                responseBody: resBody,
                explanation: explanation
            });
            
            refreshServerState();

        } catch (err) {
            console.error(err);
        }
    });

    // G. Session Protected Route Access
    document.getElementById("btn-session-submit").addEventListener("click", async () => {
        try {
            // First, make the call to the protected route (browser handles cookies automatically)
            const response = await fetch("/auth/session/protected", { method: "GET" });
            const resBody = await response.json();
            const resHeaders = {};
            response.headers.forEach((v, k) => resHeaders[k] = v);

            // To visually prove to the user what cookies the browser sent, let's call the debug echo-headers endpoint!
            const echoResponse = await fetch("/api/debug/echo-headers");
            const echoData = await echoResponse.json();

            let explanation = "";
            if (response.status === 200) {
                const sessionCookie = echoData.cookies["auth2prod_session_id"] || "Not found";
                const storeCookie = echoData.cookies["auth2prod_session_store"] || "memory";
                explanation = `Client requested a protected resource. The browser automatically appended cookies: <code>auth2prod_session_id=${sessionCookie}</code> (using store: ${storeCookie}) in the request. The server read the session ID, queried the active session store (RAM or DB), identified user ID <strong>${resBody.user.id} (${resBody.user.username})</strong>, and successfully authorized the request.`;
            } else {
                explanation = `Client requested resource but the browser did not attach any valid session cookies, or the session has expired on the server. Access Denied.`;
            }

            addLogCard({
                method: "GET",
                url: "/auth/session/protected",
                requestHeaders: { "Browser-Attached-Cookies": echoData.cookies },
                requestBody: null,
                responseStatus: response.status,
                responseHeaders: resHeaders,
                responseBody: resBody,
                explanation: explanation
            });

        } catch (err) {
            console.error(err);
        }
    });

    // H. Session Logout
    document.getElementById("btn-session-logout").addEventListener("click", async () => {
        try {
            const response = await fetch("/auth/session/logout", { method: "POST" });
            const resBody = await response.json();
            const resHeaders = {};
            response.headers.forEach((v, k) => resHeaders[k] = v);

            const explanation = `Client triggered logout. Server received request, deleted the active session token from the session store, and responded with cookies configured to expire immediately, telling the browser to erase them.`;

            addLogCard({
                method: "POST",
                url: "/auth/session/logout",
                requestHeaders: {},
                requestBody: null,
                responseStatus: response.status,
                responseHeaders: resHeaders,
                responseBody: resBody,
                explanation: explanation
            });
            
            refreshServerState();

        } catch (err) {
            console.error(err);
        }
    });

    // I. System Reset
    document.getElementById("reset-db-btn").addEventListener("click", async () => {
        if (!confirm("Are you sure you want to delete all users, API keys, and active sessions?")) return;
        
        try {
            const response = await fetch("/api/debug/reset", { method: "POST" });
            const resBody = await response.json();
            
            // Clear traffic logs
            document.getElementById("network-timeline").innerHTML = `
                <div class="empty-network">System state reset. logs cleared.</div>
            `;
            
            // Hide generated api key container
            document.getElementById("generated-key-container").classList.add("hidden");
            document.getElementById("generated-key-value").textContent = "ap_...";
            
            refreshServerState();
            alert("Database and session store cleared successfully!");
            
        } catch (err) {
            console.error(err);
        }
    });
    
    document.getElementById("clear-logs-btn").addEventListener("click", () => {
        document.getElementById("network-timeline").innerHTML = `
            <div class="empty-network">No network requests sent yet. Use the client controls to trigger requests.</div>
        `;
    });
    
    document.getElementById("refresh-state-btn").addEventListener("click", () => {
        refreshServerState();
    });
}

// Helper to base64 encode Unicode strings
function b64EncodeUnicode(str) {
    return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
        function toSolidBytes(match, p1) {
            return String.fromCharCode('0x' + p1);
    }));
}

// Helper to parse Digest Authentication header values
function parseDigestParams(header) {
    if (!header || !header.startsWith("Digest ")) return {};
    const paramsStr = header.substring(7);
    const pattern = /(\w+)=(?:"([^"]*)"|([^,\s]*))/g;
    const params = {};
    let match;
    while ((match = pattern.exec(paramsStr)) !== null) {
        const key = match[1];
        const val = match[2] !== undefined ? match[2] : match[3];
        params[key] = val;
    }
    return params;
}
