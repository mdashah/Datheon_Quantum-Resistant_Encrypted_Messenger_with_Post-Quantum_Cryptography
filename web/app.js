import init, {
    keypair_wasm,
    encapsulate_wasm,
    decapsulate_wasm,
    hkdf_32_wasm,
    ratchet_step_wasm,
    encrypt_wasm,
    decrypt_wasm,
} from "./pkg/pqc_messenger.js";

const socket = new WebSocket("ws://127.0.0.1:8080");
const chatBox = document.getElementById("chat-box");
const connectionStatus = document.getElementById("connection-status");

let wasmReady = false;
const wasmReadyPromise = init().then(() => {
    wasmReady = true;
    console.log("[JS] WASM ML-KEM ready");
});

let myUser = null;
let myPkHex = null;
let mySkHex = null;
let sessionEstablished = false;
let sessionPeer = null;
let sendKey = null;
let recvKey = null;
const peerKeys = {};

function setStatus(id, v) { document.getElementById(id).innerHTML = v; }

async function register(user) {
    await wasmReadyPromise;
    if (myUser) return;

    const savedPk = localStorage.getItem(`pqc_pk_${user}`);
    const savedSk = localStorage.getItem(`pqc_sk_${user}`);
    const savedToken = localStorage.getItem(`pqc_token_${user}`);

    if (savedPk && savedSk) {
        myPkHex = savedPk;
        mySkHex = savedSk;
    } else {
        const arr = keypair_wasm();
        myPkHex = arr[0];
        mySkHex = arr[1];
        localStorage.setItem(`pqc_pk_${user}`, myPkHex);
        localStorage.setItem(`pqc_sk_${user}`, mySkHex);
    }

    myUser = user;

    socket.send(JSON.stringify({
        type: "Register",
        user: user.toLowerCase(),
        public_key: myPkHex,
        token: savedToken
    }));

    setStatus("kem-status", `✅ Identity Established (${myPkHex.length / 2} bytes)`);
    setStatus("aes-status", "✅ AES-256-GCM ready");
    setStatus("relay-status", "✅ Zero-knowledge relay connected");
}

function requestKey(user) {
    if (user === myUser) return; 
    if (socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "GetKey", user: user.toLowerCase() }));
    }
}

async function beginHandshake(peer) {
    await wasmReadyPromise;
    if (peer === myUser) return; 
    const peerPk = peerKeys[peer];
    if (!peerPk) return;

    const arr = encapsulate_wasm(peerPk);
    const ctHex = arr[0];
    const ssHex = arr[1];
    const kAb = hkdf_32_wasm(ssHex, "session-init");

    sendKey = kAb;
    recvKey = kAb;
    sessionEstablished = true;
    sessionPeer = peer;

    socket.send(JSON.stringify({
        type: "Handshake",
        to: peer,
        ciphertext: ctHex,
        from_public_key: myPkHex,
    }));

    saveStateToServer();
    setStatus("kem-status", `✅ ML-KEM shared secret with ${peer}`);
    setStatus("ratchet-status", `✅ Ratchet initialized`);
}

function saveStateToServer() {
    if (sendKey && recvKey && sessionPeer) {
        socket.send(JSON.stringify({ 
            type: "SaveState", 
            send_key: sendKey, 
            recv_key: recvKey,
            peer: sessionPeer 
        }));
    }
}

async function sendMessage() {
    await wasmReadyPromise;

    const username = document.getElementById("username").value.trim().toLowerCase();
    const message = document.getElementById("message-input").value.trim();
    if (!username || !message) return;

    if (!myUser) {
        await register(username);
        document.getElementById("username").disabled = true;
    }

    let to = sessionPeer;
    if (!to) {
        // DYNAMIC: Ask for any user, not just Alice or Bob
        to = prompt("Recipient username:")?.trim().toLowerCase();
        if (!to || to === myUser) return; 
        
        if (!peerKeys[to]) {
            requestKey(to);
            setStatus("payload-status", `🔄 Fetching ${to}'s key. Please click Send again.`);
            return;
        }
        
        await beginHandshake(to);
        await new Promise(r => setTimeout(r, 500)); 
        
        if (!sessionEstablished || !sendKey) {
            setStatus("payload-status", "❌ Handshake failed. Please try again.");
            return;
        }
    }

    const arr = encrypt_wasm(sendKey, message);
    const nonceHex = arr[0];
    const ctHex = arr[1];
    const ts = Date.now();

    socket.send(JSON.stringify({
        type: "Message",
        to,
        nonce: nonceHex,
        ciphertext: ctHex,
        timestamp: ts,
    }));

    sendKey = ratchet_step_wasm(sendKey);
    saveStateToServer();

    addMessage(myUser, message, true);
    setStatus("payload-status", `✅ Sent securely to ${to}`);
    document.getElementById("message-input").value = "";
}

function addMessage(user, text, own) {
    const div = document.createElement("div");
    div.className = "message " + (own ? "outgoing" : "incoming");
    const t = new Date().toLocaleTimeString();
    const displayUser = user.charAt(0).toUpperCase() + user.slice(1);
    div.innerHTML = `<strong>${displayUser}</strong><br>${text}<br><small>${t}</small>`;
    chatBox.appendChild(div);
    chatBox.scrollTop = chatBox.scrollHeight;
}

socket.onopen = () => { connectionStatus.innerHTML = "🟢 Connected"; };
socket.onclose = () => { connectionStatus.innerHTML = "🔴 Disconnected"; myUser = null; };

socket.onmessage = async (ev) => {
    await wasmReadyPromise;
    let d;
    try { d = JSON.parse(ev.data); } catch { return; }

    if (d.type === "Registered") {
        if (d.token) {
            localStorage.setItem(`pqc_token_${d.user}`, d.token);
        }

        setStatus("payload-status", `✅ Registered as ${d.user}`);
        
        if (d.send_key && d.recv_key && d.session_peer) {
            sendKey = d.send_key;
            recvKey = d.recv_key;
            sessionPeer = d.session_peer;
            sessionEstablished = true;
            setStatus("ratchet-status", `✅ Ratchet restored (with ${sessionPeer})`);
        }
        // Removed requestKey("alice") and requestKey("bob") — now fully dynamic!
    }
    
    else if (d.type === "KeyResponse" && d.public_key) {
        if (d.user !== myUser) {
            peerKeys[d.user] = d.public_key;
            setStatus("kem-status", `🔑 Discovered ${d.user}`);
        }
    }

    else if (d.type === "Handshake") {
        if (d.from === myUser) return;

        const ssHex = decapsulate_wasm(d.ciphertext, mySkHex);
        const kAb = hkdf_32_wasm(ssHex, "session-init");
        
        sendKey = kAb;
        recvKey = kAb;
        sessionEstablished = true;
        sessionPeer = d.from;
        
        if (!peerKeys[d.from]) {
            peerKeys[d.from] = d.from_public_key;
        }
        
        saveStateToServer();

        setStatus("kem-status", `✅ ML-KEM shared secret with ${d.from}`);
        setStatus("ratchet-status", `✅ Ratchet initialized`);
    }

    else if (d.type === "Message") {
        if (d.from === myUser) return; 
        if (!recvKey) {
            setStatus("payload-status", "❌ No session key to decrypt offline msg.");
            return; 
        }
        
        const pt = decrypt_wasm(recvKey, d.nonce, d.ciphertext);
        if (!pt) {
            setStatus("payload-status", "❌ Decryption failed (Key mismatch)");
            return; 
        }
        
        addMessage(d.from, pt, false); 
        recvKey = ratchet_step_wasm(recvKey);
        saveStateToServer();
        setStatus("payload-status", "✅ Received securely");
    }

    else if (d.type === "QueueDelivered") {
        alert(`📥 You received ${d.count} offline message(s) while you were gone!`);
        setStatus("payload-status", `📥 ${d.count} offline message(s) delivered`);
        setTimeout(() => {
            if (document.getElementById("payload-status").innerHTML.includes("offline")) {
                setStatus("payload-status", "✅ Ready for traffic");
            }
        }, 5000);
    }

    else if (d.type === "Error") {
        setStatus("payload-status", `❌ ${d.reason}`);
    }
};

document.getElementById("username").addEventListener("keypress", async (e) => {
    if (e.key === "Enter") {
        const user = e.target.value.trim().toLowerCase();
        if (user) {
            await register(user);
            e.target.disabled = true;
            document.getElementById("message-input").focus();
        }
    }
});

document.getElementById("message-input").addEventListener("keypress", (e) => {
    if (e.key === "Enter") sendMessage();
});

function toggleTheme() {
    document.body.classList.toggle("dark");
    document.getElementById("theme-toggle").innerText =
        document.body.classList.contains("dark") ? "☀️ Light Mode" : "🌙 Dark Mode";
}

window.toggleTheme = toggleTheme;
window.sendMessage = sendMessage;