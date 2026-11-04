# Quantum Secure Messenger
### Post-Quantum End-to-End Encrypted Messaging Platform

A secure messaging platform built with **Rust**, **WebAssembly**, **ML-KEM (Kyber)**, **Double Ratchet key evolution**, **HKDF-SHA256**, **AES-256-GCM**, and a **Zero-Knowledge WebSocket Relay Server**.

The system demonstrates a complete post-quantum secure communication workflow where users establish a shared secret using ML-KEM, derive session keys using HKDF, evolve keys through a Double Ratchet mechanism, and exchange authenticated encrypted messages through a relay server that cannot inspect message content.

---

# Project Status

```text
✅ Task 1 – ML-KEM / Kyber Implementation
✅ Task 2 – Double Ratchet + AES-256-GCM
✅ Task 3 – Secure Relay Infrastructure
✅ Task 4 – Browser-Based Secure Messaging UI

✅ PROJECT COMPLETE
```

---

# Quick Start

## Option 1 – One-Click Launch (Recommended)

```text
1. Clone the repository
2. Double-click start.bat
3. Open a second browser window/tab
4. Start messaging
```

The script automatically:

- Starts the relay server
- Starts the local web server
- Opens the application

Open:

```text
http://localhost:8000/web
```

in multiple browser tabs/windows.

Enter any unique usernames and begin secure communication.

---

## Option 2 – Manual Launch

### Start Relay Server

```bash
cargo run --bin server
```

Expected output:

```text
==================================
 Zero-Knowledge Relay Server
 ws://127.0.0.1:8080
==================================
```

### Start Web Server

```bash
python -m http.server 8000
```

### Open Browser

```text
http://localhost:8000/web
```

Open multiple browser windows and use different usernames.

---

# Project Objectives

This project was developed to implement a complete post-quantum secure messaging workflow.

## Task 1

Implement Post-Quantum Key Encapsulation using:

```text
ML-KEM (Kyber)
```

Features:

- Keypair generation
- Public key publication
- Encapsulation
- Decapsulation
- Shared secret establishment
- Browser integration via WebAssembly

---

## Task 2

Implement secure message encryption:

```text
HKDF-SHA256
↓
Double Ratchet
↓
AES-256-GCM
```

Features:

- Session key derivation
- Root key evolution
- Message key evolution
- Forward secrecy
- Authenticated encryption
- Tamper detection

---

## Task 3

Implement secure relay infrastructure:

- Public key discovery
- Zero-knowledge relay
- Offline message queue
- Replay protection
- Rate limiting
- Session restoration

---

## Task 4

Implement browser-based messaging client:

- Real-time communication
- Security dashboard
- Dark mode
- Browser-side cryptography
- Dynamic peer discovery

---

# Features

## Post-Quantum Security

- ML-KEM (Kyber) key generation
- Public key registration
- Dynamic public key discovery
- Secure shared secret establishment
- Browser-based key exchange through WebAssembly

---

## End-to-End Encryption

Messages are protected using:

```text
AES-256-GCM
```

Features:

- Confidentiality
- Integrity
- Authentication
- Nonce-based encryption

---

## Double Ratchet

Every message advances the key state:

```text
K0
 ↓
K1
 ↓
K2
 ↓
K3
```

Provides:

- Forward Secrecy
- Key Evolution
- Message Isolation

---

## Public Key Discovery

Users register ML-KEM public keys with the relay:

```text
User
 ↓
Register Public Key
 ↓
Relay Registry
 ↓
Discoverable by Peers
```

Features:

- Dynamic user lookup
- No hardcoded users
- Automatic peer discovery

---

## Offline Message Queue

Messages are preserved when recipients are offline.

Workflow:

```text
User A sends message
        ↓
Recipient offline
        ↓
Relay stores ciphertext
        ↓
Recipient reconnects
        ↓
Messages delivered
```

---

## Rate Limiting

Relay implements a Token Bucket algorithm.

Current limits:

```text
Burst Capacity: 20 messages
Refill Rate: 5 messages/sec
```

Protects against:

- Spam
- Flood attacks
- Resource exhaustion

---

## Replay Protection

Every encrypted message includes:

```text
Timestamp
Nonce
Sender
```

Replay attempts are detected and rejected.

---

## Session Restoration

Client state is preserved:

```text
Identity
Keys
Ratchet State
Peer Session
Authentication Token
```

Users may reconnect without re-establishing sessions.

---

# Architecture

```text
Browser Client
      │
      ▼

ML-KEM Keypair (WASM)

      │
      ▼

Public Key Discovery

      │
      ▼

ML-KEM Handshake

      │
      ▼

Shared Secret

      │
      ▼

HKDF-SHA256

      │
      ▼

Double Ratchet

      │
      ▼

AES-256-GCM

      │
      ▼

Zero-Knowledge Relay

      │
      ▼

Encrypted Recipient
```

---

# Cryptographic Workflow

## Step 1 — Identity Generation

Browser creates:

```text
ML-KEM Public Key
ML-KEM Private Key
```

Identity is persisted locally.

---

## Step 2 — Public Key Discovery

Peer requests recipient public key.

Relay responds with:

```text
ML-KEM Public Key
```

for the requested user.

---

## Step 3 — Shared Secret Establishment

Sender performs:

```text
Encapsulation(public_key)
```

Receiver performs:

```text
Decapsulation(ciphertext)
```

Both derive:

```text
Shared Secret
```

without transmitting it.

---

## Step 4 — Key Derivation

Shared Secret:

```text
SS
```

↓

```text
HKDF-SHA256
```

↓

```text
Session Key
```

---

## Step 5 — Double Ratchet

For every message:

```text
Current Key
 ↓
Ratchet
 ↓
New Key
```

This limits impact from key compromise.

---

## Step 6 — Encryption

Messages are encrypted with:

```text
AES-256-GCM
```

using unique nonces.

---

# Security Dashboard

The web interface verifies:

```text
✅ Identity Established
✅ Public Key Discovery
✅ ML-KEM Shared Secret
✅ AES-256-GCM Active
✅ Double Ratchet Active
✅ Relay Connected
✅ Encrypted Traffic
✅ Offline Queue Delivery
```

---

# Security Properties

## Confidentiality

Only intended recipients can decrypt messages.

---

## Integrity

AES-GCM authentication tags verify:

```text
Message Authenticity
Message Integrity
```

Tampering causes decryption failure.

---

## Post-Quantum Resistance

Key exchange uses:

```text
ML-KEM (Kyber)
```

designed to resist quantum attacks.

---

## Forward Secrecy

Ratchet evolution ensures:

```text
Current key compromise
≠
Past message compromise
```

---

## Replay Protection

Encrypted payload replay attempts are rejected automatically.

---

## Zero-Knowledge Relay

The relay only sees:

```text
Ciphertext
Nonces
Timestamps
Routing Metadata
Public Keys
```

The relay never sees:

```text
Plaintext
Private Keys
Shared Secrets
Session Keys
Ratchet Keys
```

---

# Threat Model

| Threat | Mitigation |
|----------|------------|
| Quantum Key Recovery | ML-KEM |
| Network Eavesdropping | AES-256-GCM |
| Ciphertext Tampering | Authentication Tags |
| Replay Attacks | Replay Cache |
| Message Flooding | Token Bucket Rate Limiter |
| Offline Delivery Loss | Offline Queue |
| Key Compromise | Double Ratchet |
| Relay Snooping | Zero-Knowledge Architecture |

---

# Project Structure

```text
pqc_messenger/
│
├── .cargo/
│   └── config.toml
│
├── src/
│   ├── lib.rs
│   └── server.rs
│ 
│
├── web/
│   ├── index.html
│   ├── app.js
│   ├── style.css
│   └── pkg/
│
├── Cargo.toml
├── Cargo.lock
├── .gitignore
├── README.md
└── start.bat
```

---

# Technologies Used

## Backend

```text
Rust
Tokio
Tokio-Tungstenite
Serde
Serde JSON
```

### Cryptography

```text
ML-KEM (Kyber)
HKDF-SHA256
AES-256-GCM
Double Ratchet
```

### Frontend

```text
HTML5
CSS3
JavaScript
WebAssembly
wasm-bindgen
```

---

# Testing

## Secure Messaging

1. Open application in multiple browser windows.
2. Register unique usernames.
3. Send encrypted messages.

Expected:

```text
✅ Successful key discovery
✅ ML-KEM handshake
✅ Encrypted communication
```

---

## Offline Queue Test

1. Close one participant.
2. Send messages.
3. Reopen participant.

Expected:

```text
📥 Offline messages delivered
```

---

## Rate Limiting Test

Send messages rapidly.

Expected:

```text
❌ Rate limit exceeded
```

---

## Replay Protection Test

Resubmit previous encrypted payloads.

Expected:

```text
❌ Replay detected
```

---

# Author

**Mohammad Shah**

### Quantum Secure Messenger

Built using:

- ML-KEM (Kyber)
- HKDF-SHA256
- Double Ratchet
- AES-256-GCM
- Rust
- WebAssembly
- Tokio WebSockets

---

# Final Result

```text
✅ Real Post-Quantum Key Exchange
✅ Real Browser-Based ML-KEM
✅ Dynamic Public Key Discovery
✅ Offline Message Delivery
✅ Replay Protection
✅ Rate Limiting
✅ Double Ratchet
✅ AES-256-GCM Encryption
✅ Zero-Knowledge Relay
✅ Real-Time Web Interface

✅ COMPLETE POST-QUANTUM SECURE MESSAGING PLATFORM
```
