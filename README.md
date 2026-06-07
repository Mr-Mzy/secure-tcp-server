# Secure Multiprocessor TCP Server

A production-grade TCP application server written in C, featuring TLS encryption, Argon2id password hashing, session management, replay attack prevention, and persistent audit logging.

---

## Features

| Feature | Implementation |
|---------|---------------|
| **TLS 1.2+ encryption** | OpenSSL — all traffic encrypted |
| **Argon2id password hashing** | libsodium — memory-hard, salted |
| **Session tokens** | 32-char cryptographic random hex |
| **Replay attack prevention** | Per-request one-time nonces |
| **Brute-force lockout** | IP-persistent — survives reconnection |
| **Rate limiting** | IP-persistent — survives reconnection |
| **Multiprocessing** | fork() — one child per client |
| **Zombie prevention** | SIGCHLD + waitpid() |
| **Audit logging** | Timestamp, IP, PID, user, command, result |
| **Input validation** | Alphanumeric-only usernames |
| **Payload protection** | 4096-byte hard limit |

---

## Project Structure

```
├── server.c          # C server — TLS, fork, auth, logging
├── client.py         # Python client — TLS, auto-framing, nonces
├── Makefile          # Build system
├── THREAT_MODEL.md   # Full threat model — 9 attack scenarios
└── server.log        # Audit log (generated at runtime)
```

---

## Quick Start

### 1. Install dependencies
```bash
sudo apt install libssl-dev libsodium-dev
```

### 2. Generate TLS certificate
```bash
make cert
```

### 3. Create data directory
```bash
sudo mkdir -p /srv/secserver/users
sudo chmod -R 777 /srv/secserver
```

### 4. Build and run server
```bash
make
./server
```

### 5. Connect with client
```bash
python3 client.py
```

---

## Protocol

All messages use explicit length-prefixed framing:
```
LEN:<n>\n<payload>
```
`<n>` is the exact byte count of the payload. The client generates this automatically — the user never types it.

### Commands

| Command | Auth required | Description |
|---------|--------------|-------------|
| `REGISTER <user> <pass>` | No | Create account |
| `LOGIN <user> <pass>` | No | Authenticate — returns TOKEN |
| `LOGOUT` | No | End session |
| `<CMD> TOKEN:<token> <nonce>` | Yes | Protected command |

### Response format
```
OK <code> SID:<id> <message>
ERR <code> SID:<id> <message>
```

---

## Security Design

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full threat model covering 9 attack scenarios and mitigations.

**Key design decisions:**
- **Argon2id over bcrypt** — memory-hard algorithm resists GPU cracking better
- **IP-persistent rate limiting** — reconnecting cannot bypass the rate limiter or lockout
- **Per-request nonces** — stolen tokens cannot be replayed even within the TTL window
- **TLS minimum 1.2** — older insecure versions explicitly disabled

---

## Audit Log Sample

```
2026-04-11 14:32:01 | 127.0.0.1:54321 | PID:1001 | USER:NONE  | CMD:REGISTER | OK
2026-04-11 14:32:10 | 127.0.0.1:54321 | PID:1001 | USER:alice | CMD:LOGIN    | OK
2026-04-11 14:32:15 | 127.0.0.1:54322 | PID:1002 | USER:NONE  | CMD:LOGIN    | ERR:wrong password
2026-04-11 14:32:30 | 127.0.0.1:54322 | PID:1002 | USER:NONE  | CMD:LOGIN    | ERR:locked
2026-04-11 14:32:45 | 127.0.0.1:54321 | PID:1001 | USER:alice | CMD:LOGOUT   | OK
```

---

## Dependencies

- `gcc`
- `libssl-dev` (OpenSSL)
- `libsodium-dev`
