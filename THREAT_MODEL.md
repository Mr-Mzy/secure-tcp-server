# Threat Model — Secure TCP Application Server

---

## 1. System Overview

A multiprocessor TCP server written in C that handles authenticated client sessions over TLS. Each client is handled by a forked child process. The server supports user registration, login with Argon2id-hashed passwords, session token management, and protected commands with replay prevention.

---

## 2. Assets

| Asset | Description |
|-------|-------------|
| User passwords | Stored as Argon2id hashes — never plaintext |
| Session tokens | 32-char cryptographic random hex, memory-only, TTL 300s |
| User data directory | `/srv/secserver/<username>/` |
| Audit log | `server.log` |
| TLS private key | `server.key` — must be kept secret |

---

## 3. Threat Actors

| Actor | Capability | Goal |
|-------|-----------|------|
| Network eavesdropper | Passive — reads TCP traffic | Steal credentials or tokens |
| Brute-force attacker | Active — many LOGIN attempts | Guess passwords |
| Replay attacker | Captures and resends valid requests | Reuse a stolen token |
| DoS attacker | Floods server with requests | Exhaust server resources |
| Path traversal attacker | Crafts malicious usernames | Escape data directory |
| Insider | File system read access | Read stored password hashes |

---

## 4. Threats and Mitigations

### T1 — Eavesdropping
**Attack:** Attacker captures TCP traffic and reads plaintext credentials.
**Mitigation:** TLS 1.2+ encrypts all communication — nothing readable on the wire.
**Status:** ✅ Mitigated

---

### T2 — Password Cracking (offline)
**Attack:** Attacker reads `.rec` files and tries to reverse stored hashes.
**Mitigation:** Argon2id via libsodium (`crypto_pwhash_str`) — memory-hard, salted, tunable cost. GPU cracking is extremely expensive compared to SHA-256.
**Status:** ✅ Mitigated

---

### T3 — Brute Force Login
**Attack:** Attacker floods LOGIN attempts with different passwords.
**Mitigation:** 3 failed attempts locks the IP for 60 seconds. Lockout is tracked per IP and **persists across reconnections** — a new connection does not reset the counter.
**Status:** ✅ Mitigated

---

### T4 — Replay Attack
**Attack:** Attacker captures a valid authenticated request and resends it to execute it again.
**Mitigation:** Every protected command requires a one-time nonce (random 32 hex chars). Server stores seen nonces and rejects any duplicate — even if the session token is still valid.
**Status:** ✅ Mitigated

---

### T5 — Denial of Service (flooding)
**Attack:** Attacker floods the server to exhaust resources.
**Mitigation:** Max 10 requests per 10-second window per IP. Rate limit **persists across reconnects** — reconnecting does not reset the counter.
**Status:** ✅ Mitigated

---

### T6 — Path Traversal via Username
**Attack:** Username like `../../etc/passwd` used to write outside the data directory.
**Mitigation:** `valid_username()` enforces alphanumeric-only characters. Rejected before any file operation.
**Status:** ✅ Mitigated

---

### T7 — Buffer Overflow via Oversized Payload
**Attack:** Client sends huge payload to overflow server buffers.
**Mitigation:** Payloads over 4096 bytes rejected at the framing layer before reading into memory.
**Status:** ✅ Mitigated

---

### T8 — Session Hijacking
**Attack:** Attacker steals a token and uses it to impersonate a user.
**Mitigation:** Tokens transmitted only over TLS. Tokens expire after 300s inactivity. Nonce requirement means a stolen token alone is insufficient — a fresh nonce is required per request.
**Status:** ✅ Mitigated

---

### T9 — Zombie Process Accumulation
**Attack:** Uncleaned child processes fill the OS process table.
**Mitigation:** SIGCHLD handler calls `waitpid(-1, NULL, WNOHANG)` in a loop to reap all finished children immediately.
**Status:** ✅ Mitigated

---

## 5. Residual Risks

| Risk | Recommendation |
|------|---------------|
| Self-signed TLS certificate | Use CA-signed cert in production |
| Nonce store is in-memory | Persist to Redis/SQLite to survive restarts |
| IP table is in-memory | Persist to survive restarts |
| No mutual TLS | Add client certificates for high-security deployments |
| Log file not tamper-evident | Forward logs to remote syslog |

---

## 6. Security Properties Summary

| Property | Implementation |
|----------|---------------|
| Confidentiality | TLS 1.2+ |
| Integrity | TLS MAC |
| Authentication | Argon2id hashing + session tokens |
| Non-repudiation | Persistent audit log |
| Availability | Rate limiting + brute-force lockout |
| Least privilege | Isolated child process per client |
