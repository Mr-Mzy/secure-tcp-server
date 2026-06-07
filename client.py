#!/usr/bin/env python3
"""
Secure TCP Client
TLS encrypted, auto LEN-framing, nonce-based replay prevention
"""

import socket
import ssl
import sys
import secrets

HOST = "127.0.0.1"
PORT = 55000

def create_tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

# Auto-generates LEN:<n> frame before sending
def send_message(tls_sock, payload: str) -> str:
    encoded = payload.encode()
    n       = len(encoded)
    header  = f"LEN:{n}\n".encode()
    frame   = header + encoded
    print(f"[frame]  LEN:{n} | payload: {payload}")
    tls_sock.sendall(frame)
    response = b""
    while True:
        chunk = tls_sock.recv(4096)
        if not chunk:
            break
        response += chunk
        if response.endswith(b"\n"):
            break
    return response.decode().strip()

def interactive_session(tls_sock):
    print(f"[TLS] Connected securely to {HOST}:{PORT}")
    print("Commands: REGISTER <user> <pass> | LOGIN <user> <pass> | LOGOUT | quit")
    print("-" * 60)

    session_token = None

    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nDisconnecting.")
            break

        if not line:
            continue
        if line.lower() == "quit":
            print("Goodbye.")
            break
        if len(line.encode()) > 4096:
            print("[client] Payload too large (>4096 bytes), not sent.")
            continue

        cmd = line.split()[0].upper()

        # Auto-attach token and nonce for protected commands
        if cmd not in ("REGISTER", "LOGIN", "LOGOUT") and session_token:
            nonce = secrets.token_hex(16)
            line  = f"{line} TOKEN:{session_token} {nonce}"
            print(f"[nonce]  {nonce}")

        try:
            reply = send_message(tls_sock, line)
            print(f"[server] {reply}")

            # Store token automatically on login
            if "TOKEN:" in reply and "OK" in reply:
                session_token = reply.split("TOKEN:")[1].split()[0]
                print(f"[token]  stored automatically")

            # Clear token on logout
            if cmd == "LOGOUT" and "OK" in reply:
                session_token = None
                print("[token]  cleared")

        except Exception as e:
            print(f"[error] {e}")
            break

def main():
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT

    try:
        raw_sock = socket.create_connection((host, port))
    except ConnectionRefusedError:
        print(f"[error] Cannot connect to {host}:{port} — is the server running?")
        sys.exit(1)

    ctx      = create_tls_context()
    tls_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
    print(f"[TLS] Cipher: {tls_sock.cipher()[0]}  Protocol: {tls_sock.version()}")

    with tls_sock:
        interactive_session(tls_sock)

if __name__ == "__main__":
    main()
