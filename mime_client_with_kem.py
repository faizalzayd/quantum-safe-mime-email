"""
mime_client_with_kem.py

Quantum-Safe MIME Email Client
================================
Command-line client for sending and receiving emails via the
MIMEServerWithKEM TCP server.

Every connection begins with a fresh McEliece KEM handshake that establishes
an ephemeral AES-256-CBC session key before any email data is transmitted.

Usage
-----
# Send an email (with optional attachment)
python3 mime_client_with_kem.py send \\
    --from alice@localhost \\
    --to   bob@localhost   \\
    --subject "Quantum-Safe Hello" \\
    --body "Protected by McEliece KEM!" \\
    --attach ./report.pdf

# List inbox headers
python3 mime_client_with_kem.py list --user bob

# Download and display full emails
python3 mime_client_with_kem.py receive --user bob

Environment variables (must match the server):
  KEM_Q, KEM_K, KEM_T   (defaults: 5, 45, 15)
  MIME_HOST              (default: localhost)
  MIME_PORT              (default: 8025)
"""

import argparse
import os
import pickle
import socket
import struct
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from kem.client              import KEMClient
from mime_utils.email_builder import build_mime_message
from mime_utils.email_parser  import parse_mime_message, summarise
from mime_utils.attachment_handler import AttachmentHandler

# ── Configuration ──────────────────────────────────────────────────────────────
HOST = os.environ.get("MIME_HOST", "localhost")
PORT = int(os.environ.get("MIME_PORT", 8025))

# Ensure local directories exist
os.makedirs("received_files", exist_ok=True)
os.makedirs("temp_files",     exist_ok=True)


# ── AES-256-CBC helpers (mirrors server) ──────────────────────────────────────

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(16)
    padded = _pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return iv + enc.update(padded) + enc.finalize()


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    iv, ciphertext = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    return _pkcs7_unpad(padded)


def _pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    pad_len = block - (len(data) % block)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


# ── Wire protocol helpers (mirrors server) ────────────────────────────────────

def send_bytes(sock: socket.socket, data: bytes) -> None:
    size_field = struct.pack(">Q", len(data)).ljust(16, b"\x00")
    sock.sendall(size_field + data)


def recv_bytes(sock: socket.socket) -> bytes:
    size_field = _recv_exact(sock, 16)
    length = struct.unpack(">Q", size_field[:8])[0]
    return _recv_exact(sock, length)


def recv_line(sock: socket.socket) -> str:
    buf = b""
    while not buf.endswith(b"\n"):
        ch = sock.recv(1)
        if not ch:
            return buf.decode().strip()
        buf += ch
    return buf.decode().strip()


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly.")
        buf += chunk
    return buf


# ── Connection factory ─────────────────────────────────────────────────────────

def connect_and_handshake() -> tuple[socket.socket, bytes]:
    """
    Open a TCP connection to the server, perform the KEM handshake, and
    return (sock, session_key).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    kc = KEMClient()
    session_key = kc.perform_handshake(sock)
    print(f"[client] KEM handshake complete — session key established.")
    return sock, session_key


# ── SEND ───────────────────────────────────────────────────────────────────────

def cmd_send(
    from_addr:   str,
    to_addr:     str,
    subject:     str,
    body:        str,
    attachments: list[str],
) -> None:
    """
    SEND flow (§5.2):
      1. Build MIME message.
      2. Connect + KEM handshake → session key S1.
      3. Encrypt payload {recipient, mime_bytes} under S1.
      4. Send command SEND + encrypted payload.
      5. Wait for OK acknowledgement.
    """
    # Step 1: Build MIME
    mime_bytes = build_mime_message(from_addr, to_addr, subject, body, attachments)

    # Step 2: Connect + handshake
    sock, session_key = connect_and_handshake()

    try:
        # Step 3: Build + encrypt payload
        payload = pickle.dumps({"recipient": _user_from_addr(to_addr),
                                "mime_bytes": mime_bytes})
        encrypted_payload = aes_encrypt(session_key, payload)

        # Step 4: Send command then encrypted payload
        sock.sendall(b"SEND\n")
        send_bytes(sock, encrypted_payload)

        # Step 5: Wait for OK
        response = recv_line(sock)
        if response == "OK":
            print(f"[client] Email sent successfully to {to_addr}.")
        else:
            print(f"[client] Server response: {response}", file=sys.stderr)
    finally:
        sock.close()


# ── RECV ───────────────────────────────────────────────────────────────────────

def cmd_receive(username: str) -> None:
    """
    RECV flow (§5.3):
      1. Connect + KEM handshake → session key S2.
      2. Send RECV <username>.
      3. Read email count; if 0, done.
      4. Receive encrypted bundle list.
      5. Decrypt each bundle: unwrap storage key K, decrypt MIME, parse + display.
      6. Save attachments locally.
    """
    sock, session_key = connect_and_handshake()
    attachment_handler = AttachmentHandler()

    try:
        sock.sendall(f"RECV {username}\n".encode())

        # Step 3: Read count
        count_data = _recv_exact(sock, 4)
        count = struct.unpack(">I", count_data)[0]

        if count == 0:
            print(f"[client] No emails for '{username}'.")
            return

        # Step 4: Receive bundle
        encrypted_bundle = recv_bytes(sock)
        raw = aes_decrypt(session_key, encrypted_bundle)
        bundles = pickle.loads(raw)

        print(f"\n[client] Received {len(bundles)} email(s) for '{username}':\n")
        print("=" * 60)

        for i, bundle in enumerate(bundles, 1):
            # Step 5a: Unwrap storage key
            storage_key = aes_decrypt(session_key, bundle["wrapped_key"])
            # Step 5b: Decrypt MIME
            mime_bytes = aes_decrypt(storage_key, bundle["encrypted_content"])
            # Step 5c: Parse + display
            parsed = parse_mime_message(mime_bytes)
            print(f"\n--- Email {i} ---")
            print(summarise(parsed))

            # Step 6: Save attachments
            if parsed.get("attachments"):
                saved = attachment_handler.save_attachments(username, parsed["attachments"])
                for path in saved:
                    print(f"  [attachment saved] {path}")

            print("=" * 60)

    finally:
        sock.close()


# ── LIST ───────────────────────────────────────────────────────────────────────

def cmd_list(username: str) -> None:
    """
    LIST flow (§5.4):
      1. Connect + KEM handshake → session key S.
      2. Send LIST <username>.
      3. Receive + decrypt metadata list.
      4. Print inbox summary.
    """
    sock, session_key = connect_and_handshake()

    try:
        sock.sendall(f"LIST {username}\n".encode())

        encrypted_data = recv_bytes(sock)
        raw = aes_decrypt(session_key, encrypted_data)
        summary = pickle.loads(raw)

        if not summary:
            print(f"[client] Inbox for '{username}' is empty.")
            return

        print(f"\n[client] Inbox for '{username}' ({len(summary)} message(s)):\n")
        print(f"{'#':<4} {'Read':<6} {'Att':<5} {'From':<25} {'Subject':<35} Date")
        print("-" * 100)
        for idx, m in enumerate(summary, 1):
            read_str = "Yes" if m["read"] else "No"
            att_str  = "Yes" if m.get("has_attachment") else "No"
            print(
                f"{idx:<4} {read_str:<6} {att_str:<5} "
                f"{m['from'][:23]:<25} {m['subject'][:33]:<35} {m['date']}"
            )
    finally:
        sock.close()


# ── Utilities ──────────────────────────────────────────────────────────────────

def _user_from_addr(addr: str) -> str:
    """Extract the username from an email address (part before @)."""
    return addr.split("@")[0]


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Quantum-Safe MIME Email Client (McEliece KEM)"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # send
    send_parser = subparsers.add_parser("send", help="Send an email")
    send_parser.add_argument("--from",    dest="from_addr", required=True,
                             help="Sender address (e.g. alice@localhost)")
    send_parser.add_argument("--to",      dest="to_addr",   required=True,
                             help="Recipient address (e.g. bob@localhost)")
    send_parser.add_argument("--subject", required=True)
    send_parser.add_argument("--body",    required=True)
    send_parser.add_argument("--attach",  dest="attachments", nargs="*", default=[],
                             metavar="FILE", help="Files to attach")

    # receive
    recv_parser = subparsers.add_parser("receive", help="Download emails")
    recv_parser.add_argument("--user", required=True, help="Username to receive for")

    # list
    list_parser = subparsers.add_parser("list", help="List inbox headers")
    list_parser.add_argument("--user", required=True, help="Username to list for")

    args = parser.parse_args()

    if args.command == "send":
        cmd_send(
            from_addr=args.from_addr,
            to_addr=args.to_addr,
            subject=args.subject,
            body=args.body,
            attachments=args.attachments,
        )
    elif args.command == "receive":
        cmd_receive(args.user)
    elif args.command == "list":
        cmd_list(args.user)


if __name__ == "__main__":
    main()
