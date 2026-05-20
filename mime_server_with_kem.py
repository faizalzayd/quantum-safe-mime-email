"""
mime_server_with_kem.py

Quantum-Safe MIME Email Server
================================
TCP server implementing the store-and-forward email protocol described in
§5 of the project report.  Every client connection begins with a fresh
McEliece KEM handshake that establishes an ephemeral AES-256-CBC session key;
no long-term symmetric secrets are reused across connections.

Supported commands (sent by the client after the handshake):
  SEND    – store an encrypted email in the recipient's mailbox
  RECV    – retrieve and deliver all emails for a user
  LIST    – return inbox header summaries for a user

Environment variables (KEM parameters — must match the client):
  KEM_Q   (default 5)
  KEM_K   (default 45)
  KEM_T   (default 15)

Usage:
  python3 mime_server_with_kem.py
"""

import os
import pickle
import socket
import struct
import threading

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from kem.server              import KEMServer
from mailbox_manager         import MailboxManager
from mime_utils.email_parser import parse_mime_message
from mime_utils.attachment_handler import AttachmentHandler

# ── Configuration ──────────────────────────────────────────────────────────────
HOST    = "0.0.0.0"
PORT    = int(os.environ.get("MIME_PORT", 8025))
KEM_Q   = int(os.environ.get("KEM_Q", 5))
KEM_K   = int(os.environ.get("KEM_K", 45))
KEM_T   = int(os.environ.get("KEM_T", 15))

# Ensure required directories exist at startup
os.makedirs("mailbox",        exist_ok=True)
os.makedirs("received_files", exist_ok=True)
os.makedirs("temp_files",     exist_ok=True)


# ── AES-256-CBC helpers ────────────────────────────────────────────────────────

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt *plaintext* with AES-256-CBC under *key*.
    Returns IV (16 bytes) + ciphertext.
    """
    iv = os.urandom(16)
    padded = _pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return iv + enc.update(padded) + enc.finalize()


def aes_decrypt(key: bytes, data: bytes) -> bytes:
    """Decrypt AES-256-CBC data (IV prepended)."""
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


# ── Wire protocol helpers ──────────────────────────────────────────────────────

def send_bytes(conn: socket.socket, data: bytes) -> None:
    """Send a 16-byte size-prefixed blob."""
    size_field = struct.pack(">Q", len(data)).ljust(16, b"\x00")
    conn.sendall(size_field + data)


def recv_bytes(conn: socket.socket) -> bytes:
    """Receive a 16-byte size-prefixed blob."""
    size_field = _recv_exact(conn, 16)
    length = struct.unpack(">Q", size_field[:8])[0]
    return _recv_exact(conn, length)


def recv_command(conn: socket.socket) -> str:
    """Receive a plain-text command line (newline-terminated, max 256 bytes)."""
    buf = b""
    while not buf.endswith(b"\n"):
        ch = conn.recv(1)
        if not ch:
            return ""
        buf += ch
        if len(buf) > 256:
            break
    return buf.decode().strip()


def send_ok(conn: socket.socket) -> None:
    conn.sendall(b"OK\n")


def send_err(conn: socket.socket, msg: str) -> None:
    conn.sendall(f"ERR {msg}\n".encode())


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly.")
        buf += chunk
    return buf


# ── Server class ───────────────────────────────────────────────────────────────

class MIMEServerWithKEM:
    """
    TCP server that handles one command per connection, always preceded by a
    fresh McEliece KEM handshake.
    """

    def __init__(self):
        self.mailbox    = MailboxManager()
        self.attachment = AttachmentHandler()
        self.kem_params = (KEM_Q, KEM_K, KEM_T)

    # ── Connection handler ────────────────────────────────────────────────────

    def handle_client(self, conn: socket.socket, addr: tuple) -> None:
        print(f"[server] Connection from {addr}")
        try:
            # ── KEM handshake ──────────────────────────────────────────────
            ks = KEMServer(q=KEM_Q, k=KEM_K, t=KEM_T)
            session_key = ks.perform_handshake(conn)
            print(f"[server] KEM handshake complete for {addr}")

            # ── Command dispatch ───────────────────────────────────────────
            cmd_line = recv_command(conn)
            if not cmd_line:
                return

            parts = cmd_line.split(maxsplit=1)
            command = parts[0].upper()
            arg     = parts[1] if len(parts) > 1 else ""

            if command == "SEND":
                self._handle_send(conn, session_key)
            elif command == "RECV":
                self._handle_recv(conn, session_key, username=arg)
            elif command == "LIST":
                self._handle_list(conn, session_key, username=arg)
            else:
                send_err(conn, f"Unknown command: {command}")

        except Exception as exc:
            print(f"[server] Error handling {addr}: {exc}")
        finally:
            conn.close()

    # ── SEND ──────────────────────────────────────────────────────────────────

    def _handle_send(self, conn: socket.socket, session_key: bytes) -> None:
        """
        SEND flow (§5.2):
          1. Receive AES-encrypted payload containing {recipient, mime_bytes}.
          2. Decrypt with session key S1.
          3. Generate per-email storage key K.
          4. Re-encrypt MIME bytes under K.
          5. Store to mailbox.
          6. Extract attachments.
          7. Acknowledge with OK.
        """
        # Step 1-2: Receive + decrypt payload
        encrypted_payload = recv_bytes(conn)
        raw_payload = aes_decrypt(session_key, encrypted_payload)
        payload = pickle.loads(raw_payload)

        recipient  = payload["recipient"]
        mime_bytes = payload["mime_bytes"]

        # Step 3: Parse MIME for metadata
        parsed = parse_mime_message(mime_bytes)

        # Step 4: Generate storage key K and re-encrypt
        storage_key       = os.urandom(32)
        encrypted_content = aes_encrypt(storage_key, mime_bytes)

        # Step 5: Persist to mailbox
        self.mailbox.store_email(
            username=recipient,
            encrypted_content=encrypted_content,
            storage_key=storage_key,
            from_addr=parsed.get("from", ""),
            subject=parsed.get("subject", ""),
            date=parsed.get("date", ""),
            has_attachment=bool(parsed.get("attachments")),
        )

        # Step 6: Save attachments (server-side copy in received_files/)
        if parsed.get("attachments"):
            self.attachment.save_attachments(recipient, parsed["attachments"])

        # Step 7: Acknowledge
        send_ok(conn)
        print(f"[server] Stored email for '{recipient}' "
              f"from '{parsed.get('from', '?')}' — "
              f"subject: '{parsed.get('subject', '')}'")

    # ── RECV ──────────────────────────────────────────────────────────────────

    def _handle_recv(
        self,
        conn:        socket.socket,
        session_key: bytes,
        username:    str,
    ) -> None:
        """
        RECV flow (§5.3):
          1. Retrieve all emails from mailbox.
          2. For each email, bundle: encrypted content + metadata + K encrypted under S2.
          3. Send count, then pickled+encrypted bundle list.
          4. Mark emails as read.
        """
        emails = self.mailbox.get_all_emails(username)

        # Send count first
        count_data = struct.pack(">I", len(emails))
        conn.sendall(count_data)

        if not emails:
            return

        bundles = []
        for record in emails:
            # Re-encrypt the storage key under the current session key S2
            wrapped_key = aes_encrypt(session_key, record["storage_key"])
            bundles.append({
                "metadata":          record["metadata"],
                "encrypted_content": record["encrypted_content"],
                "wrapped_key":       wrapped_key,
            })

        # Pickle all bundles, encrypt, send
        raw     = pickle.dumps(bundles)
        payload = aes_encrypt(session_key, raw)
        send_bytes(conn, payload)

        # Mark all as read
        for record in emails:
            self.mailbox.mark_read(username, record["metadata"]["id"])

        print(f"[server] Delivered {len(emails)} email(s) to '{username}'")

    # ── LIST ──────────────────────────────────────────────────────────────────

    def _handle_list(
        self,
        conn:        socket.socket,
        session_key: bytes,
        username:    str,
    ) -> None:
        """
        LIST flow (§5.4):
          Return lightweight metadata list (id, from, subject, date, read,
          has_attachment) encrypted under the session key.
        """
        meta_list = self.mailbox.list_emails(username)
        summary = [
            {
                "id":             m["id"],
                "from":           m["from"],
                "subject":        m["subject"],
                "date":           m["date"],
                "read":           m["read"],
                "has_attachment": m.get("has_attachment", False),
            }
            for m in meta_list
        ]

        raw     = pickle.dumps(summary)
        payload = aes_encrypt(session_key, raw)
        send_bytes(conn, payload)
        print(f"[server] Listed {len(summary)} email(s) for '{username}'")

    # ── Main server loop ──────────────────────────────────────────────────────

    def run(self) -> None:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen(10)
        print(f"[server] Quantum-Safe MIME Email Server listening on {HOST}:{PORT}")
        print(f"[server] KEM parameters: q={KEM_Q}, k={KEM_K}, t={KEM_T}")

        try:
            while True:
                conn, addr = server_sock.accept()
                t = threading.Thread(
                    target=self.handle_client, args=(conn, addr), daemon=True
                )
                t.start()
        except KeyboardInterrupt:
            print("\n[server] Shutting down.")
        finally:
            server_sock.close()


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    server = MIMEServerWithKEM()
    server.run()
