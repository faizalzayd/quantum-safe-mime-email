"""
kem/server.py

Server-side McEliece KEM handshake.

Protocol (per connection):
  1. Server generates a fresh McEliece key pair (keygen).
  2. Server sends the public matrix G_pub to the client as a JSON-framed message.
  3. Server receives the ciphertext c from the client.
  4. Server decapsulates c → recovers message vector m.
  5. Server derives session key S = HKDF(m).
  6. Returns S to the caller for use as an AES-256-CBC key.
"""

import os
import json
import socket
import tempfile
import struct
import shutil

from mc_eliece_lib.core   import keygen, decrypt, read_vec
from mc_eliece_lib.utils  import (
    parse_matrix_file, serialise_matrix,
    derive_secret_from_file,
)

# Environment-variable driven KEM parameters (with defaults)
_Q = int(os.environ.get("KEM_Q", 5))
_K = int(os.environ.get("KEM_K", 45))
_T = int(os.environ.get("KEM_T", 15))


def _send_json(conn: socket.socket, obj: dict) -> None:
    """Length-prefix a JSON payload and send over a socket."""
    payload = json.dumps(obj).encode()
    conn.sendall(struct.pack(">I", len(payload)) + payload)


def _recv_json(conn: socket.socket) -> dict:
    """Receive a length-prefixed JSON payload from a socket."""
    raw_len = _recv_exact(conn, 4)
    length = struct.unpack(">I", raw_len)[0]
    data = _recv_exact(conn, length)
    return json.loads(data.decode())


def _recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly during recv.")
        buf += chunk
    return buf


class KEMServer:
    """
    Encapsulates the server-side KEM handshake logic.

    Usage
    -----
    ks = KEMServer(q=5, k=45, t=15)
    session_key = ks.perform_handshake(conn)
    # session_key is 32 bytes → use as AES-256-CBC key
    """

    def __init__(self, q: int = _Q, k: int = _K, t: int = _T):
        self.q = q
        self.k = k
        self.t = t

    def perform_handshake(self, conn: socket.socket) -> bytes:
        """
        Execute the full server-side KEM handshake over *conn*.

        Returns
        -------
        bytes : 32-byte AES session key shared with the client.
        """
        tmp_dir = tempfile.mkdtemp(prefix="kem_srv_", dir="temp_files")
        try:
            return self._handshake(conn, tmp_dir)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _handshake(self, conn: socket.socket, tmp_dir: str) -> bytes:
        # Step 1: Generate key pair
        key_info = keygen(self.q, self.k, self.t, tmp_dir)
        G_pub_path = key_info["G_pub_path"]
        priv_dir   = key_info["priv_dir"]

        # Step 2: Send public matrix to client
        G_pub_matrix = parse_matrix_file(G_pub_path)
        pub_msg = {
            "type":   "KEM_PUBLIC_KEY",
            "params": {"q": self.q, "k": self.k, "t": self.t},
            "G_pub":  serialise_matrix(G_pub_matrix),
        }
        _send_json(conn, pub_msg)

        # Step 3: Receive ciphertext from client
        c_msg = _recv_json(conn)
        if c_msg.get("type") != "KEM_CIPHERTEXT":
            raise ValueError(f"Unexpected message type: {c_msg.get('type')}")

        c_path = os.path.join(tmp_dir, "c_received.vec")
        with open(c_path, "w") as f:
            f.write(" ".join(map(str, c_msg["c"])) + "\n")

        # Step 4 & 5: Decapsulate → derive session key
        m_path = decrypt(c_path, priv_dir, tmp_dir)
        session_key = derive_secret_from_file(m_path)

        return session_key
