"""
kem/client.py

Client-side McEliece KEM handshake.

Protocol (per connection):
  1. Client receives the server's public matrix G_pub (JSON-framed).
  2. Client generates a random message vector m.
  3. Client encapsulates: c = m * G_pub + e  (e = random error, weight ≤ t).
  4. Client derives session key S = HKDF(m).
  5. Client sends ciphertext c to the server.
  6. Returns S to the caller for use as an AES-256-CBC key.
"""

import os
import json
import random
import socket
import struct
import tempfile
import shutil

from mc_eliece_lib.core   import encrypt, write_vec
from mc_eliece_lib.utils  import (
    deserialise_matrix, write_matrix_file, write_vec_file,
    vec_to_bytes, derive_secret,
)

# Environment-variable driven KEM parameters (must match server)
_Q = int(os.environ.get("KEM_Q", 5))
_K = int(os.environ.get("KEM_K", 45))
_T = int(os.environ.get("KEM_T", 15))


def _send_json(sock: socket.socket, obj: dict) -> None:
    payload = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _recv_json(sock: socket.socket) -> dict:
    raw_len = _recv_exact(sock, 4)
    length = struct.unpack(">I", raw_len)[0]
    data = _recv_exact(sock, length)
    return json.loads(data.decode())


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly during recv.")
        buf += chunk
    return buf


def _random_message_vec(k: int) -> list[int]:
    """Generate a random binary message vector of length k."""
    return [random.randint(0, 1) for _ in range(k)]


def _random_error_vec(n: int, t: int) -> list[int]:
    """
    Generate a random binary error vector of length n with exactly t ones.
    """
    vec = [0] * n
    positions = random.sample(range(n), t)
    for pos in positions:
        vec[pos] = 1
    return vec


def _mat_vec_mul_gf2(matrix: list[list[int]], vec: list[int]) -> list[int]:
    """
    Multiply matrix (rows × cols) by column vector vec over GF(2).
    Returns result vector of length rows.
    """
    result = []
    for row in matrix:
        dot = sum(a * b for a, b in zip(row, vec)) % 2
        result.append(dot)
    return result


class KEMClient:
    """
    Encapsulates the client-side KEM handshake logic.

    Usage
    -----
    kc = KEMClient()
    session_key = kc.perform_handshake(sock)
    # session_key is 32 bytes → use as AES-256-CBC key
    """

    def __init__(self):
        self.q = _Q
        self.k = _K
        self.t = _T

    def perform_handshake(self, sock: socket.socket) -> bytes:
        """
        Execute the full client-side KEM handshake over *sock*.

        Returns
        -------
        bytes : 32-byte AES session key shared with the server.
        """
        tmp_dir = tempfile.mkdtemp(prefix="kem_cli_", dir="temp_files")
        try:
            return self._handshake(sock, tmp_dir)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def _handshake(self, sock: socket.socket, tmp_dir: str) -> bytes:
        # Step 1: Receive public key from server
        pub_msg = _recv_json(sock)
        if pub_msg.get("type") != "KEM_PUBLIC_KEY":
            raise ValueError(f"Unexpected message type: {pub_msg.get('type')}")

        G_pub = deserialise_matrix(pub_msg["G_pub"])
        params = pub_msg["params"]
        k = params["k"]
        t = params["t"]
        # n = number of columns in G_pub
        n = len(G_pub[0]) if G_pub else 0

        # Step 2: Generate random message vector m (length k)
        m_vec = _random_message_vec(k)

        # Step 3a: Write G_pub and m to files for C binary
        G_pub_path = os.path.join(tmp_dir, "G_pub_recv.mat")
        m_path     = os.path.join(tmp_dir, "m.vec")
        write_matrix_file(G_pub_path, G_pub)
        write_vec_file(m_path, m_vec)

        # Step 3b: Encapsulate using C binary → ciphertext c
        c_path = encrypt(G_pub_path, m_path, t, tmp_dir)

        # Step 4: Derive session key from m
        m_bytes = vec_to_bytes(m_vec)
        session_key = derive_secret(m_bytes)

        # Step 5: Send ciphertext to server
        with open(c_path, "r") as f:
            c_vec = list(map(int, f.read().split()))

        c_msg = {"type": "KEM_CIPHERTEXT", "c": c_vec}
        _send_json(sock, c_msg)

        return session_key
