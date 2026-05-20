"""
mc_eliece_lib/utils.py

Utility helpers for the McEliece KEM layer:
  - Matrix file I/O (parse / serialise the binary .mat format used by the C binaries)
  - HKDF-based shared-secret derivation from the recovered message vector
"""

import os
import json
import struct
import hashlib
import hmac

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


# ── Matrix serialisation ───────────────────────────────────────────────────────

def parse_matrix_file(path: str) -> list[list[int]]:
    """
    Parse a matrix written by the C keygen / find_H binaries.

    Expected file format (text):
        <rows> <cols>
        <row_0_col_0> <row_0_col_1> ...
        ...

    Returns a list-of-lists of integers.
    """
    rows = []
    with open(path, "r") as f:
        header = f.readline().split()
        nrows, ncols = int(header[0]), int(header[1])
        for _ in range(nrows):
            row = list(map(int, f.readline().split()))
            if len(row) != ncols:
                raise ValueError(
                    f"Matrix row length mismatch: expected {ncols}, got {len(row)}"
                )
            rows.append(row)
    return rows


def serialise_matrix(matrix: list[list[int]]) -> dict:
    """
    Serialise a 2-D integer matrix to a JSON-friendly dict for network transport.

    Returns {'rows': int, 'cols': int, 'data': [[int, ...], ...]}
    """
    nrows = len(matrix)
    ncols = len(matrix[0]) if nrows else 0
    return {"rows": nrows, "cols": ncols, "data": matrix}


def deserialise_matrix(obj: dict) -> list[list[int]]:
    """Inverse of serialise_matrix."""
    return obj["data"]


def write_matrix_file(path: str, matrix: list[list[int]]) -> None:
    """
    Write a matrix in the text format expected by the C encryption binary.
    """
    nrows = len(matrix)
    ncols = len(matrix[0]) if nrows else 0
    with open(path, "w") as f:
        f.write(f"{nrows} {ncols}\n")
        for row in matrix:
            f.write(" ".join(map(str, row)) + "\n")


# ── Vector serialisation ───────────────────────────────────────────────────────

def parse_vec_file(path: str) -> list[int]:
    """
    Parse a binary column-vector file produced by the C binaries.

    Format: single line of space-separated integers (0/1 for GF(2) vectors).
    """
    with open(path, "r") as f:
        return list(map(int, f.read().split()))


def write_vec_file(path: str, vec: list[int]) -> None:
    """Write a vector in the format expected by the C encryption binary."""
    with open(path, "w") as f:
        f.write(" ".join(map(str, vec)) + "\n")


def vec_to_bytes(vec: list[int]) -> bytes:
    """Pack a bit-vector (list of 0/1) into a compact bytes object."""
    # Pad to a multiple of 8
    n = len(vec)
    padded = vec + [0] * ((8 - n % 8) % 8)
    result = bytearray()
    for i in range(0, len(padded), 8):
        byte = 0
        for bit in padded[i:i + 8]:
            byte = (byte << 1) | (bit & 1)
        result.append(byte)
    return bytes(result)


def bytes_to_vec(data: bytes, length: int) -> list[int]:
    """Unpack a bytes object back into a bit-vector of the given length."""
    bits = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits[:length]


# ── HKDF shared-secret derivation ─────────────────────────────────────────────

_HKDF_INFO  = b"McEliece-KEM-Session-Key-v1"
_HKDF_SALT  = b"quantum-safe-mime-email-salt-2025"


def derive_secret(message_vec: bytes, extra_info: bytes = b"") -> bytes:
    """
    Derive a 32-byte (256-bit) AES session key from the raw message vector
    using HKDF-SHA256.

    Parameters
    ----------
    message_vec : the shared McEliece message vector (as raw bytes)
    extra_info  : optional additional binding context (e.g. connection nonce)

    Returns
    -------
    32 bytes suitable for use as an AES-256 key.
    """
    info = _HKDF_INFO + extra_info
    hkdf = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=_HKDF_SALT,
        info=info,
        backend=default_backend(),
    )
    return hkdf.derive(message_vec)


def derive_secret_from_file(vec_path: str, extra_info: bytes = b"") -> bytes:
    """
    Convenience wrapper: read the message vector file produced by the C binary
    and derive the session key.
    """
    vec = parse_vec_file(vec_path)
    raw = vec_to_bytes(vec)
    return derive_secret(raw, extra_info)
