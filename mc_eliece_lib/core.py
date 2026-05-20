"""
mc_eliece_lib/core.py

Wraps the compiled C binaries for McEliece cryptographic operations:
  - keygen      : generate Goppa-code key pair
  - find_H      : compute parity-check matrix
  - encryption  : encapsulate (client side)
  - decryption  : decapsulate (server side)

Binary paths are relative to this file's directory (mc_eliece_lib/binaries/).
All intermediate matrix files are written to a caller-supplied temp directory.
"""

import os
import subprocess
import json
import tempfile
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────
_BIN_DIR = Path(__file__).parent / "binaries"

KEYGEN_BIN     = _BIN_DIR / "keygen"
FIND_H_BIN     = _BIN_DIR / "find_H"
ENCRYPT_BIN    = _BIN_DIR / "encryption"
DECRYPT_BIN    = _BIN_DIR / "decryption"


def _run(cmd: list, check: bool = True) -> subprocess.CompletedProcess:
    """Run a subprocess, capturing stdout/stderr."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command {cmd[0]} failed (rc={result.returncode}):\n"
            f"  stdout: {result.stdout.strip()}\n"
            f"  stderr: {result.stderr.strip()}"
        )
    return result


# ── Key Generation ─────────────────────────────────────────────────────────────

def keygen(q: int, k: int, t: int, tmp_dir: str) -> dict:
    """
    Generate a McEliece key pair for the given Goppa-code parameters.

    Parameters
    ----------
    q       : field size (prime)
    k       : code dimension
    t       : error-correction capacity
    tmp_dir : directory where intermediate matrix files are written

    Returns
    -------
    dict with keys:
        'G_pub_path'   – path to the public generator matrix file
        'priv_dir'     – directory containing private key components (S, G, P)
        'params'       – {'q': q, 'k': k, 't': t}
    """
    tmp_dir = str(tmp_dir)
    os.makedirs(tmp_dir, exist_ok=True)

    cmd = [
        str(KEYGEN_BIN),
        "--q", str(q),
        "--k", str(k),
        "--t", str(t),
        "--outdir", tmp_dir,
    ]
    _run(cmd)

    return {
        "G_pub_path": os.path.join(tmp_dir, "G_pub.mat"),
        "priv_dir":   tmp_dir,
        "params":     {"q": q, "k": k, "t": t},
    }


def find_H(G_pub_path: str, tmp_dir: str) -> str:
    """
    Compute the parity-check matrix H from the public generator matrix.

    Parameters
    ----------
    G_pub_path : path to the public generator matrix file
    tmp_dir    : output directory

    Returns
    -------
    Path to the generated H matrix file.
    """
    H_path = os.path.join(str(tmp_dir), "H.mat")
    cmd = [
        str(FIND_H_BIN),
        "--G", G_pub_path,
        "--out", H_path,
    ]
    _run(cmd)
    return H_path


# ── Encapsulation (client) ─────────────────────────────────────────────────────

def encrypt(G_pub_path: str, message_vec_path: str, t: int, tmp_dir: str) -> str:
    """
    Encapsulation step: compute ciphertext c = m * G_pub + e.

    Parameters
    ----------
    G_pub_path      : path to public generator matrix
    message_vec_path: path to the random message vector m (binary)
    t               : max weight of error vector e
    tmp_dir         : output directory

    Returns
    -------
    Path to the ciphertext file (c.vec).
    """
    c_path = os.path.join(str(tmp_dir), "c.vec")
    cmd = [
        str(ENCRYPT_BIN),
        "--G",   G_pub_path,
        "--msg", message_vec_path,
        "--t",   str(t),
        "--out", c_path,
    ]
    _run(cmd)
    return c_path


# ── Decapsulation (server) ─────────────────────────────────────────────────────

def decrypt(c_path: str, priv_dir: str, tmp_dir: str) -> str:
    """
    Decapsulation step: recover message vector m from ciphertext c using
    Goppa decoding.

    Parameters
    ----------
    c_path   : path to ciphertext file
    priv_dir : directory containing private key files (S.mat, G.mat, P.mat)
    tmp_dir  : output directory

    Returns
    -------
    Path to the recovered message vector file (m_recovered.vec).
    """
    m_path = os.path.join(str(tmp_dir), "m_recovered.vec")
    cmd = [
        str(DECRYPT_BIN),
        "--c",       c_path,
        "--privdir", priv_dir,
        "--out",     m_path,
    ]
    _run(cmd)
    return m_path


# ── Convenience: read/write binary vector files ────────────────────────────────

def read_vec(path: str) -> bytes:
    """Read a raw binary vector file and return its bytes."""
    with open(path, "rb") as f:
        return f.read()


def write_vec(path: str, data: bytes) -> None:
    """Write bytes to a binary vector file."""
    with open(path, "wb") as f:
        f.write(data)


def read_matrix_json(path: str) -> dict:
    """Read a matrix stored as JSON (used for G_pub transport)."""
    with open(path, "r") as f:
        return json.load(f)


def write_matrix_json(path: str, matrix_data: dict) -> None:
    """Write a matrix as JSON."""
    with open(path, "w") as f:
        json.dump(matrix_data, f)
