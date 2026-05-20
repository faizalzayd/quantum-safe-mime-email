# Quantum-Safe MIME Email System
### McEliece KEM · AES-256-CBC · RFC 2045 MIME · Python 3.6+

A fully asynchronous, store-and-forward email system resistant to quantum
attacks, replacing RSA/ECDH key exchange with the McEliece Key Encapsulation
Mechanism (KEM).

---

## Project Structure

```
quantum_mime_email/
├── mime_server_with_kem.py     # TCP server — KEM handshake + SEND/RECV/LIST
├── mime_client_with_kem.py     # CLI client — build, encrypt, send, receive
├── mailbox_manager.py          # File-based mailbox (JSON meta + AES .enc + .key)
│
├── kem/
│   ├── server.py               # Server-side KEM handshake (decapsulation)
│   └── client.py               # Client-side KEM handshake (encapsulation)
│
├── mime_utils/
│   ├── email_builder.py        # RFC 2822 MIME construction
│   ├── email_parser.py         # MIME parsing → structured dict
│   └── attachment_handler.py   # Safe attachment extraction to disk
│
└── mc_eliece_lib/
    ├── core.py                 # Python wrappers for compiled C binaries
    ├── utils.py                # Matrix I/O + HKDF secret derivation
    └── Makefile                # Builds keygen / find_H / encryption / decryption
```

---

## Installation

```bash
# 1. Python dependency
pip install cryptography

# 2. Compile McEliece C binaries
cd mc_eliece_lib
make
cd ..

# Python >= 3.6 required; ~100 MB disk for mailboxes
```

---

## Usage

### Start the server (Terminal 1)
```bash
python3 mime_server_with_kem.py
```

### Alice sends an email with attachment (Terminal 2)
```bash
python3 mime_client_with_kem.py send \
    --from alice@localhost \
    --to   bob@localhost   \
    --subject "Quantum-Safe Hello" \
    --body "Protected by McEliece KEM!" \
    --attach ./report.pdf
```

### Bob lists inbox headers (Terminal 3)
```bash
python3 mime_client_with_kem.py list --user bob
```

### Bob downloads full emails (Terminal 3)
```bash
python3 mime_client_with_kem.py receive --user bob
```

---

## KEM Security Parameters

| q  | k    | t   | Security  | Handshake | Use case          |
|----|------|-----|-----------|-----------|-------------------|
| 3  | 22   | 8   | Low       | ~1.6 s    | Testing only      |
| 5  | 45   | 15  | Medium    | ~1.8 s    | **Recommended**   |
| 7  | 172  | 60  | High      | ~7.2 s    | Balanced          |
| 11 | 666  | 100 | Very High | ~8.3 min  | Maximum practical |
| 13 | 1099 | 120 | Maximum   | ~36 min   | Research / offline|

### Custom parameters (server and client must match)
```bash
KEM_Q=7 KEM_K=172 KEM_T=60 python3 mime_server_with_kem.py
KEM_Q=7 KEM_K=172 KEM_T=60 python3 mime_client_with_kem.py send ...
```

---

## On-Disk Mailbox Layout

```
mailbox/
  <user>/
    inbox/
      <id>.json   # metadata: from, subject, date, read flag
      <id>.enc    # AES-256-CBC encrypted MIME message
      <id>.key    # per-email storage AES key (32 bytes)
received_files/
  <user>/         # extracted attachments after receive
temp_files/       # KEM intermediate matrix files (transient)
```

---

## Three-Layer Encryption Model

```
Sender  →  [AES_S1( MIME )]  →  Server  →  [AES_K( MIME )] on disk
Receiver ← [AES_S2( K ) + AES_K( MIME )] ← Server
```

- **S1** — session key from sender's KEM handshake (ephemeral)
- **K**  — random per-email storage key (`os.urandom(32)`)
- **S2** — session key from receiver's KEM handshake (ephemeral)

---

## Security Properties

| Property                    | Mechanism                        | Status |
|-----------------------------|----------------------------------|--------|
| Quantum-resistant key exchange | McEliece KEM                  | ✓      |
| Bulk data confidentiality   | AES-256-CBC                      | ✓      |
| Forward secrecy             | Ephemeral KEM keys per connection| ✓      |
| Storage isolation           | Per-email random key K           | ✓      |
| Harvest-now-decrypt-later   | Post-quantum KEM + AES           | ✓      |
| Endpoint compromise         | Out of scope                     | ✗      |
| Metadata hiding             | Not implemented                  | ✗      |
