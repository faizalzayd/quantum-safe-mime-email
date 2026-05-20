"""
mailbox_manager.py

File-based mailbox storage for the quantum-safe MIME email system.

On-disk layout (mirrors the report's specification):

    mailbox/
        <user>/
            inbox/
                <id>.json   – metadata: from, subject, date, read flag,
                              has_attachment
                <id>.enc    – AES-256-CBC encrypted MIME bytes (under storage key K)
                <id>.key    – per-email random storage AES key (32 bytes, raw)

Every email stored here is encrypted at rest under its own independent random
key, providing storage-level isolation as described in the Three-Layer Encryption
Model (§4.1 of the report).
"""

import json
import os
import uuid
from datetime import datetime, timezone


class MailboxManager:
    """
    Manages reading and writing of encrypted email blobs on disk.

    Parameters
    ----------
    base_dir : root of the mailbox tree (default: "mailbox")
    """

    def __init__(self, base_dir: str = "mailbox"):
        self.base_dir = base_dir

    # ── Internal path helpers ─────────────────────────────────────────────────

    def _inbox_dir(self, username: str) -> str:
        path = os.path.join(self.base_dir, username, "inbox")
        os.makedirs(path, exist_ok=True)
        return path

    def _paths(self, username: str, email_id: str) -> tuple[str, str, str]:
        """Return (json_path, enc_path, key_path) for a given email ID."""
        d = self._inbox_dir(username)
        return (
            os.path.join(d, f"{email_id}.json"),
            os.path.join(d, f"{email_id}.enc"),
            os.path.join(d, f"{email_id}.key"),
        )

    # ── Write ─────────────────────────────────────────────────────────────────

    def store_email(
        self,
        username:     str,
        encrypted_content: bytes,
        storage_key:  bytes,
        from_addr:    str,
        subject:      str,
        date:         str    = "",
        has_attachment: bool = False,
    ) -> str:
        """
        Persist one encrypted email to disk.

        Parameters
        ----------
        username           : recipient username
        encrypted_content  : AES-256-CBC ciphertext of the raw MIME bytes
        storage_key        : 32-byte random AES key used for encrypted_content
        from_addr          : sender address (stored in metadata, plaintext)
        subject            : subject line  (stored in metadata, plaintext)
        date               : RFC 2822 date string (optional; defaults to now)
        has_attachment     : whether the MIME message contains attachments

        Returns
        -------
        The new email's UUID string (used as file stem).
        """
        email_id = str(uuid.uuid4())
        json_path, enc_path, key_path = self._paths(username, email_id)

        if not date:
            date = datetime.now(tz=timezone.utc).strftime(
                "%a, %d %b %Y %H:%M:%S +0000"
            )

        metadata = {
            "id":             email_id,
            "from":           from_addr,
            "subject":        subject,
            "date":           date,
            "read":           False,
            "has_attachment": has_attachment,
        }

        # Write metadata JSON
        with open(json_path, "w") as f:
            json.dump(metadata, f, indent=2)

        # Write encrypted content
        with open(enc_path, "wb") as f:
            f.write(encrypted_content)

        # Write raw storage key
        with open(key_path, "wb") as f:
            f.write(storage_key)

        return email_id

    # ── Read ──────────────────────────────────────────────────────────────────

    def list_emails(self, username: str) -> list[dict]:
        """
        Return a list of metadata dicts for all emails in the user's inbox,
        sorted by date (oldest first).
        """
        inbox = self._inbox_dir(username)
        results = []
        for name in os.listdir(inbox):
            if name.endswith(".json"):
                email_id = name[:-5]
                json_path, _, _ = self._paths(username, email_id)
                with open(json_path, "r") as f:
                    results.append(json.load(f))
        # Sort by date string (lexicographic; works for RFC 2822 with same tz)
        results.sort(key=lambda m: m.get("date", ""))
        return results

    def get_email(self, username: str, email_id: str) -> dict:
        """
        Load the full email record for *email_id*: metadata + ciphertext + key.

        Returns
        -------
        dict with keys:
            'metadata'          : dict (from .json)
            'encrypted_content' : bytes (from .enc)
            'storage_key'       : bytes (from .key)
        """
        json_path, enc_path, key_path = self._paths(username, email_id)

        with open(json_path, "r") as f:
            metadata = json.load(f)
        with open(enc_path, "rb") as f:
            encrypted_content = f.read()
        with open(key_path, "rb") as f:
            storage_key = f.read()

        return {
            "metadata":          metadata,
            "encrypted_content": encrypted_content,
            "storage_key":       storage_key,
        }

    def get_all_emails(self, username: str) -> list[dict]:
        """
        Load every email in the user's inbox (metadata + ciphertext + key).
        Returns list of dicts as returned by get_email().
        """
        meta_list = self.list_emails(username)
        return [self.get_email(username, m["id"]) for m in meta_list]

    # ── Update ────────────────────────────────────────────────────────────────

    def mark_read(self, username: str, email_id: str) -> None:
        """Set read=True in the metadata JSON for *email_id*."""
        json_path, _, _ = self._paths(username, email_id)
        with open(json_path, "r") as f:
            metadata = json.load(f)
        metadata["read"] = True
        with open(json_path, "w") as f:
            json.dump(metadata, f, indent=2)

    # ── Delete ────────────────────────────────────────────────────────────────

    def delete_email(self, username: str, email_id: str) -> None:
        """Remove all three files associated with *email_id*."""
        for path in self._paths(username, email_id):
            if os.path.exists(path):
                os.remove(path)
