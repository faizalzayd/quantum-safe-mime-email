"""
mime_utils/email_builder.py

Constructs RFC 2045/2822-compliant MIME messages with:
  - Standard headers (From, To, Subject, Date, Message-ID, MIME-Version)
  - Plain-text body part
  - Optional file attachments (base64-encoded)
  - multipart/mixed envelope when attachments are present
"""

import base64
import mimetypes
import os
import uuid
from datetime import datetime, timezone
from email import encoders
from email.mime.base        import MIMEBase
from email.mime.multipart   import MIMEMultipart
from email.mime.text        import MIMEText


def build_mime_message(
    from_addr:    str,
    to_addr:      str,
    subject:      str,
    body:         str,
    attachments:  list[str] | None = None,
) -> bytes:
    """
    Build a complete MIME message and return it as raw bytes.

    Parameters
    ----------
    from_addr   : sender address, e.g. "alice@localhost"
    to_addr     : recipient address, e.g. "bob@localhost"
    subject     : email subject line
    body        : plain-text message body
    attachments : list of file paths to attach (optional)

    Returns
    -------
    Raw MIME bytes (UTF-8 encoded).

    Example
    -------
    >>> raw = build_mime_message(
    ...     "alice@localhost", "bob@localhost",
    ...     "Hello", "Quantum-safe greetings!",
    ...     attachments=["report.pdf"],
    ... )
    """
    attachments = attachments or []

    if attachments:
        msg = MIMEMultipart("mixed")
    else:
        # Single-part message; we still wrap in MIMEMultipart for consistency
        # but callers can use a simpler MIMEText if preferred.
        msg = MIMEMultipart("mixed")

    # ── Standard headers ──────────────────────────────────────────────────────
    msg["From"]       = from_addr
    msg["To"]         = to_addr
    msg["Subject"]    = subject
    msg["Date"]       = _format_date()
    msg["Message-ID"] = f"<{uuid.uuid4()}@localhost>"
    msg["MIME-Version"] = "1.0"

    # ── Body ──────────────────────────────────────────────────────────────────
    text_part = MIMEText(body, "plain", "utf-8")
    msg.attach(text_part)

    # ── Attachments ───────────────────────────────────────────────────────────
    for file_path in attachments:
        _attach_file(msg, file_path)

    return msg.as_bytes()


def _format_date() -> str:
    """Return the current UTC time in RFC 2822 format."""
    now = datetime.now(tz=timezone.utc)
    return now.strftime("%a, %d %b %Y %H:%M:%S +0000")


def _attach_file(msg: MIMEMultipart, file_path: str) -> None:
    """
    Read *file_path* and attach it to *msg* as a base64-encoded MIME part.

    The Content-Type is guessed from the file extension; falls back to
    application/octet-stream.
    """
    filename = os.path.basename(file_path)
    content_type, _ = mimetypes.guess_type(file_path)
    if content_type is None:
        content_type = "application/octet-stream"

    main_type, sub_type = content_type.split("/", 1)

    with open(file_path, "rb") as f:
        file_data = f.read()

    part = MIMEBase(main_type, sub_type)
    part.set_payload(file_data)
    encoders.encode_base64(part)
    part.add_header(
        "Content-Disposition",
        "attachment",
        filename=filename,
    )
    msg.attach(part)
