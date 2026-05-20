"""
mime_utils/email_parser.py

Parses raw MIME bytes (as produced by email_builder or received from the
network) into a structured Python dict.

Returned structure
------------------
{
    "from":        str,
    "to":          str,
    "subject":     str,
    "date":        str,
    "message_id":  str,
    "body":        str,          # plain-text body
    "attachments": [             # list of attachment dicts
        {
            "filename":     str,
            "content_type": str,
            "data":         bytes,
        },
        ...
    ],
}
"""

import email
from email import policy
from email.message import EmailMessage


def parse_mime_message(raw: bytes) -> dict:
    """
    Parse *raw* MIME bytes and return a structured dict.

    Parameters
    ----------
    raw : raw MIME bytes as produced by email_builder.build_mime_message()

    Returns
    -------
    dict with keys: from, to, subject, date, message_id, body, attachments.
    """
    msg: EmailMessage = email.message_from_bytes(raw, policy=policy.default)

    result = {
        "from":       msg.get("From",       ""),
        "to":         msg.get("To",         ""),
        "subject":    msg.get("Subject",    ""),
        "date":       msg.get("Date",       ""),
        "message_id": msg.get("Message-ID", ""),
        "body":       "",
        "attachments": [],
    }

    if msg.is_multipart():
        for part in msg.walk():
            content_type        = part.get_content_type()
            content_disposition = str(part.get_content_disposition() or "")

            if content_type == "text/plain" and "attachment" not in content_disposition:
                # Body part
                result["body"] = _decode_payload(part)

            elif "attachment" in content_disposition or part.get_filename():
                # Attachment part
                result["attachments"].append({
                    "filename":     part.get_filename() or "unnamed",
                    "content_type": content_type,
                    "data":         part.get_payload(decode=True) or b"",
                })
    else:
        # Single-part message
        result["body"] = _decode_payload(msg)

    return result


def _decode_payload(part) -> str:
    """
    Safely decode a text MIME part to a Unicode string.
    Falls back to latin-1 if the declared charset fails.
    """
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset)
    except (UnicodeDecodeError, LookupError):
        return payload.decode("latin-1", errors="replace")


def summarise(parsed: dict) -> str:
    """
    Return a human-readable one-line summary of a parsed email dict.
    Useful for the LIST command output.
    """
    n_att = len(parsed.get("attachments", []))
    att_str = f"  [{n_att} attachment(s)]" if n_att else ""
    return (
        f"From:    {parsed['from']}\n"
        f"To:      {parsed['to']}\n"
        f"Subject: {parsed['subject']}\n"
        f"Date:    {parsed['date']}\n"
        f"Body:    {parsed['body'][:200]}"
        f"{'...' if len(parsed['body']) > 200 else ''}"
        f"{att_str}"
    )
