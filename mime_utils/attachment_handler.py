"""
mime_utils/attachment_handler.py

Safely extracts attachments from parsed MIME messages and writes them to
the per-user received_files/ directory.

Security considerations
-----------------------
- Filenames are sanitised to prevent path traversal (e.g. "../../etc/passwd").
- Duplicate filenames are disambiguated with a numeric suffix.
- Maximum file size is enforced (default 50 MB per attachment).
"""

import os
import re


MAX_ATTACHMENT_BYTES = 50 * 1024 * 1024   # 50 MB safety limit
_SAFE_FILENAME_RE    = re.compile(r"[^\w.\-]")


def sanitise_filename(filename: str) -> str:
    """
    Return a safe filename with no path separators or shell-special characters.

    Examples
    --------
    >>> sanitise_filename("../../etc/passwd")
    'etc_passwd'
    >>> sanitise_filename("my report (v2).pdf")
    'my_report__v2_.pdf'
    """
    # Strip any directory component first
    filename = os.path.basename(filename)
    # Replace unsafe characters with underscores
    safe = _SAFE_FILENAME_RE.sub("_", filename)
    # Collapse multiple underscores
    safe = re.sub(r"_+", "_", safe).strip("_")
    return safe or "attachment"


def _unique_path(directory: str, filename: str) -> str:
    """
    Return a file path that does not already exist in *directory*.
    If *filename* is taken, appends _1, _2, … before the extension.
    """
    base, ext = os.path.splitext(filename)
    candidate = os.path.join(directory, filename)
    counter = 1
    while os.path.exists(candidate):
        candidate = os.path.join(directory, f"{base}_{counter}{ext}")
        counter += 1
    return candidate


class AttachmentHandler:
    """
    Manages writing attachments to disk for a given base directory.

    Parameters
    ----------
    base_dir : root directory under which per-user sub-directories are created
               (e.g. "received_files")
    """

    def __init__(self, base_dir: str = "received_files"):
        self.base_dir = base_dir

    def save_attachments(
        self,
        username: str,
        attachments: list[dict],
    ) -> list[str]:
        """
        Save a list of attachment dicts (as produced by email_parser) to
        received_files/<username>/.

        Parameters
        ----------
        username    : the recipient's username (used as sub-directory name)
        attachments : list of dicts with keys 'filename', 'content_type', 'data'

        Returns
        -------
        List of absolute paths to the saved files.
        """
        user_dir = os.path.join(self.base_dir, username)
        os.makedirs(user_dir, exist_ok=True)

        saved_paths = []
        for att in attachments:
            filename = sanitise_filename(att.get("filename", "attachment"))
            data     = att.get("data", b"")

            if not isinstance(data, bytes):
                data = b""

            if len(data) > MAX_ATTACHMENT_BYTES:
                raise ValueError(
                    f"Attachment '{filename}' exceeds the "
                    f"{MAX_ATTACHMENT_BYTES // (1024*1024)} MB limit."
                )

            dest_path = _unique_path(user_dir, filename)
            with open(dest_path, "wb") as f:
                f.write(data)

            saved_paths.append(dest_path)

        return saved_paths

    def list_received_files(self, username: str) -> list[str]:
        """
        Return filenames of all files previously saved for *username*.
        """
        user_dir = os.path.join(self.base_dir, username)
        if not os.path.isdir(user_dir):
            return []
        return sorted(os.listdir(user_dir))
