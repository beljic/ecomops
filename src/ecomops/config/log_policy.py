"""Log-only path policy: an alias may only name a log file inside a log folder.

EcomOps reads logs, never system, configuration, or secret files. The rules:

1. the normalized path must be inside one of the allowed log folders;
2. the file name must look like a log (``*.log``, ``*.log.1``,
   ``*.log-20260901``), except inside the system log folder ``/var/log``
   where extensionless logs such as ``syslog`` or ``cron`` are common;
3. system folders, secret folders, and config/secret file types are always
   denied, even when a log folder is configured to include them.
"""

import os
import re
from collections.abc import Sequence
from pathlib import PurePosixPath

SYSTEM_LOG_DIR = PurePosixPath("/var/log")
_DENIED_PREFIXES = tuple(
    PurePosixPath(prefix)
    for prefix in ("/etc", "/proc", "/sys", "/dev", "/boot", "/root", "/run")
)
_DENIED_COMPONENTS = frozenset({".ssh", ".gnupg", ".aws", ".git", ".kube", ".docker"})
_DENIED_SUFFIXES = (
    ".php",
    ".phtml",
    ".env",
    ".ini",
    ".conf",
    ".cnf",
    ".xml",
    ".json",
    ".yaml",
    ".yml",
    ".sql",
    ".pem",
    ".key",
    ".crt",
    ".p12",
    ".htpasswd",
)
# ``.log`` optionally followed by a rotation suffix made of digits, dashes and
# dots; in a glob pattern ``?`` and ``*`` may stand in for rotation digits.
_LOG_NAME = re.compile(r"\.log(?:[.-][0-9?*][0-9?*.-]*)?$")


class LogPathPolicyViolation(ValueError):
    """Raised when a path is not an allowed log file."""


def normalize(path: str | os.PathLike[str]) -> PurePosixPath:
    return PurePosixPath(os.path.normpath(os.fspath(path)))


def is_within(path: PurePosixPath, directory: PurePosixPath) -> bool:
    return path == directory or directory in path.parents


def check_log_directory(directory: str | os.PathLike[str]) -> PurePosixPath:
    normalized = normalize(directory)
    if not normalized.is_absolute():
        raise LogPathPolicyViolation(f"log folder {directory} must be absolute")
    _check_denied(normalized)
    return normalized


def check_log_path(
    path: str | os.PathLike[str], allowed_dirs: Sequence[str | os.PathLike[str]]
) -> None:
    """Reject ``path`` unless it names a log file inside an allowed log folder.

    ``path`` may end in a glob pattern; the pattern is judged by the same
    name rule as a concrete file name.
    """
    normalized = normalize(path)
    if not normalized.is_absolute():
        raise LogPathPolicyViolation(f"{path} must resolve to an absolute path")
    _check_denied(normalized)
    folders = [normalize(directory) for directory in allowed_dirs]
    if not any(is_within(normalized.parent, folder) for folder in folders):
        raise LogPathPolicyViolation(f"{path} is outside the allowed log folders")
    if not _LOG_NAME.search(normalized.name) and not is_within(
        normalized.parent, SYSTEM_LOG_DIR
    ):
        raise LogPathPolicyViolation(
            f"{path} is not a log file name (*.log, *.log.1, *.log-20260901)"
        )


def _check_denied(path: PurePosixPath) -> None:
    if any(is_within(path, prefix) for prefix in _DENIED_PREFIXES):
        raise LogPathPolicyViolation(f"{path} is inside a denied system folder")
    if _DENIED_COMPONENTS.intersection(path.parts):
        raise LogPathPolicyViolation(f"{path} is inside a denied secret folder")
    parts = path.parts
    if any(parts[i : i + 2] == ("app", "etc") for i in range(len(parts) - 1)):
        raise LogPathPolicyViolation(f"{path} is inside a configuration folder")
    name = path.name.lower()
    if name == ".env" or name.startswith(".env.") or name.endswith(_DENIED_SUFFIXES):
        raise LogPathPolicyViolation(f"{path} is a configuration or secret file")
