import shlex

from ecomops.core.exceptions import ReadOnlyViolation

_SHELL_SYNTAX = frozenset(";&|<>$`()")
_MUTATING_OR_PRIVILEGED_COMMANDS = frozenset(
    {
        "bash",
        "cat",
        "chmod",
        "chown",
        "cp",
        "dd",
        "kill",
        "ln",
        "mkdir",
        "mktemp",
        "mv",
        "perl",
        "python",
        "python3",
        "rm",
        "rmdir",
        "sed",
        "sh",
        "shutdown",
        "sudo",
        "systemctl",
        "tee",
        "touch",
        "truncate",
        "uptime",
        "zsh",
    }
)
_SCRIPT_SUFFIXES = (".bash", ".fish", ".pl", ".py", ".rb", ".sh", ".zsh")
MAX_TAIL_LINES = 5000


def _contains_shell_operator(value: str) -> bool:
    return any(character in _SHELL_SYNTAX for character in value)


def _looks_like_command(path: str) -> bool:
    first_word = path.split(maxsplit=1)[0]
    command_name = first_word.rsplit("/", maxsplit=1)[-1]

    if command_name in _MUTATING_OR_PRIVILEGED_COMMANDS:
        return True
    if path.lower().endswith(_SCRIPT_SUFFIXES):
        return True
    if first_word.startswith("./") and "/" not in first_word[2:]:
        return True

    # A path with spaces must still have a path component before the first
    # space. Otherwise input such as ``curl https://...`` is command-shaped.
    return bool(
        any(character.isspace() for character in path) and "/" not in first_word
    )


class ReadOnlyPolicy:
    """Construct the only remote command permitted by the SSH read path."""

    @staticmethod
    def validate_path(path: str) -> str:
        """Return a configured log path or reject command-shaped input."""
        if not isinstance(path, str) or not path:
            raise ReadOnlyViolation("Log path must be a non-empty string")
        if path != path.strip():
            raise ReadOnlyViolation("Log path must not have surrounding whitespace")
        if any(ord(character) < 32 or ord(character) == 127 for character in path):
            raise ReadOnlyViolation("Control characters are not allowed in log paths")
        if _contains_shell_operator(path):
            raise ReadOnlyViolation("Shell operators are not allowed in read-only mode")
        if _looks_like_command(path):
            raise ReadOnlyViolation("Command-shaped input is not allowed as a log path")
        return path

    @staticmethod
    def build_tail_command(path: str, lines: int) -> str:
        """Build a bounded command for a trusted, already-resolved alias path.

        Project and alias resolution must happen before this boundary. This is
        deliberately not a generic command or arbitrary-path interface.
        """
        if isinstance(lines, bool) or not isinstance(lines, int) or lines <= 0:
            raise ValueError("lines must be a positive integer")
        if lines > MAX_TAIL_LINES:
            raise ValueError(f"lines exceed the maximum of {MAX_TAIL_LINES}")
        validated_path = ReadOnlyPolicy.validate_path(path)
        return f"tail --lines {lines} -- {shlex.quote(validated_path)}"


def validate_read_only_command(command: str) -> str:
    """Reject the legacy raw-command interface in favor of fixed builders."""
    raise ReadOnlyViolation("Raw SSH commands are not accepted in read-only mode")
