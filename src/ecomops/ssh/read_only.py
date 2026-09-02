import shlex

from ecomops.core.exceptions import ReadOnlyViolation

_ALLOWED_COMMANDS = {"cat", "grep", "head", "rg", "stat", "tail"}
_SHELL_OPERATORS = {";", "&&", "||", "|", ">", ">>", "<", "&"}


def _contains_shell_operator(command: str) -> bool:
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(command):
        character = command[index]
        if escaped:
            escaped = False
        elif character == "\\":
            escaped = True
        elif quote:
            if character == quote:
                quote = None
        elif character in {"'", '"'}:
            quote = character
        elif character in _SHELL_OPERATORS:
            return True
        index += 1
    return False


def validate_read_only_command(command: str) -> str:
    """Return a command only when it is a single approved read-only command."""
    if not command.strip():
        raise ReadOnlyViolation("Empty command is not allowed")
    if _contains_shell_operator(command):
        raise ReadOnlyViolation("Shell operators are not allowed in read-only mode")
    try:
        parts = shlex.split(command)
    except ValueError as error:
        raise ReadOnlyViolation("Malformed shell command") from error
    if not parts or parts[0] not in _ALLOWED_COMMANDS:
        raise ReadOnlyViolation(
            f"Command is not allowed in read-only mode: {parts[0] if parts else ''}"
        )
    return command
