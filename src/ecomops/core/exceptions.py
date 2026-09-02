class EcomOpsError(Exception):
    """Base exception for expected EcomOps failures."""


class ReadOnlyViolation(EcomOpsError):
    """Raised when a command is not provably read-only."""
