class EcomOpsError(Exception):
    """Base exception for expected EcomOps failures."""


class ReadOnlyViolation(EcomOpsError):
    """Raised when a command is not provably read-only."""


class SSHTransportError(EcomOpsError):
    """Raised when a bounded SSH log read cannot be completed safely."""


class SSHPermissionDeniedError(SSHTransportError):
    """Raised when SSH authentication or authorization is denied."""


class ConfigurationError(EcomOpsError):
    """Raised when a project configuration cannot be loaded safely."""


class ProjectNotFoundError(ConfigurationError):
    """Raised when a requested project is not configured."""


class LogAliasNotFoundError(ConfigurationError):
    """Raised when a requested log alias is not configured for a project."""
