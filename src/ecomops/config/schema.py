import os
from pathlib import Path
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyNetwork,
    field_validator,
    model_validator,
)

from ecomops.core.exceptions import (
    ConfigurationError,
    LogAliasNotFoundError,
    LogPathPolicyError,
    ReadOnlyViolation,
)
from ecomops.core.models import ClientIpSource, LogSource
from ecomops.ssh.read_only import validate_glob_pattern

from .log_policy import (
    SYSTEM_LOG_DIR,
    LogPathPolicyViolation,
    check_log_directory,
    check_log_path,
)

LogType = Literal["php", "magento", "nginx", "mysql", "mariadb", "cron", "generic"]
_GLOB_CHARACTERS = frozenset("*?[]")


def _expand_path(path: Path) -> Path:
    return path.expanduser()


class LocalConnectionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["local"]
    root: Path

    @field_validator("root")
    @classmethod
    def expand_root(cls, path: Path) -> Path:
        return _expand_path(path)


class SSHConnectionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["ssh"]
    host: str
    user: str
    port: int = 22
    root: Path | None = None
    key_path: Path | None = None
    known_hosts_path: Path | None = None

    @field_validator("root", "key_path", "known_hosts_path")
    @classmethod
    def expand_optional_path(cls, path: Path | None) -> Path | None:
        return _expand_path(path) if path is not None else None


ConnectionConfig = Annotated[
    LocalConnectionConfig | SSHConnectionConfig,
    Field(discriminator="type"),
]


class LogAliasConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    type: LogType
    client_ip_source: ClientIpSource = "socket"

    @model_validator(mode="after")
    def validate_client_ip_source(self) -> "LogAliasConfig":
        if self.client_ip_source != "socket" and self.type != "nginx":
            raise ValueError("client_ip_source is only supported for nginx aliases")
        return self

    @field_validator("path")
    @classmethod
    def validate_glob_path(cls, path: str) -> str:
        if not _has_glob(path):
            return path
        parts = Path(path)
        if _has_glob(str(parts.parent)):
            raise ValueError("glob wildcards are only allowed in the file name")
        try:
            validate_glob_pattern(parts.name)
        except ReadOnlyViolation as error:
            raise ValueError(f"unsupported glob pattern: {error}") from None
        return path

    @property
    def is_glob(self) -> bool:
        return _has_glob(self.path)


def _has_glob(value: str) -> bool:
    return any(character in _GLOB_CHARACTERS for character in value)


class SecurityConfig(BaseModel):
    """Local-only inputs for ``security_scan``; no external lookups are made."""

    model_config = ConfigDict(extra="forbid")

    tor_cidrs: list[IPvAnyNetwork] = Field(default_factory=list)
    login_threshold: int = Field(default=5, ge=2)


class ProjectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    platform: str = "custom"
    connection: ConnectionConfig
    log_dirs: list[Path] | None = None
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    log_aliases: dict[str, LogAliasConfig] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_relative_ssh_paths(self) -> "ProjectConfig":
        if isinstance(self.connection, SSHConnectionConfig):
            if self.connection.root is None and any(
                not Path(alias.path).expanduser().is_absolute()
                for alias in self.log_aliases.values()
            ):
                raise ValueError(
                    "SSH connection root is required for relative log alias paths."
                )
        try:
            allowed_dirs = self.allowed_log_dirs()
            for name in self.log_aliases:
                try:
                    check_log_path(self.resolve_log_path(name), allowed_dirs)
                except LogPathPolicyViolation as error:
                    raise LogPathPolicyViolation(
                        f"log alias '{name}': {error}"
                    ) from None
        except LogPathPolicyViolation as error:
            raise ValueError(f"log path policy: {error}") from None
        return self

    def allowed_log_dirs(self) -> list[Path]:
        """Folders aliases may read from: ``log_dirs``, else root and /var/log."""
        root = self.connection.root
        if self.log_dirs is None:
            candidates = ([] if root is None else [root]) + [Path(SYSTEM_LOG_DIR)]
        else:
            candidates = []
            for directory in self.log_dirs:
                directory = directory.expanduser()
                if not directory.is_absolute():
                    if root is None:
                        raise LogPathPolicyViolation(
                            f"relative log folder {directory} needs a connection root"
                        )
                    directory = root / directory
                candidates.append(directory)
        return [Path(check_log_directory(directory)) for directory in candidates]

    def check_real_log_path(self, real_path: str) -> None:
        """Re-check a symlink-resolved local path against the log policy."""
        try:
            check_log_path(
                real_path,
                [Path(os.path.realpath(d)) for d in self.allowed_log_dirs()],
            )
        except LogPathPolicyViolation as error:
            raise LogPathPolicyError(f"Log path policy: {error}") from None

    def resolve_log_alias(self, alias: str) -> LogAliasConfig:
        try:
            return self.log_aliases[alias]
        except KeyError as error:
            raise LogAliasNotFoundError(
                f"Log alias '{alias}' is not configured for project '{self.name}'."
            ) from error

    def resolve_log_path(self, alias: str) -> Path:
        log_path = Path(self.resolve_log_alias(alias).path).expanduser()
        if not log_path.is_absolute():
            if isinstance(self.connection, LocalConnectionConfig):
                return self.connection.root / log_path
            if self.connection.root is not None:
                return self.connection.root / log_path
        return log_path

    def resolve_log_glob(self, alias: str) -> tuple[Path, str]:
        """Return the directory and file-name pattern of a glob alias."""
        if not self.resolve_log_alias(alias).is_glob:
            raise ConfigurationError(
                f"Log alias '{alias}' is not a glob for project '{self.name}'."
            )
        pattern_path = self.resolve_log_path(alias)
        return pattern_path.parent, pattern_path.name

    def resolve_log_source(self, alias: str) -> LogSource:
        log_alias = self.resolve_log_alias(alias)
        return LogSource(
            type=self.connection.type,
            path=str(self.resolve_log_path(alias)),
            project=self.name,
            alias=alias,
            log_type=log_alias.type,
        )
