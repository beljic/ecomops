from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ecomops.core.exceptions import LogAliasNotFoundError
from ecomops.core.models import LogSource


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
    key_path: Path | None = None
    known_hosts_path: Path | None = None

    @field_validator("key_path", "known_hosts_path")
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
    type: str


class ProjectConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    platform: str = "custom"
    connection: ConnectionConfig
    log_aliases: dict[str, LogAliasConfig] = Field(default_factory=dict)

    def resolve_log_alias(self, alias: str) -> LogAliasConfig:
        try:
            return self.log_aliases[alias]
        except KeyError as error:
            raise LogAliasNotFoundError(
                f"Log alias '{alias}' is not configured for project '{self.name}'."
            ) from error

    def resolve_log_path(self, alias: str) -> Path:
        log_path = Path(self.resolve_log_alias(alias).path).expanduser()
        if (
            isinstance(self.connection, LocalConnectionConfig)
            and not log_path.is_absolute()
        ):
            return self.connection.root / log_path
        return log_path

    def resolve_log_source(self, alias: str) -> LogSource:
        log_alias = self.resolve_log_alias(alias)
        return LogSource(
            type=self.connection.type,
            path=str(self.resolve_log_path(alias)),
            project=self.name,
            alias=alias,
            log_type=log_alias.type,
        )
