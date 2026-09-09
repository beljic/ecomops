from ecomops.config.schema import (
    LocalConnectionConfig,
    ProjectConfig,
    SSHConnectionConfig,
)
from ecomops.logs.sources import LocalLogSource
from ecomops.ssh.fetcher import SSHLogSource


def resolve_source(
    project: ProjectConfig, alias: str, *, ssh_password: str | None = None
) -> LocalLogSource | SSHLogSource:
    """Resolve a configured alias to its fixed read-only transport."""
    project.resolve_log_alias(alias)
    if isinstance(project.connection, LocalConnectionConfig):
        return LocalLogSource()
    assert isinstance(project.connection, SSHConnectionConfig)
    if ssh_password is None:
        return SSHLogSource(project.connection)
    return SSHLogSource(project.connection, password=ssh_password)
