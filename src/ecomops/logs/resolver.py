from ecomops.config.schema import (
    LocalConnectionConfig,
    ProjectConfig,
    SSHConnectionConfig,
)
from ecomops.logs.sources import LocalLogSource
from ecomops.ssh.fetcher import SSHLogSource


def resolve_source(project: ProjectConfig, alias: str) -> LocalLogSource | SSHLogSource:
    """Resolve a configured alias to its fixed read-only transport."""
    project.resolve_log_alias(alias)
    if isinstance(project.connection, LocalConnectionConfig):
        return LocalLogSource()
    assert isinstance(project.connection, SSHConnectionConfig)
    return SSHLogSource(project.connection)
