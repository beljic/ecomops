from pathlib import Path

import pytest
from pydantic import ValidationError

from ecomops.config.projects import ProjectRegistry
from ecomops.config.schema import (
    LocalConnectionConfig,
    ProjectConfig,
    SSHConnectionConfig,
)
from ecomops.core.exceptions import (
    ConfigurationError,
    LogAliasNotFoundError,
    ProjectNotFoundError,
)


def write_project(projects_dir: Path, filename: str, content: str) -> None:
    (projects_dir / filename).write_text(content, encoding="utf-8")


def test_loads_local_project_from_external_directory(tmp_path: Path) -> None:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    write_project(
        projects_dir,
        "store.yaml",
        """
name: storefront
platform: magento
connection:
  type: local
  root: ~/workspace/storefront
log_aliases:
  exception:
    path: var/log/exception.log
    type: magento
""",
    )

    project = ProjectRegistry.load(projects_dir).get("storefront")

    assert isinstance(project.connection, LocalConnectionConfig)
    assert project.connection.root == Path("~/workspace/storefront").expanduser()
    assert project.resolve_log_alias("exception").path == "var/log/exception.log"
    assert project.resolve_log_path("exception") == (
        Path("~/workspace/storefront").expanduser() / "var/log/exception.log"
    )


def test_loads_ssh_project_with_optional_key_and_known_hosts_paths(
    tmp_path: Path,
) -> None:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    write_project(
        projects_dir,
        "production.yml",
        """
name: production
connection:
  type: ssh
  host: logs.example.test
  user: readonly
  key_path: ~/.ssh/ecomops_readonly
  known_hosts_path: ~/.ssh/known_hosts
log_aliases:
  nginx-error:
    path: /var/log/nginx/error.log
    type: nginx
""",
    )

    project = ProjectRegistry.load(projects_dir).get("production")

    assert isinstance(project.connection, SSHConnectionConfig)
    assert project.connection.host == "logs.example.test"
    assert project.connection.key_path == Path("~/.ssh/ecomops_readonly").expanduser()
    assert project.connection.known_hosts_path == Path(
        "~/.ssh/known_hosts"
    ).expanduser()
    assert project.resolve_log_alias("nginx-error").type == "nginx"
    assert project.resolve_log_path("nginx-error") == Path("/var/log/nginx/error.log")


def test_get_rejects_unknown_project(tmp_path: Path) -> None:
    with pytest.raises(ProjectNotFoundError, match="missing"):
        ProjectRegistry.load(tmp_path).get("missing")


def test_alias_resolution_rejects_unknown_alias() -> None:
    project = ProjectConfig.model_validate(
        {
            "name": "storefront",
            "connection": {"type": "local", "root": "/srv/storefront"},
            "log_aliases": {},
        }
    )

    with pytest.raises(LogAliasNotFoundError, match="system"):
        project.resolve_log_alias("system")


def test_rejects_password_in_ssh_connection() -> None:
    with pytest.raises(ValidationError, match="password"):
        ProjectConfig.model_validate(
            {
                "name": "production",
                "connection": {
                    "type": "ssh",
                    "host": "logs.example.test",
                    "user": "readonly",
                    "password": "must-not-be-supported",
                },
            }
        )


def test_load_uses_projects_directory_environment_override(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    projects_dir = tmp_path / "external-projects"
    projects_dir.mkdir()
    write_project(
        projects_dir,
        "store.yaml",
        """
name: storefront
connection:
  type: local
  root: /srv/storefront
""",
    )
    monkeypatch.setenv("ECOMOPS_PROJECTS_DIR", str(projects_dir))

    assert ProjectRegistry.load().get("storefront").name == "storefront"


def test_rejects_group_writable_project_file(tmp_path: Path) -> None:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    project_file = projects_dir / "store.yaml"
    project_file.write_text(
        """
name: storefront
connection:
  type: local
  root: /srv/storefront
""",
        encoding="utf-8",
    )
    project_file.chmod(0o664)

    with pytest.raises(ConfigurationError, match="group- or world-writable"):
        ProjectRegistry.load(projects_dir)
