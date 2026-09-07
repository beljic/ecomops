from pathlib import Path

from ecomops.config.loader import (
    expand_path,
    load_project_file,
    projects_directory,
    validate_directory_permissions,
)
from ecomops.config.schema import ProjectConfig
from ecomops.core.exceptions import ConfigurationError, ProjectNotFoundError


class ProjectRegistry:
    def __init__(self, projects: dict[str, ProjectConfig]) -> None:
        self._projects = projects

    @classmethod
    def load(cls, projects_dir: Path | None = None) -> "ProjectRegistry":
        directory = (
            expand_path(projects_dir)
            if projects_dir is not None
            else projects_directory()
        )
        if not directory.exists():
            return cls({})
        if not directory.is_dir():
            raise ConfigurationError(
                f"Projects path '{directory}' must be a directory."
            )
        validate_directory_permissions(directory)

        projects: dict[str, ProjectConfig] = {}
        project_files = sorted(
            {*directory.glob("*.yaml"), *directory.glob("*.yml")},
            key=lambda path: path.name,
        )
        for project_file in project_files:
            project = load_project_file(project_file)
            if project.name in projects:
                raise ConfigurationError(
                    f"Project '{project.name}' is declared more than once "
                    f"in '{directory}'."
                )
            projects[project.name] = project
        return cls(projects)

    def get(self, name: str) -> ProjectConfig:
        try:
            return self._projects[name]
        except KeyError as error:
            raise ProjectNotFoundError(
                f"Project '{name}' is not configured."
            ) from error

    def all(self) -> list[ProjectConfig]:
        return [self._projects[name] for name in sorted(self._projects)]
