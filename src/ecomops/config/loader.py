import os
import stat
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]
from pydantic import ValidationError

from ecomops.config.schema import ProjectConfig
from ecomops.core.exceptions import ConfigurationError

DEFAULT_PROJECTS_DIR = Path("~/.config/ecomops/projects")


def projects_directory() -> Path:
    configured_directory = os.environ.get("ECOMOPS_PROJECTS_DIR")
    return expand_path(configured_directory or DEFAULT_PROJECTS_DIR)


def expand_path(path: str | Path) -> Path:
    return Path(os.path.expandvars(str(path))).expanduser()


def validate_file_permissions(path: Path) -> None:
    _reject_if_group_or_world_writable(path, kind="Configuration file")


def validate_directory_permissions(path: Path) -> None:
    _reject_if_group_or_world_writable(path, kind="Configuration directory")


def _reject_if_group_or_world_writable(path: Path, *, kind: str) -> None:
    mode = path.stat().st_mode
    if mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ConfigurationError(
            f"{kind} '{path}' must not be group- or world-writable."
        )


def load_project_file(path: Path) -> ProjectConfig:
    validate_file_permissions(path)
    try:
        with path.open(encoding="utf-8") as config_file:
            raw_config: Any = yaml.safe_load(config_file)
    except OSError as error:
        raise ConfigurationError(
            f"Unable to read configuration file '{path}'."
        ) from error
    except yaml.YAMLError as error:
        raise ConfigurationError(
            f"Invalid YAML in configuration file '{path}'."
        ) from error

    if not isinstance(raw_config, dict):
        raise ConfigurationError(
            f"Configuration file '{path}' must contain a YAML mapping."
        )

    try:
        return ProjectConfig.model_validate(raw_config)
    except ValidationError as error:
        raise ConfigurationError(
            f"Invalid project configuration in '{path}'."
        ) from error
