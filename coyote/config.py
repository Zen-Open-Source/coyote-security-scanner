"""Configuration loading and defaults for Coyote."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import yaml


@dataclass
class TargetConfig:
    repo_url: str = ""
    branch: str = "main"
    local_path: str = "./watched_repo"


@dataclass
class PollingConfig:
    interval_seconds: int = 60


@dataclass
class ScanConfig:
    exclude_paths: list[str] = field(default_factory=lambda: [
        "node_modules/", "venv/", ".git/", "vendor/", "__pycache__/",
    ])
    exclude_extensions: list[str] = field(default_factory=lambda: [
        ".min.js", ".map", ".lock",
    ])
    max_file_size_mb: int = 5


@dataclass
class NotificationsConfig:
    console: bool = True


@dataclass
class OutputConfig:
    report_dir: str = "./reports"
    format: list[str] = field(default_factory=lambda: ["json", "markdown"])


@dataclass
class CoyoteConfig:
    target: TargetConfig = field(default_factory=TargetConfig)
    polling: PollingConfig = field(default_factory=PollingConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)
    output: OutputConfig = field(default_factory=OutputConfig)

    @property
    def max_file_size_bytes(self) -> int:
        return self.scan.max_file_size_mb * 1024 * 1024


def _apply_dict(target: Any, data: dict) -> None:
    """Apply a dict of values onto a dataclass instance."""
    for key, value in data.items():
        if hasattr(target, key):
            current = getattr(target, key)
            if isinstance(current, (TargetConfig, PollingConfig, ScanConfig,
                                    NotificationsConfig, OutputConfig)):
                if isinstance(value, dict):
                    _apply_dict(current, value)
            else:
                setattr(target, key, value)


def load_config(path: str = "config.yaml") -> CoyoteConfig:
    """Load configuration from a YAML file, falling back to defaults."""
    config = CoyoteConfig()

    if not os.path.isfile(path):
        return config

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if data and isinstance(data, dict):
        _apply_dict(config, data)

    return config
