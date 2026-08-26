"""
AutoRedTeam - Configuration Loader.

Loads settings from config/config.yaml and merges them with environment
variables and CLI overrides. Provides typed access to model, audit and
red-team execution settings.
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

CONFIG_PATH = Path(__file__).parent.parent / "config" / "config.yaml"


class AppConfig:
    """Typed wrapper around the merged configuration dictionary."""

    def __init__(self, raw: Dict[str, Any]):
        self._raw = raw

    @property
    def app(self) -> Dict[str, Any]:
        return self._raw.get("app", {})

    @property
    def models(self) -> Dict[str, Any]:
        return self._raw.get("models", {})

    @property
    def audit(self) -> Dict[str, Any]:
        return self._raw.get("audit", {})

    def victim(self) -> Dict[str, Any]:
        return self.models.get("victim", {})

    def attacker(self) -> Dict[str, Any]:
        return self.models.get("attacker", {})

    def evaluator(self) -> Dict[str, Any]:
        return self.models.get("evaluator", {})

    def guarded_secrets(self) -> list:
        return self.audit.get("secrets_to_guard", [])

    def get(self, key: str, default: Any = None) -> Any:
        return self._raw.get(key, default)


def load_config(path: Optional[Path] = None) -> AppConfig:
    """Loads and returns the application configuration."""
    cfg_path = path or CONFIG_PATH
    raw: Dict[str, Any] = {}
    if cfg_path.exists():
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    raw = loaded
        except Exception as e:
            print(f"[config] Warning: could not load {cfg_path}: {e}")
    return AppConfig(raw)
