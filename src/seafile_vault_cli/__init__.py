"""Seafile Vault CLI public Python API."""

from .client import (
    Config,
    ConfigError,
    LinkSecurityError,
    LocalFileError,
    PathSecurityError,
    PermissionMode,
    PermissionModeError,
    SeafileVaultClient,
    SeafileVaultError,
    SizeLimitError,
)

__all__ = [
    "Config",
    "ConfigError",
    "LinkSecurityError",
    "LocalFileError",
    "PathSecurityError",
    "PermissionMode",
    "PermissionModeError",
    "SeafileVaultClient",
    "SeafileVaultError",
    "SizeLimitError",
]

__version__ = "0.1.0"
