"""Seafile Vault CLI public Python API."""

from .client import (
    Config,
    ConfigError,
    LinkSecurityError,
    LocalFileError,
    LockNotActiveError,
    PathSecurityError,
    PermissionMode,
    PermissionModeError,
    RemoteNotFoundError,
    SeafileVaultClient,
    SeafileVaultError,
    SizeLimitError,
)

__all__ = [
    "Config",
    "ConfigError",
    "LinkSecurityError",
    "LockNotActiveError",
    "LocalFileError",
    "PathSecurityError",
    "PermissionMode",
    "PermissionModeError",
    "RemoteNotFoundError",
    "SeafileVaultClient",
    "SeafileVaultError",
    "SizeLimitError",
]

__version__ = "0.4.1"
