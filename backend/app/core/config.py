"""Application configuration.

This module handles all configuration settings for the application.
Environment variables can override defaults, making the app easy to
deploy in different environments (dev, staging, production).

Example: set ``ECDAT_HOST`` and ``ECDAT_PORT`` in a ``.env`` file
or in your shell to override the defaults below.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central settings for the ECDAT application.

    Uses pydantic-settings so every field can be overridden
    through environment variables prefixed with ``ECDAT_``.
    """

    # -- General app settings --------------------------------------------
    project_name: str = "Q-BITS-ECDAT"
    project_description: str = (
        "Enterprise Cryptographic Discovery and Analysis Tool - "
        "cryptographic inventory, CBOM generation, "
        "quantum-risk assessment and PQC migration prioritization"
    )
    version: str = "0.1.0"
    debug: bool = True

    # -- Server settings --------------------------------------------------
    host: str = "0.0.0.0"
    port: int = 8000

    # -- Scanning settings -------------------------------------------------
    # Maximum number of files to scan in a single run (0 = unlimited).
    max_files_to_scan: int = 0
    # File extensions we will scan for cryptographic usage.
    supported_extensions: list[str] = [".py", ".java", ".js", ".ts"]
    # Directories that should always be skipped during scanning.
    excluded_dirs: list[str] = [
        ".git",
        "__pycache__",
        "node_modules",
        "venv",
        ".venv",
        "env",
        "dist",
        "build",
    ]

    # -- Model configuration for pydantic-settings ------------------------
    model_config = SettingsConfigDict(
        env_prefix="ECDAT_",  # e.g. ECDAT_HOST, ECDAT_PORT
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance.

    ``lru_cache`` ensures the settings are loaded from the
    environment only once, then re-used for every request.
    """
    return Settings()


# A ready-to-use instance so other modules can simply do:
#   from backend.app.core.config import settings
settings = get_settings()
