"""Shared utilities for source-file discovery."""

from dataclasses import dataclass
import os
from pathlib import Path


IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        "node_modules",
        "venv",
        ".venv",
        "__pycache__",
        ".next",
        "dist",
        "build",
    }
)

SUPPORTED_EXTENSIONS = frozenset(
    {
        ".py",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".java",
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".go",
        ".rs",
        ".php",
        ".rb",
        ".yaml",
        ".yml",
        ".json",
        ".xml",
        ".conf",
        ".config",
    }
)


@dataclass(frozen=True)
class DiscoveredFile:
    """Metadata for a supported source or configuration file."""

    path: Path
    relative_path: Path
    extension: str


def read_source_text(file_path: Path) -> str | None:
    """Read a supported text file, returning ``None`` for binary content."""

    try:
        raw_content = file_path.read_bytes()
    except OSError as error:
        raise ValueError(f"Unable to read source file: {file_path}") from error

    if b"\x00" in raw_content[:4096]:
        return None

    try:
        return raw_content.decode("utf-8")
    except UnicodeDecodeError:
        return raw_content.decode("utf-8", errors="replace")


def discover_source_files(repository_path: Path) -> list[DiscoveredFile]:
    """Recursively discover supported files without opening their contents."""

    discovered: list[DiscoveredFile] = []
    for root, directories, filenames in os.walk(repository_path):
        directories[:] = sorted(
            directory
            for directory in directories
            if directory not in IGNORED_DIRECTORIES
        )
        for filename in sorted(filenames):
            file_path = Path(root) / filename
            extension = file_path.suffix.lower()
            if extension not in SUPPORTED_EXTENSIONS:
                continue
            discovered.append(
                DiscoveredFile(
                    path=file_path,
                    relative_path=file_path.relative_to(repository_path),
                    extension=extension,
                )
            )
    return discovered
