"""Outbound driven ports for DPX-Cairo."""

from __future__ import annotations

from typing import Protocol
from pattern_detector.domain.code_model import CairoFile, CodeModel
from pattern_detector.domain.detection import DetectionReport


class SourceProviderPort(Protocol):
    """Port for discovering and reading Cairo source files (.cairo)."""

    def load_files(self, target_path: str, extensions: list[str], exclude_dirs: list[str] | None = None) -> list[tuple[str, str]]:
        """Return list of (file_path, file_content)."""
        ...


class ParserPort(Protocol):
    """Port for parsing Cairo source text into CodeModel."""

    def parse_file(self, file_path: str, content: str) -> CairoFile:
        """Parse a single Cairo file into CairoFile model."""
        ...

    def parse_codebase(self, files: list[tuple[str, str]], target_path: str = "") -> CodeModel:
        """Parse multiple Cairo files into an aggregated CodeModel."""
        ...


class ReportFormatterPort(Protocol):
    """Port for formatting DetectionReport into string representation."""

    def format(self, report: DetectionReport, verbose: bool = False) -> str:
        """Format report into string representation."""
        ...


class ResultRepositoryPort(Protocol):
    """Port for persisting formatted detection reports to disk."""

    def save(self, report: DetectionReport, destination_path: str, verbose: bool = False) -> None:
        """Save report to destination path."""
        ...
