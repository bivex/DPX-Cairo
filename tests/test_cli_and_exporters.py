"""Unit tests for CLI commands and JSON/Markdown/SARIF/HTML/LLM exporters for Cairo."""

from __future__ import annotations

import json
from typer.testing import CliRunner

from pattern_detector.adapters.inbound.cli.main import app
from pattern_detector.adapters.outbound.persistence.formatters import (
    JsonReportFormatter,
    MarkdownReportFormatter,
    SarifReportFormatter,
)
from pattern_detector.adapters.outbound.persistence.html_report_formatter import HtmlReportFormatter
from pattern_detector.adapters.outbound.persistence.llm_report_formatter import LlmReportFormatter
from pattern_detector.domain.detection import Detection, DetectionReport
from pattern_detector.domain.value_objects import (
    Confidence,
    Evidence,
    PatternCategory,
    PatternType,
    SourceLocation,
)

runner = CliRunner()


def _dummy_report() -> DetectionReport:
    ev = Evidence(
        rule_code="CAIRO_TEST",
        description="Test heuristic for Starknet component composition",
        weight=0.95,
        location=SourceLocation("contract.cairo", 10),
    )
    det = Detection(
        pattern_type=PatternType.STARKNET_CONTRACT_COMPONENT_COMPOSITION,
        pattern_category=PatternCategory.CAIRO_IDIOMATIC_STARKNET,
        target_name="MyContract",
        target_kind="contract",
        confidence=Confidence(score=0.95, evidences=[ev]),
        primary_location=SourceLocation("contract.cairo", 10),
        evidences=[ev],
    )
    return DetectionReport(
        project_path="test_project",
        scanned_files_count=1,
        detections=[det],
        elapsed_seconds=0.012,
    )


def test_cli_rules_command() -> None:
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "DPX-Cairo" in result.stdout
    assert "Component Composition" in result.stdout or "Component" in result.stdout


def test_cli_info_command() -> None:
    result = runner.invoke(app, ["info", "starknet_contract_component_composition"])
    assert result.exit_code == 0
    assert "Component Composition" in result.stdout


def test_exporters_format() -> None:
    rep = _dummy_report()

    json_out = JsonReportFormatter().format(rep)
    data = json.loads(json_out)
    assert data["total_detections_count"] == 1

    md_out = MarkdownReportFormatter().format(rep)
    assert "# ⚡ DPX-Cairo: Cairo & Starknet Smart Contract Architectural Pattern Report" in md_out

    sarif_out = SarifReportFormatter().format(rep)
    sarif_data = json.loads(sarif_out)
    assert sarif_data["version"] == "2.1.0"

    html_out = HtmlReportFormatter().format(rep)
    assert "DPX-Cairo Architecture & Starknet Observability HUD" in html_out

    llm_out = LlmReportFormatter().format_scan_report(rep)
    assert '<codebase_architecture_analysis language="cairo">' in llm_out
