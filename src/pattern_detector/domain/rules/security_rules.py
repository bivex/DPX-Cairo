"""Starknet Smart Contract Security & Hazard detection rules."""

from __future__ import annotations

import re
from pattern_detector.domain.code_model import CodeModel
from pattern_detector.domain.detection import Detection
from pattern_detector.domain.rules.base import BaseRule
from pattern_detector.domain.value_objects import (
    Confidence,
    Evidence,
    PatternCategory,
    PatternType,
)


class UnprotectedExternalEntryHazardRule(BaseRule):
    """Detects external entrypoints modifying state without caller verification."""

    WRITE_PATTERN = re.compile(r"\bself\.\w+\.write\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.is_external and self.WRITE_PATTERN.search(fn.body):
                if not fn.has_caller_check and "get_caller_address" not in fn.body and not fn.has_assert:
                    evidences = [
                        Evidence(
                            rule_code="HAZARD_UNPROTECTED_EXTERNAL_WRITE",
                            description=f"External entry function '{fn.name}' mutates contract storage without get_caller_address() authorization check",
                            weight=0.92,
                            location=fn.location,
                        )
                    ]
                    detections.append(
                        Detection(
                            pattern_type=PatternType.UNPROTECTED_EXTERNAL_ENTRY_HAZARD,
                            pattern_category=PatternCategory.STARKNET_SECURITY_HAZARDS,
                            target_name=fn.name,
                            target_kind="fn",
                            confidence=Confidence(score=0.92, evidences=evidences),
                            primary_location=fn.location,
                            evidences=evidences,
                        )
                    )
        return detections


class MissingCallerVerificationHazardRule(BaseRule):
    """Detects critical admin/upgrade functions lacking access control."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            is_admin_name = any(kw in fn.name.lower() for kw in ("upgrade", "set_admin", "set_owner", "mint_unlimited", "drain", "set_fee"))
            if is_admin_name and fn.is_external:
                if not fn.has_caller_check and "get_caller_address" not in fn.body and not fn.has_assert and "assert_only_owner" not in fn.body:
                    evidences = [
                        Evidence(
                            rule_code="HAZARD_MISSING_CALLER_CHECK",
                            description=f"Administrative function '{fn.name}' lacks caller verification / access control guard",
                            weight=0.95,
                            location=fn.location,
                        )
                    ]
                    detections.append(
                        Detection(
                            pattern_type=PatternType.MISSING_CALLER_VERIFICATION_HAZARD,
                            pattern_category=PatternCategory.STARKNET_SECURITY_HAZARDS,
                            target_name=fn.name,
                            target_kind="fn",
                            confidence=Confidence(score=0.95, evidences=evidences),
                            primary_location=fn.location,
                            evidences=evidences,
                        )
                    )
        return detections


class UnboundedStorageLoopDosHazardRule(BaseRule):
    """Detects unbounded loop over dynamic array risking transaction step exhaustion."""

    LOOP_PATTERN = re.compile(r"\b(while|loop)\s*\{[\s\S]*?\b\w+\.len\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.LOOP_PATTERN.search(fn.body) and not fn.has_assert:
                evidences = [
                    Evidence(
                        rule_code="HAZARD_UNBOUNDED_STORAGE_LOOP_DOS",
                        description=f"Function '{fn.name}' loops over dynamic array length without bounds check, risking Transaction Step Gas Exhaustion",
                        weight=0.88,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.UNBOUNDED_STORAGE_LOOP_DOS_HAZARD,
                        pattern_category=PatternCategory.STARKNET_SECURITY_HAZARDS,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class L1L2ReentrancyHazardRule(BaseRule):
    """Detects L1 message handler invoking external contract before updating storage."""

    DISPATCH_BEFORE_WRITE = re.compile(r"\bcall_contract_syscall[\s\S]*?\b\w+\.write\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if (fn.is_l1_handler or "#[l1_handler]" in fn.raw_text) and self.DISPATCH_BEFORE_WRITE.search(fn.body):
                evidences = [
                    Evidence(
                        rule_code="HAZARD_L1_L2_REENTRANCY",
                        description=f"L1 message handler '{fn.name}' performs external calls before updating storage, violating Checks-Effects-Interactions (CEI)",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.L1_L2_REENTRANCY_HAZARD,
                        pattern_category=PatternCategory.STARKNET_SECURITY_HAZARDS,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
