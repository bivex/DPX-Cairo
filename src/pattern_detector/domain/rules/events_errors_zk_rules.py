"""Starknet Events, Short String Panics & ZK Cryptographic Builtin rules."""

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


class StarknetEventVariantEmissionRule(BaseRule):
    """Detects Starknet Event emission via self.emit(Event::...)."""

    EMIT_PATTERN = re.compile(r"\bself\.emit\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.has_emit or self.EMIT_PATTERN.search(fn.body):
                evidences = [
                    Evidence(
                        rule_code="STARKNET_EVENT_EMISSION",
                        description=f"Function '{fn.name}' emits structured Starknet Event variants via self.emit()",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.STARKNET_EVENT_VARIANT_EMISSION,
                        pattern_category=PatternCategory.EVENTS_ERRORS_ZK,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class Felt252ShortStringErrorsRule(BaseRule):
    """Detects gas-efficient felt252 short string errors in assert() statements."""

    SHORT_STR_PATTERN = re.compile(r"\bassert!\s*\([^,]+,\s*'[^']+'\)")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.SHORT_STR_PATTERN.search(fn.body) or ("assert(" in fn.body and "'" in fn.body):
                evidences = [
                    Evidence(
                        rule_code="CAIRO_SHORT_STRING_ERROR",
                        description=f"Function '{fn.name}' uses gas-efficient felt252 short string error panics in assertions",
                        weight=0.90,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.FELT252_SHORT_STRING_ERRORS,
                        pattern_category=PatternCategory.EVENTS_ERRORS_ZK,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class PedersenPoseidonHashBuiltinRule(BaseRule):
    """Detects STARK-friendly algebraic hash builtins (Poseidon / Pedersen)."""

    HASH_PATTERN = re.compile(r"\b(poseidon_hash_span|pedersen|core::poseidon|core::pedersen)\b")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.HASH_PATTERN.search(fn.body):
                evidences = [
                    Evidence(
                        rule_code="CAIRO_ZK_HASH_BUILTIN",
                        description=f"Function '{fn.name}' computes algebraic STARK-friendly hashes (Poseidon / Pedersen)",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.PEDERSEN_POSEIDON_HASH_BUILTIN,
                        pattern_category=PatternCategory.EVENTS_ERRORS_ZK,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
