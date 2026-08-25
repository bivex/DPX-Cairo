"""Starknet Component Upgradability & Access Control rules."""

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


class UpgradeableContractClassHashRule(BaseRule):
    """Detects Starknet Upgradeable Proxy pattern using replace_class_hash_syscall."""

    UPGRADE_PATTERN = re.compile(r"\b(replace_class_hash_syscall|upgrade)\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.UPGRADE_PATTERN.search(fn.body) or "replace_class_hash" in fn.name:
                evidences = [
                    Evidence(
                        rule_code="STARKNET_UPGRADEABLE_PROXY",
                        description=f"Function '{fn.name}' implements Upgradeable Contract pattern via replace_class_hash_syscall",
                        weight=0.95,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.UPGRADEABLE_CONTRACT_CLASS_HASH,
                        pattern_category=PatternCategory.COMPONENTS_UPGRADES,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class ComponentStorageEmbeddingRule(BaseRule):
    """Detects component substorage embedding with #[substorage(v0)]."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for c in model.all_contracts:
            if c.storage and "#[substorage(v0)]" in c.storage.raw_text:
                evidences = [
                    Evidence(
                        rule_code="STARKNET_SUBSTORAGE_EMBEDDING",
                        description=f"Contract '{c.name}' embeds component substorage via #[substorage(v0)] attribute",
                        weight=0.92,
                        location=c.storage.location or c.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.COMPONENT_STORAGE_EMBEDDING,
                        pattern_category=PatternCategory.COMPONENTS_UPGRADES,
                        target_name=c.name,
                        target_kind="storage",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=c.storage.location or c.location,
                        evidences=evidences,
                    )
                )
        return detections


class ReentrancyGuardComponentRule(BaseRule):
    """Detects integration of ReentrancyGuardComponent."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for c in model.all_contracts:
            has_guard = any("reentrancy" in comp.name.lower() or "reentrancy" in comp.path.lower() for comp in c.components)
            if has_guard:
                evidences = [
                    Evidence(
                        rule_code="STARKNET_REENTRANCY_GUARD",
                        description=f"Contract '{c.name}' embeds ReentrancyGuardComponent to prevent cross-call reentrancy exploits",
                        weight=0.95,
                        location=c.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.REENTRANCY_GUARD_COMPONENT,
                        pattern_category=PatternCategory.COMPONENTS_UPGRADES,
                        target_name=c.name,
                        target_kind="contract",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=c.location,
                        evidences=evidences,
                    )
                )
        return detections


class OwnableAccessControlComponentRule(BaseRule):
    """Detects integration of OwnableComponent or AccessControlComponent."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for c in model.all_contracts:
            has_ownable = any("ownable" in comp.name.lower() or "accesscontrol" in comp.name.lower() for comp in c.components)
            if has_ownable:
                evidences = [
                    Evidence(
                        rule_code="STARKNET_OWNABLE_ACCESS_CONTROL",
                        description=f"Contract '{c.name}' embeds Ownable / AccessControl component for role-based authorization",
                        weight=0.95,
                        location=c.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.OWNABLE_ACCESS_CONTROL_COMPONENT,
                        pattern_category=PatternCategory.COMPONENTS_UPGRADES,
                        target_name=c.name,
                        target_kind="contract",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=c.location,
                        evidences=evidences,
                    )
                )
        return detections
