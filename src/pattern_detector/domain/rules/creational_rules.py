"""GoF Creational design pattern detection rules for Cairo & Starknet (5/5)."""

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


class SingletonContractStateRule(BaseRule):
    """Detects Singleton pattern via Starknet contract persistent storage state."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for c in model.all_contracts:
            if c.is_starknet_contract and c.storage:
                evidences = [
                    Evidence(
                        rule_code="CREATIONAL_SINGLETON_CONTRACT_STORAGE",
                        description=f"Contract '{c.name}' implements Singleton Contract Storage managing state at a deterministic Starknet address",
                        weight=0.92,
                        location=c.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.SINGLETON_CONTRACT_STATE,
                        pattern_category=PatternCategory.CREATIONAL,
                        target_name=c.name,
                        target_kind="contract",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=c.location,
                        evidences=evidences,
                    )
                )
        return detections


class FactoryContractDeploySyscallRule(BaseRule):
    """Detects Factory pattern deploying child contracts on-chain via deploy_syscall."""

    DEPLOY_PATTERN = re.compile(r"\b(deploy_syscall|starknet::deploy_syscall)\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.DEPLOY_PATTERN.search(fn.body) or "deploy_contract" in fn.name:
                evidences = [
                    Evidence(
                        rule_code="CREATIONAL_FACTORY_DEPLOY",
                        description=f"Function '{fn.name}' implements Factory Contract pattern deploying new instances via deploy_syscall",
                        weight=0.95,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.FACTORY_CONTRACT_DEPLOY_SYSCALL,
                        pattern_category=PatternCategory.CREATIONAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class AbstractFactoryPoolCreatorRule(BaseRule):
    """Detects Abstract Factory creating generic liquidity pools and market vaults."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if "create_pool" in fn.name or "create_pair" in fn.name or "spawn_vault" in fn.name:
                evidences = [
                    Evidence(
                        rule_code="CREATIONAL_ABSTRACT_FACTORY_POOL",
                        description=f"Function '{fn.name}' implements Abstract Factory creating decentralized pool/pair instances",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.ABSTRACT_FACTORY_POOL_CREATOR,
                        pattern_category=PatternCategory.CREATIONAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class BuilderMultisigPayloadRule(BaseRule):
    """Detects Builder pattern assembling arrays of execution calls (Array<Call>)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if "build_calls" in fn.name or "build_payload" in fn.name or ("Array<Call>" in fn.return_type and "append" in fn.body):
                evidences = [
                    Evidence(
                        rule_code="CREATIONAL_BUILDER_CALLS",
                        description=f"Function '{fn.name}' implements Builder pattern assembling batch execution calls (Array<Call>)",
                        weight=0.90,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.BUILDER_MULTISIG_PAYLOAD,
                        pattern_category=PatternCategory.CREATIONAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class PrototypeArraySpanSliceRule(BaseRule):
    """Detects Prototype pattern slicing data spans (span.slice) without allocations."""

    SLICE_PATTERN = re.compile(r"\b\w+\.slice\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.SLICE_PATTERN.search(fn.body):
                evidences = [
                    Evidence(
                        rule_code="CREATIONAL_PROTOTYPE_SPAN_SLICE",
                        description=f"Function '{fn.name}' implements Prototype Span Slice pattern creating memory-efficient sub-views",
                        weight=0.90,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.PROTOTYPE_ARRAY_SPAN_SLICE,
                        pattern_category=PatternCategory.CREATIONAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
