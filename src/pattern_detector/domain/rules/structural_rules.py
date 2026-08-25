"""GoF Structural design pattern detection rules for Cairo & Starknet (7/7)."""

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


class AdapterOraclePragmaWrapperRule(BaseRule):
    """Detects Adapter pattern wrapping Pragma/Empiric price feeds."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for t in model.all_traits:
            if "Oracle" in t.name or "PriceFeed" in t.name or "Pragma" in t.name:
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_ADAPTER_ORACLE",
                        description=f"Trait '{t.name}' implements Adapter pattern standardizing external Starknet price oracles",
                        weight=0.90,
                        location=t.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.ADAPTER_ORACLE_PRAGMA_WRAPPER,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=t.name,
                        target_kind="trait",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=t.location,
                        evidences=evidences,
                    )
                )
        return detections


class BridgeL1L2MessagingRule(BaseRule):
    """Detects Bridge pattern coordinating L1 <-> L2 messaging (send_message_to_l1_syscall / #[l1_handler])."""

    L1_PATTERN = re.compile(r"\b(send_message_to_l1_syscall|#\[l1_handler\])\b")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.is_l1_handler or self.L1_PATTERN.search(fn.body) or "send_message_to_l1" in fn.body:
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_BRIDGE_L1_L2",
                        description=f"Function '{fn.name}' implements Bridge Cross-Layer Messaging (L1 <-> L2)",
                        weight=0.95,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.BRIDGE_L1_L2_MESSAGING,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class CompositeMulticallBatchRule(BaseRule):
    """Detects Composite pattern executing multicall batches (Array<Call>)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if any("Array<Call>" in p or "Span<Call>" in p for p in fn.parameters) or fn.name in ("__execute__", "multicall", "execute_batch"):
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_COMPOSITE_MULTICALL",
                        description=f"Function '{fn.name}' implements Composite pattern executing heterogeneous batch calls (Array<Call>)",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.COMPOSITE_MULTICALL_BATCH,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class DecoratorStakingBoosterRule(BaseRule):
    """Detects Decorator pattern augmenting base staking balances with reward boosters."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for c in model.all_contracts:
            if "boost" in c.name.lower() or "multiplier" in c.name.lower():
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_DECORATOR_BOOSTER",
                        description=f"Contract '{c.name}' implements Decorator pattern augmenting staking positions with reward multipliers",
                        weight=0.88,
                        location=c.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.DECORATOR_STAKING_BOOSTER,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=c.name,
                        target_kind="contract",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=c.location,
                        evidences=evidences,
                    )
                )
        return detections


class FacadeRouterDispatcherRule(BaseRule):
    """Detects Facade DEX Router unifying multi-hop swaps across AMM pools."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for c in model.all_contracts:
            if "router" in c.name.lower() or "aggregator" in c.name.lower():
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_FACADE_ROUTER",
                        description=f"Contract '{c.name}' implements Facade pattern exposing high-level multi-pool swap routing entrypoints",
                        weight=0.92,
                        location=c.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.FACADE_ROUTER_DISPATCHER,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=c.name,
                        target_kind="contract",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=c.location,
                        evidences=evidences,
                    )
                )
        return detections


class FlyweightClassHashRegistryRule(BaseRule):
    """Detects Flyweight pattern managing shared ClassHash values."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for c in model.all_contracts:
            if c.storage and any("ClassHash" in f.type_str for f in c.storage.fields):
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_FLYWEIGHT_CLASS_HASH",
                        description=f"Contract '{c.name}' implements Flyweight pattern storing reusable ClassHash references for proxy instances",
                        weight=0.90,
                        location=c.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.FLYWEIGHT_CLASS_HASH_REGISTRY,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=c.name,
                        target_kind="contract",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=c.location,
                        evidences=evidences,
                    )
                )
        return detections


class ProxyDelegateDispatcherRule(BaseRule):
    """Detects Proxy pattern delegating execution via library_call_syscall or dispatcher."""

    DISPATCH_PATTERN = re.compile(r"\b(library_call_syscall|call_contract_syscall)\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.DISPATCH_PATTERN.search(fn.body) or "delegate_call" in fn.name:
                evidences = [
                    Evidence(
                        rule_code="STRUCTURAL_PROXY_DISPATCHER",
                        description=f"Function '{fn.name}' implements Proxy Delegation pattern forwarding calls via library_call / call_contract syscalls",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.PROXY_DELEGATE_DISPATCHER,
                        pattern_category=PatternCategory.STRUCTURAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
