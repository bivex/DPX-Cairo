"""GoF Behavioral design pattern detection rules for Cairo & Starknet (11/11)."""

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


class ChainOfResponsibilityPermissionPipeRule(BaseRule):
    """Detects Chain of Responsibility permission checks."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.name.startswith("validate_") or "check_permissions" in fn.name or "verify_rules" in fn.name:
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_CHAIN_PERMISSION",
                        description=f"Function '{fn.name}' implements Chain of Responsibility validating transaction permissions sequentially",
                        weight=0.88,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.CHAIN_OF_RESPONSIBILITY_PERMISSION_PIPE,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class CommandAccountCallPayloadRule(BaseRule):
    """Detects Command pattern encapsulating executable Call structs."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if "Call" in fn.parameters or "execute_call" in fn.name or "execute_from_outside" in fn.name:
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_COMMAND_CALL",
                        description=f"Function '{fn.name}' implements Command pattern executing strongly typed Call structs",
                        weight=0.90,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.COMMAND_ACCOUNT_CALL_PAYLOAD,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class InterpreterBytecodeEvaluatorRule(BaseRule):
    """Detects Interpreter pattern evaluating on-chain rules or bytecode."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.name in ("eval", "evaluate", "interpret", "exec_op", "evaluate_rule"):
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_INTERPRETER_BYTECODE",
                        description=f"Function '{fn.name}' evaluates on-chain DSL rules or execution byte buffers",
                        weight=0.90,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.INTERPRETER_BYTECODE_EVALUATOR,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class IteratorSpanCursorScanRule(BaseRule):
    """Detects Iterator pattern scanning spans with pop_front() or index loops."""

    SPAN_SCAN_PATTERN = re.compile(r"\b\w+\.pop_front\s*\(")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if self.SPAN_SCAN_PATTERN.search(fn.body) or ("loop " in fn.body and "span" in fn.body):
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_ITERATOR_SPAN_SCAN",
                        description=f"Function '{fn.name}' implements Iterator pattern consuming Span elements sequentially",
                        weight=0.90,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.ITERATOR_SPAN_CURSOR_SCAN,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class MediatorEscrowAtomicSwapRule(BaseRule):
    """Detects Mediator pattern coordinating atomic token exchanges."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for c in model.all_contracts:
            if "escrow" in c.name.lower() or "swap" in c.name.lower() or "settlement" in c.name.lower():
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_MEDIATOR_ESCROW",
                        description=f"Contract '{c.name}' implements Mediator pattern coordinating atomic asset exchange between counterparties",
                        weight=0.90,
                        location=c.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.MEDIATOR_ESCROW_ATOMIC_SWAP,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=c.name,
                        target_kind="contract",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=c.location,
                        evidences=evidences,
                    )
                )
        return detections


class MementoCheckpointSnapshotRule(BaseRule):
    """Detects Memento state snapshots for historical block checkpoints or voting balances."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for c in model.all_contracts:
            if "checkpoint" in c.name.lower() or "snapshot" in c.name.lower() or "history" in c.name.lower():
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_MEMENTO_SNAPSHOT",
                        description=f"Contract '{c.name}' captures historical block/state checkpoints (Memento pattern)",
                        weight=0.90,
                        location=c.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.MEMENTO_CHECKPOINT_SNAPSHOT,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=c.name,
                        target_kind="contract",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=c.location,
                        evidences=evidences,
                    )
                )
        return detections


class ObserverEventEmissionRule(BaseRule):
    """Detects Observer pattern emitting typed events."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.has_emit or "self.emit" in fn.body:
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_OBSERVER_EVENT",
                        description=f"Function '{fn.name}' implements Observer pattern broadcasting state changes via Starknet events",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.OBSERVER_EVENT_EMISSION,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class StateMachineVaultLifecycleRule(BaseRule):
    """Detects State Machine protocol lifecycle states."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for c in model.all_contracts:
            if "state" in c.name.lower() or "lifecycle" in c.name.lower() or "phase" in c.name.lower():
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_STATE_LIFECYCLE",
                        description=f"Contract '{c.name}' implements State Machine pattern coordinating protocol operational states",
                        weight=0.88,
                        location=c.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.STATE_MACHINE_VAULT_LIFECYCLE,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=c.name,
                        target_kind="contract",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=c.location,
                        evidences=evidences,
                    )
                )
        return detections


class StrategyYieldHarvestInjectionRule(BaseRule):
    """Detects Strategy pattern injecting interchangeable yield/rebalance logic."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for c in model.all_contracts:
            if "strategy" in c.name.lower() or "harvest" in c.name.lower():
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_STRATEGY_INJECTION",
                        description=f"Contract '{c.name}' implements Strategy pattern providing interchangeable yield algorithms",
                        weight=0.90,
                        location=c.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.STRATEGY_YIELD_HARVEST_INJECTION,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=c.name,
                        target_kind="contract",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=c.location,
                        evidences=evidences,
                    )
                )
        return detections


class TemplateMethodHookLifecycleRule(BaseRule):
    """Detects Template Method lifecycle coordinating execution with pre/post hooks."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.name in ("execute", "process", "settle") and any(f"before_{fn.name}" in fn.body or f"after_{fn.name}" in fn.body or "check_preconditions" in fn.body for f in [fn]):
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_TEMPLATE_METHOD",
                        description=f"Function '{fn.name}' implements Template Method pattern coordinating execution with pre/post hook checks",
                        weight=0.90,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.TEMPLATE_METHOD_HOOK_LIFECYCLE,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.90, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class VisitorFlashloanReceiverRule(BaseRule):
    """Detects Flashloan callback receiver hook patterns."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if "on_flash_loan" in fn.name or "flash_borrow" in fn.name or "execute_operation" in fn.name:
                evidences = [
                    Evidence(
                        rule_code="BEHAVIORAL_VISITOR_FLASHLOAN",
                        description=f"Function '{fn.name}' implements Visitor Callback Receiver for flashloans / cross-contract composability",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.VISITOR_FLASHLOAN_RECEIVER,
                        pattern_category=PatternCategory.BEHAVIORAL,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
