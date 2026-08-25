"""Cairo Idiomatic, Starknet & Sierra Architecture rules."""

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


class StarknetContractComponentCompositionRule(BaseRule):
    """Detects Starknet Component composition (component!(...) and #[abi(embed_v0)])."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for c in model.all_contracts:
            if c.components or c.is_starknet_component:
                evidences = [
                    Evidence(
                        rule_code="STARKNET_COMPONENT_COMPOSITION",
                        description=f"Contract/Component '{c.name}' implements Starknet Component Composition with {len(c.components)} embedded component mixin(s)",
                        weight=0.95,
                        location=c.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.STARKNET_CONTRACT_COMPONENT_COMPOSITION,
                        pattern_category=PatternCategory.CAIRO_IDIOMATIC_STARKNET,
                        target_name=c.name,
                        target_kind="contract" if c.is_starknet_contract else "component",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=c.location,
                        evidences=evidences,
                    )
                )
        return detections


class StarknetInterfaceAbiDefinitionRule(BaseRule):
    """Detects Starknet external interface traits declared with #[starknet::interface]."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for t in model.all_traits:
            if t.is_starknet_interface:
                evidences = [
                    Evidence(
                        rule_code="STARKNET_INTERFACE_ABI",
                        description=f"Trait '{t.name}' defines Starknet Contract ABI Interface (#[starknet::interface]) with {len(t.methods)} method(s)",
                        weight=0.95,
                        location=t.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.STARKNET_INTERFACE_ABI_DEFINITION,
                        pattern_category=PatternCategory.CAIRO_IDIOMATIC_STARKNET,
                        target_name=t.name,
                        target_kind="interface",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=t.location,
                        evidences=evidences,
                    )
                )
        return detections


class StorageMappingDataLayoutRule(BaseRule):
    """Detects persistent contract storage declaring Map<K, V> or Vec<T> under #[storage]."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for c in model.all_contracts:
            if c.storage and (c.storage.has_mapping or c.storage.has_vec or len(c.storage.fields) > 0):
                evidences = [
                    Evidence(
                        rule_code="STARKNET_STORAGE_MAPPING",
                        description=f"Contract '{c.name}' defines Starknet Storage Layout with {len(c.storage.fields)} persistent field(s) (Map / Vec)",
                        weight=0.95,
                        location=c.storage.location or c.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.STORAGE_MAPPING_DATA_LAYOUT,
                        pattern_category=PatternCategory.CAIRO_IDIOMATIC_STARKNET,
                        target_name=c.name,
                        target_kind="storage",
                        confidence=Confidence(score=0.95, evidences=evidences),
                        primary_location=c.storage.location or c.location,
                        evidences=evidences,
                    )
                )
        return detections


class AccountAbstractionValidationRule(BaseRule):
    """Detects Starknet native Account Abstraction entrypoints (__validate__, __execute__)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for c in model.all_contracts:
            fn_names = {fn.name for fn in c.all_functions}
            if "__validate__" in fn_names or "__execute__" in fn_names or "__validate_declare__" in fn_names:
                evidences = [
                    Evidence(
                        rule_code="STARKNET_ACCOUNT_ABSTRACTION",
                        description=f"Contract '{c.name}' implements Starknet Native Account Abstraction protocol (__validate__, __execute__)",
                        weight=0.98,
                        location=c.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.ACCOUNT_ABSTRACTION_VALIDATION,
                        pattern_category=PatternCategory.CAIRO_IDIOMATIC_STARKNET,
                        target_name=c.name,
                        target_kind="contract",
                        confidence=Confidence(score=0.98, evidences=evidences),
                        primary_location=c.location,
                        evidences=evidences,
                    )
                )
        return detections


class Felt252FieldArithmeticRule(BaseRule):
    """Detects prime field element (felt252) arithmetic and parameters."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if any("felt252" in p for p in fn.parameters) or "felt252" in fn.return_type or "felt252" in fn.raw_text:
                evidences = [
                    Evidence(
                        rule_code="CAIRO_FELT252_ARITHMETIC",
                        description=f"Function '{fn.name}' operates on STARK prime field elements (felt252)",
                        weight=0.88,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.FELT252_FIELD_ARITHMETIC,
                        pattern_category=PatternCategory.CAIRO_IDIOMATIC_STARKNET,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections


class StarknetSyscallDispatcherRule(BaseRule):
    """Detects Starknet execution context syscalls (get_caller_address, get_contract_address, get_block_timestamp)."""

    SYSCALL_PATTERN = re.compile(
        r"\b(get_caller_address|get_contract_address|get_block_timestamp|get_block_number|get_tx_info|call_contract_syscall|deploy_syscall)\s*\("
    )

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            if fn.has_syscall or self.SYSCALL_PATTERN.search(fn.body):
                evidences = [
                    Evidence(
                        rule_code="STARKNET_SYSCALL_DISPATCHER",
                        description=f"Function '{fn.name}' invokes Starknet execution environment syscalls",
                        weight=0.92,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.STARKNET_SYSCALL_DISPATCHER,
                        pattern_category=PatternCategory.CAIRO_IDIOMATIC_STARKNET,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.92, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
