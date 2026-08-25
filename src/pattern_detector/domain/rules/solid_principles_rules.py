"""SOLID principles and Cairo / Starknet code quality smell rules."""

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


class MonolithicContractSrpRule(BaseRule):
    """Detects monolithic contracts declaring excessive functions (>= 15) or storage fields (>= 10)."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for c in model.all_contracts:
            storage_fields_cnt = len(c.storage.fields) if c.storage else 0
            fn_cnt = len(c.all_functions)
            if fn_cnt >= 15 or storage_fields_cnt >= 10:
                evidences = [
                    Evidence(
                        rule_code="SRP_MONOLITHIC_CONTRACT",
                        description=f"Contract '{c.name}' defines {fn_cnt} functions and {storage_fields_cnt} storage fields; decompose into reusable Starknet components",
                        weight=0.88,
                        location=c.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.MONOLITHIC_CONTRACT_SRP,
                        pattern_category=PatternCategory.PRINCIPLE,
                        target_name=c.name,
                        target_kind="contract",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=c.location,
                        evidences=evidences,
                    )
                )
        return detections


class FatComponentInterfaceIspRule(BaseRule):
    """Detects fat interface traits declaring excessive methods (>= 10), violating Interface Segregation."""

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for t in model.all_traits:
            if len(t.methods) >= 10:
                evidences = [
                    Evidence(
                        rule_code="ISP_FAT_INTERFACE",
                        description=f"Trait '{t.name}' declares {len(t.methods)} methods; decompose into focused role interfaces",
                        weight=0.88,
                        location=t.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.FAT_COMPONENT_INTERFACE_ISP,
                        pattern_category=PatternCategory.PRINCIPLE,
                        target_name=t.name,
                        target_kind="trait",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=t.location,
                        evidences=evidences,
                    )
                )
        return detections


class HardcodedContractAddressOcpRule(BaseRule):
    """Detects hardcoding literal hex addresses (contract_address_const::<0x...>) instead of storage variables."""

    HEX_ADDR_PATTERN = re.compile(r"contract_address_const::<[0-9a-fA-Fx]+>")

    def evaluate(self, model: CodeModel) -> list[Detection]:
        detections: list[Detection] = []
        for fn in model.all_functions:
            matches = self.HEX_ADDR_PATTERN.findall(fn.body)
            if matches:
                evidences = [
                    Evidence(
                        rule_code="OCP_HARDCODED_CONTRACT_ADDRESS",
                        description=f"Function '{fn.name}' hardcodes literal contract address '{matches[0]}'; initialize via constructor or storage variables",
                        weight=0.88,
                        location=fn.location,
                    )
                ]
                detections.append(
                    Detection(
                        pattern_type=PatternType.HARDCODED_CONTRACT_ADDRESS_OCP,
                        pattern_category=PatternCategory.PRINCIPLE,
                        target_name=fn.name,
                        target_kind="fn",
                        confidence=Confidence(score=0.88, evidences=evidences),
                        primary_location=fn.location,
                        evidences=evidences,
                    )
                )
        return detections
