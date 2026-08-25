"""Unit tests for Cairo SOLID principles and code smells."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_cairo_parser import NativeCairoParserAdapter
from pattern_detector.domain.rules.solid_principles_rules import (
    FatComponentInterfaceIspRule,
    HardcodedContractAddressOcpRule,
    MonolithicContractSrpRule,
)
from pattern_detector.domain.value_objects import PatternType


def test_monolithic_contract_srp() -> None:
    funcs = "\n".join([f"    fn method_{i}(self: @ContractState) {{}}" for i in range(16)])
    code = f"""
#[starknet::contract]
mod HugeContract {{
{funcs}
}}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("huge.cairo", code)])

    rule = MonolithicContractSrpRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.MONOLITHIC_CONTRACT_SRP


def test_fat_component_interface_isp() -> None:
    methods = "\n".join([f"    fn action_{i}(ref self: TContractState);" for i in range(11)])
    code = f"""
#[starknet::interface]
pub trait IFatInterface<TContractState> {{
{methods}
}}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("fat.cairo", code)])

    rule = FatComponentInterfaceIspRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.FAT_COMPONENT_INTERFACE_ISP


def test_hardcoded_contract_address_ocp() -> None:
    code = """
fn get_admin() -> ContractAddress {
    contract_address_const::<0x123456789>()
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("addr.cairo", code)])

    rule = HardcodedContractAddressOcpRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.HARDCODED_CONTRACT_ADDRESS_OCP
