"""Unit tests for Starknet smart contract security hazards."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_cairo_parser import NativeCairoParserAdapter
from pattern_detector.domain.rules.security_rules import (
    L1L2ReentrancyHazardRule,
    MissingCallerVerificationHazardRule,
    UnboundedStorageLoopDosHazardRule,
    UnprotectedExternalEntryHazardRule,
)
from pattern_detector.domain.value_objects import PatternType


def test_unprotected_external_entry_hazard() -> None:
    code = """
#[external(v0)]
fn set_fee_unprotected(ref self: ContractState, new_fee: u256) {
    self.fee.write(new_fee);
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("unsafe.cairo", code)])

    rule = UnprotectedExternalEntryHazardRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.UNPROTECTED_EXTERNAL_ENTRY_HAZARD


def test_missing_caller_verification_hazard() -> None:
    code = """
#[external(v0)]
fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("unsafe.cairo", code)])

    rule = MissingCallerVerificationHazardRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.MISSING_CALLER_VERIFICATION_HAZARD


def test_unbounded_storage_loop_dos_hazard() -> None:
    code = """
fn loop_all(data: Array<u256>) {
    loop {
        let l = data.len();
    };
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("unsafe.cairo", code)])

    rule = UnboundedStorageLoopDosHazardRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.UNBOUNDED_STORAGE_LOOP_DOS_HAZARD


def test_l1_l2_reentrancy_hazard() -> None:
    code = """
#[l1_handler]
fn process_msg(from: felt252) {
    call_contract_syscall(0.try_into().unwrap(), 0, array![].span());
    self.balance.write(100);
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("unsafe.cairo", code)])

    rule = L1L2ReentrancyHazardRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.L1_L2_REENTRANCY_HAZARD
