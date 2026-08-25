"""Tests verifying zero false positives on clean, idiomatic Cairo & Starknet contracts."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_cairo_parser import NativeCairoParserAdapter
from pattern_detector.domain.rules.security_rules import (
    MissingCallerVerificationHazardRule,
    UnprotectedExternalEntryHazardRule,
)
from pattern_detector.domain.rules.solid_principles_rules import MonolithicContractSrpRule


def test_clean_caller_guarded_write_no_hazard() -> None:
    code = """
#[external(v0)]
fn set_fee_protected(ref self: ContractState, new_fee: u256) {
    let caller = get_caller_address();
    assert(caller == self.owner.read(), 'NOT_OWNER');
    self.fee.write(new_fee);
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("clean.cairo", code)])

    rule = UnprotectedExternalEntryHazardRule()
    detections = rule.evaluate(model)

    assert len(detections) == 0


def test_clean_guarded_upgrade_no_hazard() -> None:
    code = """
#[external(v0)]
fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
    self.ownable.assert_only_owner();
    replace_class_hash_syscall(new_class_hash);
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("clean.cairo", code)])

    rule = MissingCallerVerificationHazardRule()
    detections = rule.evaluate(model)

    assert len(detections) == 0


def test_clean_small_contract_no_srp() -> None:
    code = """
#[starknet::contract]
mod SmallContract {
    fn helper() {}
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("clean.cairo", code)])

    rule = MonolithicContractSrpRule()
    detections = rule.evaluate(model)

    assert len(detections) == 0
