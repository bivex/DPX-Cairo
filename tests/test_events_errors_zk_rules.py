"""Unit tests for Starknet Events, Short String Panics and ZK Builtin rules."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_cairo_parser import NativeCairoParserAdapter
from pattern_detector.domain.rules.events_errors_zk_rules import (
    Felt252ShortStringErrorsRule,
    PedersenPoseidonHashBuiltinRule,
    StarknetEventVariantEmissionRule,
)
from pattern_detector.domain.value_objects import PatternType


def test_starknet_event_variant_emission() -> None:
    code = """
fn emit_transfer(ref self: ContractState, to: ContractAddress, amount: u256) {
    self.emit(Event::Transfer(Transfer { to, amount }));
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("events.cairo", code)])

    rule = StarknetEventVariantEmissionRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.STARKNET_EVENT_VARIANT_EMISSION


def test_felt252_short_string_errors() -> None:
    code = """
fn verify_owner(caller: ContractAddress, owner: ContractAddress) {
    assert(caller == owner, 'CALLER_NOT_OWNER');
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("errors.cairo", code)])

    rule = Felt252ShortStringErrorsRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.FELT252_SHORT_STRING_ERRORS


def test_pedersen_poseidon_hash_builtin() -> None:
    code = """
fn compute_stark_hash(data: Span<felt252>) -> felt252 {
    core::poseidon::poseidon_hash_span(data)
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("hash.cairo", code)])

    rule = PedersenPoseidonHashBuiltinRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.PEDERSEN_POSEIDON_HASH_BUILTIN
