"""Unit tests for Cairo Idiomatic, Starknet & Sierra Architecture rules."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_cairo_parser import NativeCairoParserAdapter
from pattern_detector.domain.rules.idiomatic_rules import (
    AccountAbstractionValidationRule,
    Felt252FieldArithmeticRule,
    StarknetContractComponentCompositionRule,
    StarknetInterfaceAbiDefinitionRule,
    StarknetSyscallDispatcherRule,
    StorageMappingDataLayoutRule,
)
from pattern_detector.domain.value_objects import PatternType


def test_starknet_contract_component_composition() -> None:
    code = """
#[starknet::contract]
mod MyContract {
    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("contract.cairo", code)])

    rule = StarknetContractComponentCompositionRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.STARKNET_CONTRACT_COMPONENT_COMPOSITION


def test_starknet_interface_abi_definition() -> None:
    code = """
#[starknet::interface]
pub trait IVault<TContractState> {
    fn deposit(ref self: TContractState, amount: u256);
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("interface.cairo", code)])

    rule = StarknetInterfaceAbiDefinitionRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.STARKNET_INTERFACE_ABI_DEFINITION


def test_storage_mapping_data_layout() -> None:
    code = """
#[starknet::contract]
mod StorageDemo {
    #[storage]
    struct Storage {
        balances: Map<ContractAddress, u256>,
    }
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("storage.cairo", code)])

    rule = StorageMappingDataLayoutRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.STORAGE_MAPPING_DATA_LAYOUT


def test_account_abstraction_validation() -> None:
    code = """
#[starknet::contract]
mod Account {
    fn __validate__(ref self: ContractState, calls: Array<Call>) -> felt252 {
        0
    }
    fn __execute__(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
        array![]
    }
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("account.cairo", code)])

    rule = AccountAbstractionValidationRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.ACCOUNT_ABSTRACTION_VALIDATION


def test_felt252_field_arithmetic() -> None:
    code = """
fn hash_token_id(id: felt252) -> felt252 {
    id + 1
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("math.cairo", code)])

    rule = Felt252FieldArithmeticRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.FELT252_FIELD_ARITHMETIC


def test_starknet_syscall_dispatcher() -> None:
    code = """
fn check_caller() {
    let caller = get_caller_address();
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("syscall.cairo", code)])

    rule = StarknetSyscallDispatcherRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.STARKNET_SYSCALL_DISPATCHER
