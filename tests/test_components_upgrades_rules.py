"""Unit tests for Starknet Component Upgrades and Access Control rules."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_cairo_parser import NativeCairoParserAdapter
from pattern_detector.domain.rules.components_upgrades_rules import (
    ComponentStorageEmbeddingRule,
    OwnableAccessControlComponentRule,
    ReentrancyGuardComponentRule,
    UpgradeableContractClassHashRule,
)
from pattern_detector.domain.value_objects import PatternType


def test_upgradeable_contract_class_hash() -> None:
    code = """
fn upgrade_contract(new_class_hash: ClassHash) {
    replace_class_hash_syscall(new_class_hash);
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("upgrade.cairo", code)])

    rule = UpgradeableContractClassHashRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.UPGRADEABLE_CONTRACT_CLASS_HASH


def test_component_storage_embedding() -> None:
    code = """
#[starknet::contract]
mod EmbedDemo {
    #[storage]
    struct Storage {
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
    }
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("embed.cairo", code)])

    rule = ComponentStorageEmbeddingRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.COMPONENT_STORAGE_EMBEDDING


def test_reentrancy_guard_component() -> None:
    code = """
#[starknet::contract]
mod SafeVault {
    component!(path: ReentrancyGuardComponent, storage: reentrancy_guard, event: ReentrancyGuardEvent);
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("safe.cairo", code)])

    rule = ReentrancyGuardComponentRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.REENTRANCY_GUARD_COMPONENT


def test_ownable_access_control_component() -> None:
    code = """
#[starknet::contract]
mod OwnedVault {
    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("owned.cairo", code)])

    rule = OwnableAccessControlComponentRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.OWNABLE_ACCESS_CONTROL_COMPONENT
