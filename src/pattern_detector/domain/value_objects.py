"""Value objects, Enums, and domain primitives for Cairo & Starknet static analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class PatternCategory(str, Enum):
    """Broad architectural classification for Cairo & Starknet patterns."""

    CAIRO_IDIOMATIC_STARKNET = "cairo_idiomatic_starknet"
    COMPONENTS_UPGRADES = "components_upgrades"
    EVENTS_ERRORS_ZK = "events_errors_zk"
    CREATIONAL = "creational"
    STRUCTURAL = "structural"
    BEHAVIORAL = "behavioral"
    STARKNET_SECURITY_HAZARDS = "starknet_security_hazards"
    PRINCIPLE = "principle"


class PatternType(str, Enum):
    """Exhaustive catalog of Cairo 1-2+ Starknet patterns, components, and security hazards."""

    # 1. Cairo Idiomatic, Starknet & Sierra Architecture (6)
    STARKNET_CONTRACT_COMPONENT_COMPOSITION = "starknet_contract_component_composition"
    STARKNET_INTERFACE_ABI_DEFINITION = "starknet_interface_abi_definition"
    STORAGE_MAPPING_DATA_LAYOUT = "storage_mapping_data_layout"
    ACCOUNT_ABSTRACTION_VALIDATION = "account_abstraction_validation"
    FELT252_FIELD_ARITHMETIC = "felt252_field_arithmetic"
    STARKNET_SYSCALL_DISPATCHER = "starknet_syscall_dispatcher"

    # 2. Upgradability & Component Mixins (4)
    UPGRADEABLE_CONTRACT_CLASS_HASH = "upgradeable_contract_class_hash"
    COMPONENT_STORAGE_EMBEDDING = "component_storage_embedding"
    REENTRANCY_GUARD_COMPONENT = "reentrancy_guard_component"
    OWNABLE_ACCESS_CONTROL_COMPONENT = "ownable_access_control_component"

    # 3. Events, Errors & ZK Primitives (3)
    STARKNET_EVENT_VARIANT_EMISSION = "starknet_event_variant_emission"
    FELT252_SHORT_STRING_ERRORS = "felt252_short_string_errors"
    PEDERSEN_POSEIDON_HASH_BUILTIN = "pedersen_poseidon_hash_builtin"

    # 4. Creational Patterns (5/5)
    SINGLETON_CONTRACT_STATE = "singleton_contract_state"
    FACTORY_CONTRACT_DEPLOY_SYSCALL = "factory_contract_deploy_syscall"
    ABSTRACT_FACTORY_POOL_CREATOR = "abstract_factory_pool_creator"
    BUILDER_MULTISIG_PAYLOAD = "builder_multisig_payload"
    PROTOTYPE_ARRAY_SPAN_SLICE = "prototype_array_span_slice"

    # 5. Structural Patterns (7/7)
    ADAPTER_ORACLE_PRAGMA_WRAPPER = "adapter_oracle_pragma_wrapper"
    BRIDGE_L1_L2_MESSAGING = "bridge_l1_l2_messaging"
    COMPOSITE_MULTICALL_BATCH = "composite_multicall_batch"
    DECORATOR_STAKING_BOOSTER = "decorator_staking_booster"
    FACADE_ROUTER_DISPATCHER = "facade_router_dispatcher"
    FLYWEIGHT_CLASS_HASH_REGISTRY = "flyweight_class_hash_registry"
    PROXY_DELEGATE_DISPATCHER = "proxy_delegate_dispatcher"

    # 6. Behavioral Patterns (11/11)
    CHAIN_OF_RESPONSIBILITY_PERMISSION_PIPE = "chain_of_responsibility_permission_pipe"
    COMMAND_ACCOUNT_CALL_PAYLOAD = "command_account_call_payload"
    INTERPRETER_BYTECODE_EVALUATOR = "interpreter_bytecode_evaluator"
    ITERATOR_SPAN_CURSOR_SCAN = "iterator_span_cursor_scan"
    MEDIATOR_ESCROW_ATOMIC_SWAP = "mediator_escrow_atomic_swap"
    MEMENTO_CHECKPOINT_SNAPSHOT = "memento_checkpoint_snapshot"
    OBSERVER_EVENT_EMISSION = "observer_event_emission"
    STATE_MACHINE_VAULT_LIFECYCLE = "state_machine_vault_lifecycle"
    STRATEGY_YIELD_HARVEST_INJECTION = "strategy_yield_harvest_injection"
    TEMPLATE_METHOD_HOOK_LIFECYCLE = "template_method_hook_lifecycle"
    VISITOR_FLASHLOAN_RECEIVER = "visitor_flashloan_receiver"

    # 7. Starknet Security Hazards (4)
    UNPROTECTED_EXTERNAL_ENTRY_HAZARD = "unprotected_external_entry_hazard"
    MISSING_CALLER_VERIFICATION_HAZARD = "missing_caller_verification_hazard"
    UNBOUNDED_STORAGE_LOOP_DOS_HAZARD = "unbounded_storage_loop_dos_hazard"
    L1_L2_REENTRANCY_HAZARD = "l1_l2_reentrancy_hazard"

    # 8. SOLID Principles & Smells (3)
    MONOLITHIC_CONTRACT_SRP = "monolithic_contract_srp"
    FAT_COMPONENT_INTERFACE_ISP = "fat_component_interface_isp"
    HARDCODED_CONTRACT_ADDRESS_OCP = "hardcoded_contract_address_ocp"


class ConfidenceLevel(str, Enum):
    """Categorical confidence level ranking."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


@dataclass(frozen=True)
class SourceLocation:
    """Precise source code location in a Cairo file (.cairo)."""

    file_path: str
    line: int
    column: int = 1

    def __str__(self) -> str:
        return f"{self.file_path}:{self.line}:{self.column}"


@dataclass
class Evidence:
    """Individual heuristic or signal contributing to pattern detection."""

    rule_code: str
    description: str
    weight: float
    location: SourceLocation | None = None


@dataclass
class Confidence:
    """Aggregated detection confidence score and heuristic evidence trail."""

    score: float
    evidences: list[Evidence] = field(default_factory=list)

    @property
    def level(self) -> ConfidenceLevel:
        if self.score >= 0.85:
            return ConfidenceLevel.VERY_HIGH
        if self.score >= 0.70:
            return ConfidenceLevel.HIGH
        if self.score >= 0.50:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

    @property
    def percentage_str(self) -> str:
        return f"{int(round(self.score * 100))}%"
