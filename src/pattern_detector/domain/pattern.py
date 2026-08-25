"""Comprehensive pattern catalog and metadata for Cairo & Starknet static analysis."""

from __future__ import annotations

from dataclasses import dataclass
from pattern_detector.domain.value_objects import PatternCategory, PatternType


@dataclass(frozen=True)
class PatternDefinition:
    """Detailed architectural specification of a Cairo & Starknet pattern or hazard."""

    type: PatternType
    category: PatternCategory
    name: str
    description: str
    cairo_version: str = "Cairo 1.0 - 2.8+ / Starknet"
    recommendation: str = ""


PATTERN_CATALOG: dict[PatternType, PatternDefinition] = {
    # 1. Cairo Idiomatic, Starknet & Sierra Architecture
    PatternType.STARKNET_CONTRACT_COMPONENT_COMPOSITION: PatternDefinition(
        type=PatternType.STARKNET_CONTRACT_COMPONENT_COMPOSITION,
        category=PatternCategory.CAIRO_IDIOMATIC_STARKNET,
        name="Starknet Component Composition Architecture",
        description="Modular contract composition using component!(path, storage, event) and #[abi(embed_v0)] mixins.",
        recommendation="Favor component composition over monolithic inheritance for reusable contract logic.",
    ),
    PatternType.STARKNET_INTERFACE_ABI_DEFINITION: PatternDefinition(
        type=PatternType.STARKNET_INTERFACE_ABI_DEFINITION,
        category=PatternCategory.CAIRO_IDIOMATIC_STARKNET,
        name="Starknet Interface ABI Trait Definition",
        description="Explicit external contract ABI traits declared with #[starknet::interface] and ContractState generic.",
        recommendation="Define clean interfaces with #[starknet::interface] for all public contract APIs.",
    ),
    PatternType.STORAGE_MAPPING_DATA_LAYOUT: PatternDefinition(
        type=PatternType.STORAGE_MAPPING_DATA_LAYOUT,
        category=PatternCategory.CAIRO_IDIOMATIC_STARKNET,
        name="Starknet Storage Mapping Layout",
        description="Persistent contract storage declaring Map<K, V>, Vec<T>, or LegacyMap under #[storage] struct.",
        recommendation="Organize contract state neatly under the #[storage] struct using Map and Vec.",
    ),
    PatternType.ACCOUNT_ABSTRACTION_VALIDATION: PatternDefinition(
        type=PatternType.ACCOUNT_ABSTRACTION_VALIDATION,
        category=PatternCategory.CAIRO_IDIOMATIC_STARKNET,
        name="Starknet Account Abstraction Protocol",
        description="Native Account Abstraction implementing __validate__, __execute__, and __validate_declare__ entrypoints.",
        recommendation="Ensure signature validation logic strictly reverts on invalid signatures in __validate__.",
    ),
    PatternType.FELT252_FIELD_ARITHMETIC: PatternDefinition(
        type=PatternType.FELT252_FIELD_ARITHMETIC,
        category=PatternCategory.CAIRO_IDIOMATIC_STARKNET,
        name="Felt252 Field Element Arithmetic",
        description="Prime field element (felt252) operations adhering to STARK curve prime modulo arithmetic.",
        recommendation="Use u256/u128 for integer balance math and felt252 for identifiers and short strings.",
    ),
    PatternType.STARKNET_SYSCALL_DISPATCHER: PatternDefinition(
        type=PatternType.STARKNET_SYSCALL_DISPATCHER,
        category=PatternCategory.CAIRO_IDIOMATIC_STARKNET,
        name="Starknet Syscall Dispatcher",
        description="Low-level execution context syscalls (get_caller_address, get_contract_address, get_block_timestamp).",
        recommendation="Use standard library syscall wrappers for execution environment queries.",
    ),

    # 2. Upgradability & Component Mixins
    PatternType.UPGRADEABLE_CONTRACT_CLASS_HASH: PatternDefinition(
        type=PatternType.UPGRADEABLE_CONTRACT_CLASS_HASH,
        category=PatternCategory.COMPONENTS_UPGRADES,
        name="Upgradeable Contract Class Hash Replacement",
        description="Starknet proxy/upgrade architecture using replace_class_hash_syscall for atomic code evolution.",
        recommendation="Guard replace_class_hash_syscall behind multi-sig or timelocked admin governance.",
    ),
    PatternType.COMPONENT_STORAGE_EMBEDDING: PatternDefinition(
        type=PatternType.COMPONENT_STORAGE_EMBEDDING,
        category=PatternCategory.COMPONENTS_UPGRADES,
        name="Component Substorage Embedding",
        description="Embedding component substorage structs into the main contract #[storage] with #[substorage(v0)].",
        recommendation="Isolate component storage cleanly using #[substorage(v0)].",
    ),
    PatternType.REENTRANCY_GUARD_COMPONENT: PatternDefinition(
        type=PatternType.REENTRANCY_GUARD_COMPONENT,
        category=PatternCategory.COMPONENTS_UPGRADES,
        name="Reentrancy Guard Component",
        description="Component preventing reentrancy attacks across external call boundaries via storage mutex lock.",
        recommendation="Integrate ReentrancyGuardComponent around external call dispatchers.",
    ),
    PatternType.OWNABLE_ACCESS_CONTROL_COMPONENT: PatternDefinition(
        type=PatternType.OWNABLE_ACCESS_CONTROL_COMPONENT,
        category=PatternCategory.COMPONENTS_UPGRADES,
        name="Ownable Access Control Component",
        description="Role-based or single-owner access control component verifying caller permissions.",
        recommendation="Use standard Ownable or AccessControl components for privileged entrypoints.",
    ),

    # 3. Events, Errors & ZK Primitives
    PatternType.STARKNET_EVENT_VARIANT_EMISSION: PatternDefinition(
        type=PatternType.STARKNET_EVENT_VARIANT_EMISSION,
        category=PatternCategory.EVENTS_ERRORS_ZK,
        name="Starknet Event Variant Emission",
        description="Starknet typed event enum deriving starknet::Event emitted via self.emit(Event::...).",
        recommendation="Emit structured event variants for all critical contract state mutations.",
    ),
    PatternType.FELT252_SHORT_STRING_ERRORS: PatternDefinition(
        type=PatternType.FELT252_SHORT_STRING_ERRORS,
        category=PatternCategory.EVENTS_ERRORS_ZK,
        name="Felt252 Short String Panics",
        description="Gas-efficient short string error codes passed to assert(cond, 'ERROR_MESSAGE').",
        recommendation="Use concise short string error messages (<= 31 characters) for minimal gas overhead.",
    ),
    PatternType.PEDERSEN_POSEIDON_HASH_BUILTIN: PatternDefinition(
        type=PatternType.PEDERSEN_POSEIDON_HASH_BUILTIN,
        category=PatternCategory.EVENTS_ERRORS_ZK,
        name="Pedersen & Poseidon ZK Hash Builtins",
        description="Algebraic STARK-friendly hash functions (poseidon_hash_span, pedersen) optimized for ZK proofs.",
        recommendation="Prefer Poseidon hash over Pedersen in Cairo 1-2+ for lower execution step costs.",
    ),

    # 4. Creational Patterns (5/5)
    PatternType.SINGLETON_CONTRACT_STATE: PatternDefinition(
        type=PatternType.SINGLETON_CONTRACT_STATE,
        category=PatternCategory.CREATIONAL,
        name="Singleton Contract State Storage",
        description="Starknet contract singleton instance managing persistent storage variables at a deterministic address.",
        recommendation="Group related configuration variables inside singleton storage structs.",
    ),
    PatternType.FACTORY_CONTRACT_DEPLOY_SYSCALL: PatternDefinition(
        type=PatternType.FACTORY_CONTRACT_DEPLOY_SYSCALL,
        category=PatternCategory.CREATIONAL,
        name="Factory Contract Deploy Syscall",
        description="Factory pattern deploying new child contract instances on-chain via deploy_syscall.",
        recommendation="Use deploy_syscall in factory contracts to spawn standardized child instances.",
    ),
    PatternType.ABSTRACT_FACTORY_POOL_CREATOR: PatternDefinition(
        type=PatternType.ABSTRACT_FACTORY_POOL_CREATOR,
        category=PatternCategory.CREATIONAL,
        name="Abstract Factory Liquidity Pool Creator",
        description="Abstract factory trait creating decentralized AMM pairs and lending pools on Starknet.",
        recommendation="Parameterize pool creation with token addresses and fee tier configurations.",
    ),
    PatternType.BUILDER_MULTISIG_PAYLOAD: PatternDefinition(
        type=PatternType.BUILDER_MULTISIG_PAYLOAD,
        category=PatternCategory.CREATIONAL,
        name="Builder Multisig Call Batch Payload",
        description="Builder pattern assembling arrays of execution calls (Array<Call>) for atomic execution.",
        recommendation="Construct batch calls using Array<Call> builders for atomic execution.",
    ),
    PatternType.PROTOTYPE_ARRAY_SPAN_SLICE: PatternDefinition(
        type=PatternType.PROTOTYPE_ARRAY_SPAN_SLICE,
        category=PatternCategory.CREATIONAL,
        name="Prototype Array Span Slice",
        description="Prototype pattern cloning or slicing data views via span.slice(...) without reallocations.",
        recommendation="Use Span slices instead of cloning full arrays to minimize Sierra execution steps.",
    ),

    # 5. Structural Patterns (7/7)
    PatternType.ADAPTER_ORACLE_PRAGMA_WRAPPER: PatternDefinition(
        type=PatternType.ADAPTER_ORACLE_PRAGMA_WRAPPER,
        category=PatternCategory.STRUCTURAL,
        name="Adapter Oracle Pragma Price Wrapper",
        description="Adapter pattern transforming Pragma/Empiric oracle price feeds into uniform quotation structs.",
        recommendation="Standardize external price oracle feeds behind a uniform adapter trait.",
    ),
    PatternType.BRIDGE_L1_L2_MESSAGING: PatternDefinition(
        type=PatternType.BRIDGE_L1_L2_MESSAGING,
        category=PatternCategory.STRUCTURAL,
        name="Bridge L1 <-> L2 Messaging Portal",
        description="Starknet cross-layer communication using send_message_to_l1_syscall and #[l1_handler].",
        recommendation="Verify L1 sender address strictly in #[l1_handler] entrypoints.",
    ),
    PatternType.COMPOSITE_MULTICALL_BATCH: PatternDefinition(
        type=PatternType.COMPOSITE_MULTICALL_BATCH,
        category=PatternCategory.STRUCTURAL,
        name="Composite Multicall Batch Execution",
        description="Composite pattern executing multiple heterogeneous contract calls in a single transaction.",
        recommendation="Support multicall batches to enhance Starknet UX and reduce transaction fees.",
    ),
    PatternType.DECORATOR_STAKING_BOOSTER: PatternDefinition(
        type=PatternType.DECORATOR_STAKING_BOOSTER,
        category=PatternCategory.STRUCTURAL,
        name="Decorator Staking Yield Booster",
        description="Decorator pattern augmenting base staking balances with reward multiplier components.",
        recommendation="Wrap base staking positions with boost layers rather than modifying core pool logic.",
    ),
    PatternType.FACADE_ROUTER_DISPATCHER: PatternDefinition(
        type=PatternType.FACADE_ROUTER_DISPATCHER,
        category=PatternCategory.STRUCTURAL,
        name="Facade DEX Router Dispatcher",
        description="Unified entrypoint facade abstracting multi-hop routing across individual AMM pools.",
        recommendation="Provide high-level swap and liquidity routing functions in a facade dispatcher.",
    ),
    PatternType.FLYWEIGHT_CLASS_HASH_REGISTRY: PatternDefinition(
        type=PatternType.FLYWEIGHT_CLASS_HASH_REGISTRY,
        category=PatternCategory.STRUCTURAL,
        name="Flyweight Class Hash Registry",
        description="Flyweight pattern reusing shared class hashes across multiple proxy instances.",
        recommendation="Store shared class hashes in a central registry for gas-efficient proxy deployments.",
    ),
    PatternType.PROXY_DELEGATE_DISPATCHER: PatternDefinition(
        type=PatternType.PROXY_DELEGATE_DISPATCHER,
        category=PatternCategory.STRUCTURAL,
        name="Proxy Delegate Dispatcher",
        description="Proxy pattern forwarding calls via library_call_syscall or contract dispatchers.",
        recommendation="Use standard Starknet upgradeable proxy components for contract upgradability.",
    ),

    # 6. Behavioral Patterns (11/11)
    PatternType.CHAIN_OF_RESPONSIBILITY_PERMISSION_PIPE: PatternDefinition(
        type=PatternType.CHAIN_OF_RESPONSIBILITY_PERMISSION_PIPE,
        category=PatternCategory.BEHAVIORAL,
        name="Chain of Responsibility Permission Pipeline",
        description="Passing transaction requests through sequenced permission check functions.",
        recommendation="Structure complex authorization rules as chained validation functions.",
    ),
    PatternType.COMMAND_ACCOUNT_CALL_PAYLOAD: PatternDefinition(
        type=PatternType.COMMAND_ACCOUNT_CALL_PAYLOAD,
        category=PatternCategory.BEHAVIORAL,
        name="Command Account Call Payload",
        description="Encapsulating executable actions into Starknet Call structs passed to account executors.",
        recommendation="Model account actions as strongly typed Call structs.",
    ),
    PatternType.INTERPRETER_BYTECODE_EVALUATOR: PatternDefinition(
        type=PatternType.INTERPRETER_BYTECODE_EVALUATOR,
        category=PatternCategory.BEHAVIORAL,
        name="Interpreter On-Chain Bytecode Evaluator",
        description="Evaluating on-chain DSL rules or state transition byte instructions from spans.",
        recommendation="Use table-driven interpreters for programmable on-chain settlement logic.",
    ),
    PatternType.ITERATOR_SPAN_CURSOR_SCAN: PatternDefinition(
        type=PatternType.ITERATOR_SPAN_CURSOR_SCAN,
        category=PatternCategory.BEHAVIORAL,
        name="Iterator Span Cursor Scan",
        description="Cursor-based iteration over Span elements (span.pop_front(), loop).",
        recommendation="Bound span iteration loops to prevent transaction step exhaustion.",
    ),
    PatternType.MEDIATOR_ESCROW_ATOMIC_SWAP: PatternDefinition(
        type=PatternType.MEDIATOR_ESCROW_ATOMIC_SWAP,
        category=PatternCategory.BEHAVIORAL,
        name="Mediator Escrow Atomic Swap",
        description="Central escrow contract mediating atomic token exchanges between counterparties.",
        recommendation="Use atomic escrow contracts to eliminate counterparty risk.",
    ),
    PatternType.MEMENTO_CHECKPOINT_SNAPSHOT: PatternDefinition(
        type=PatternType.MEMENTO_CHECKPOINT_SNAPSHOT,
        category=PatternCategory.BEHAVIORAL,
        name="Memento Historical Checkpoint Snapshot",
        description="Recording historical block or epoch checkpoints for governance and reward calculations.",
        recommendation="Store historical epoch snapshots in indexed maps for retrospective queries.",
    ),
    PatternType.OBSERVER_EVENT_EMISSION: PatternDefinition(
        type=PatternType.OBSERVER_EVENT_EMISSION,
        category=PatternCategory.BEHAVIORAL,
        name="Observer Event Notification Emission",
        description="Observer pattern broadcasting typed event variants (self.emit) for indexers.",
        recommendation="Emit strongly typed event structs for all critical state mutations.",
    ),
    PatternType.STATE_MACHINE_VAULT_LIFECYCLE: PatternDefinition(
        type=PatternType.STATE_MACHINE_VAULT_LIFECYCLE,
        category=PatternCategory.BEHAVIORAL,
        name="State Machine Vault Lifecycle",
        description="Finite State Machine enforcing protocol states (Pending, Active, Paused, Settled).",
        recommendation="Enforce explicit state transition guards in stateful smart contracts.",
    ),
    PatternType.STRATEGY_YIELD_HARVEST_INJECTION: PatternDefinition(
        type=PatternType.STRATEGY_YIELD_HARVEST_INJECTION,
        category=PatternCategory.BEHAVIORAL,
        name="Strategy Yield Harvest Injection",
        description="Strategy pattern injecting interchangeable yield/rebalance dispatchers into vaults.",
        recommendation="Parameterize vault rebalancing with interchangeable strategy dispatchers.",
    ),
    PatternType.TEMPLATE_METHOD_HOOK_LIFECYCLE: PatternDefinition(
        type=PatternType.TEMPLATE_METHOD_HOOK_LIFECYCLE,
        category=PatternCategory.BEHAVIORAL,
        name="Template Method Lifecycle Hooks",
        description="Fixed execution skeleton coordinating entrypoints with pre/post execution hooks.",
        recommendation="Coordinate trade execution with pre-trade and post-trade hook checks.",
    ),
    PatternType.VISITOR_FLASHLOAN_RECEIVER: PatternDefinition(
        type=PatternType.VISITOR_FLASHLOAN_RECEIVER,
        category=PatternCategory.BEHAVIORAL,
        name="Visitor Flashloan Receiver Callback",
        description="Callback receiver invoked by flashloan pools during borrow transactions.",
        recommendation="Validate flashloan callback return values strictly.",
    ),

    # 7. Starknet Security Hazards
    PatternType.UNPROTECTED_EXTERNAL_ENTRY_HAZARD: PatternDefinition(
        type=PatternType.UNPROTECTED_EXTERNAL_ENTRY_HAZARD,
        category=PatternCategory.STARKNET_SECURITY_HAZARDS,
        name="Unprotected External Entry Hazard",
        description="Public external function modifying contract storage without caller verification.",
        recommendation="Verify caller address with get_caller_address() before mutating storage.",
    ),
    PatternType.MISSING_CALLER_VERIFICATION_HAZARD: PatternDefinition(
        type=PatternType.MISSING_CALLER_VERIFICATION_HAZARD,
        category=PatternCategory.STARKNET_SECURITY_HAZARDS,
        name="Missing Caller Verification Hazard",
        description="Critical admin or upgrade function lacking access control verification.",
        recommendation="Ensure all administrative functions enforce caller authorization checks.",
    ),
    PatternType.UNBOUNDED_STORAGE_LOOP_DOS_HAZARD: PatternDefinition(
        type=PatternType.UNBOUNDED_STORAGE_LOOP_DOS_HAZARD,
        category=PatternCategory.STARKNET_SECURITY_HAZARDS,
        name="Unbounded Storage Loop DoS Hazard",
        description="Unbounded loop over dynamic storage or array risking transaction step exhaustion.",
        recommendation="Paginate storage reads and bound loop iterations.",
    ),
    PatternType.L1_L2_REENTRANCY_HAZARD: PatternDefinition(
        type=PatternType.L1_L2_REENTRANCY_HAZARD,
        category=PatternCategory.STARKNET_SECURITY_HAZARDS,
        name="L1 <-> L2 Reentrancy Hazard",
        description="L1 message handler invoking external contract calls before updating local storage state.",
        recommendation="Follow Checks-Effects-Interactions (CEI) strictly inside #[l1_handler] functions.",
    ),

    # 8. SOLID Principles & Smells
    PatternType.MONOLITHIC_CONTRACT_SRP: PatternDefinition(
        type=PatternType.MONOLITHIC_CONTRACT_SRP,
        category=PatternCategory.PRINCIPLE,
        name="Monolithic Contract SRP Violation",
        description="Contract declaring excessive functions (>= 15) or storage fields (>= 10), violating Single Responsibility.",
        recommendation="Decompose large contracts into reusable Starknet components.",
    ),
    PatternType.FAT_COMPONENT_INTERFACE_ISP: PatternDefinition(
        type=PatternType.FAT_COMPONENT_INTERFACE_ISP,
        category=PatternCategory.PRINCIPLE,
        name="Fat Component Interface ISP Violation",
        description="Interface trait declaring excessive methods (>= 10), violating Interface Segregation.",
        recommendation="Split large interface traits into focused role interfaces.",
    ),
    PatternType.HARDCODED_CONTRACT_ADDRESS_OCP: PatternDefinition(
        type=PatternType.HARDCODED_CONTRACT_ADDRESS_OCP,
        category=PatternCategory.PRINCIPLE,
        name="Hardcoded Contract Address OCP Violation",
        description="Hardcoding literal contract addresses (contract_address_const::<0x...>) instead of configurable parameters.",
        recommendation="Store contract addresses in storage variables or initialize via constructor.",
    ),
}
