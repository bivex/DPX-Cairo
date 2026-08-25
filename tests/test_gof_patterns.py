"""Unit tests for all 23 GoF Creational, Structural, and Behavioral patterns in Cairo & Starknet."""

from __future__ import annotations

from pattern_detector.adapters.outbound.parsers.native_cairo_parser import NativeCairoParserAdapter
from pattern_detector.domain.rules.behavioral_rules import (
    ChainOfResponsibilityPermissionPipeRule,
    CommandAccountCallPayloadRule,
    InterpreterBytecodeEvaluatorRule,
    IteratorSpanCursorScanRule,
    MediatorEscrowAtomicSwapRule,
    MementoCheckpointSnapshotRule,
    ObserverEventEmissionRule,
    StateMachineVaultLifecycleRule,
    StrategyYieldHarvestInjectionRule,
    TemplateMethodHookLifecycleRule,
    VisitorFlashloanReceiverRule,
)
from pattern_detector.domain.rules.creational_rules import (
    AbstractFactoryPoolCreatorRule,
    BuilderMultisigPayloadRule,
    FactoryContractDeploySyscallRule,
    PrototypeArraySpanSliceRule,
    SingletonContractStateRule,
)
from pattern_detector.domain.rules.structural_rules import (
    AdapterOraclePragmaWrapperRule,
    BridgeL1L2MessagingRule,
    CompositeMulticallBatchRule,
    DecoratorStakingBoosterRule,
    FacadeRouterDispatcherRule,
    FlyweightClassHashRegistryRule,
    ProxyDelegateDispatcherRule,
)
from pattern_detector.domain.value_objects import PatternType


# --- Creational (5/5) ---

def test_singleton_contract_state() -> None:
    code = """
#[starknet::contract]
mod Registry {
    #[storage]
    struct Storage { admin: ContractAddress }
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("registry.cairo", code)])

    rule = SingletonContractStateRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.SINGLETON_CONTRACT_STATE


def test_factory_contract_deploy_syscall() -> None:
    code = """
fn deploy_child(class_hash: ClassHash, salt: felt252) {
    deploy_syscall(class_hash, salt, array![].span(), false);
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("factory.cairo", code)])

    rule = FactoryContractDeploySyscallRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.FACTORY_CONTRACT_DEPLOY_SYSCALL


def test_abstract_factory_pool_creator() -> None:
    code = """
fn create_pool(token_a: ContractAddress, token_b: ContractAddress) {}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("amm.cairo", code)])

    rule = AbstractFactoryPoolCreatorRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.ABSTRACT_FACTORY_POOL_CREATOR


def test_builder_multisig_payload() -> None:
    code = """
fn build_calls() -> Array<Call> {
    let mut calls = array![];
    calls.append(Call { to: 0.try_into().unwrap(), selector: 0, calldata: array![].span() });
    calls
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("builder.cairo", code)])

    rule = BuilderMultisigPayloadRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.BUILDER_MULTISIG_PAYLOAD


def test_prototype_array_span_slice() -> None:
    code = """
fn extract_sub_payload(data: Span<felt252>) -> Span<felt252> {
    data.slice(0, 4)
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("slice.cairo", code)])

    rule = PrototypeArraySpanSliceRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.PROTOTYPE_ARRAY_SPAN_SLICE


# --- Structural (7/7) ---

def test_adapter_oracle_pragma_wrapper() -> None:
    code = """
pub trait IPragmaOracleAdapter {
    fn get_price(token: ContractAddress) -> u256;
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("oracle.cairo", code)])

    rule = AdapterOraclePragmaWrapperRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.ADAPTER_ORACLE_PRAGMA_WRAPPER


def test_bridge_l1_l2_messaging() -> None:
    code = """
#[l1_handler]
fn process_l1_deposit(from_address: felt252, amount: u256) {}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("bridge.cairo", code)])

    rule = BridgeL1L2MessagingRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.BRIDGE_L1_L2_MESSAGING


def test_composite_multicall_batch() -> None:
    code = """
fn __execute__(calls: Array<Call>) {}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("multicall.cairo", code)])

    rule = CompositeMulticallBatchRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.COMPOSITE_MULTICALL_BATCH


def test_decorator_staking_booster() -> None:
    code = """
#[starknet::contract]
mod StakingBoostVault {}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("boost.cairo", code)])

    rule = DecoratorStakingBoosterRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.DECORATOR_STAKING_BOOSTER


def test_facade_router_dispatcher() -> None:
    code = """
#[starknet::contract]
mod SwapRouterDispatcher {}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("router.cairo", code)])

    rule = FacadeRouterDispatcherRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.FACADE_ROUTER_DISPATCHER


def test_flyweight_class_hash_registry() -> None:
    code = """
#[starknet::contract]
mod HashRegistry {
    #[storage]
    struct Storage {
        account_class_hash: ClassHash,
    }
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("registry.cairo", code)])

    rule = FlyweightClassHashRegistryRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.FLYWEIGHT_CLASS_HASH_REGISTRY


def test_proxy_delegate_dispatcher() -> None:
    code = """
fn forward_call(class_hash: ClassHash, selector: felt252, calldata: Span<felt252>) {
    library_call_syscall(class_hash, selector, calldata);
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("proxy.cairo", code)])

    rule = ProxyDelegateDispatcherRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.PROXY_DELEGATE_DISPATCHER


# --- Behavioral (11/11) ---

def test_chain_of_responsibility_permission_pipe() -> None:
    code = """
fn validate_permissions() {}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("perms.cairo", code)])

    rule = ChainOfResponsibilityPermissionPipeRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.CHAIN_OF_RESPONSIBILITY_PERMISSION_PIPE


def test_command_account_call_payload() -> None:
    code = """
fn execute_call(call: Call) {}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("call.cairo", code)])

    rule = CommandAccountCallPayloadRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.COMMAND_ACCOUNT_CALL_PAYLOAD


def test_interpreter_bytecode_evaluator() -> None:
    code = """
fn exec_op(opcode: u8) {}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("vm.cairo", code)])

    rule = InterpreterBytecodeEvaluatorRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.INTERPRETER_BYTECODE_EVALUATOR


def test_iterator_span_cursor_scan() -> None:
    code = """
fn sum_span(mut data: Span<u256>) -> u256 {
    let mut sum = 0;
    while let Option::Some(val) = data.pop_front() {
        sum += *val;
    };
    sum
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("scan.cairo", code)])

    rule = IteratorSpanCursorScanRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.ITERATOR_SPAN_CURSOR_SCAN


def test_mediator_escrow_atomic_swap() -> None:
    code = """
#[starknet::contract]
mod EscrowSwapContract {}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("escrow.cairo", code)])

    rule = MediatorEscrowAtomicSwapRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.MEDIATOR_ESCROW_ATOMIC_SWAP


def test_memento_checkpoint_snapshot() -> None:
    code = """
#[starknet::contract]
mod BlockSnapshotHistory {}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("snap.cairo", code)])

    rule = MementoCheckpointSnapshotRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.MEMENTO_CHECKPOINT_SNAPSHOT


def test_observer_event_emission() -> None:
    code = """
fn on_deposit(ref self: ContractState) {
    self.emit(Event::Deposit(Deposit {}));
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("obs.cairo", code)])

    rule = ObserverEventEmissionRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.OBSERVER_EVENT_EMISSION


def test_state_machine_vault_lifecycle() -> None:
    code = """
#[starknet::contract]
mod ProtocolLifecycleState {}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("state.cairo", code)])

    rule = StateMachineVaultLifecycleRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.STATE_MACHINE_VAULT_LIFECYCLE


def test_strategy_yield_harvest_injection() -> None:
    code = """
#[starknet::contract]
mod AutoHarvestStrategy {}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("strat.cairo", code)])

    rule = StrategyYieldHarvestInjectionRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.STRATEGY_YIELD_HARVEST_INJECTION


def test_template_method_hook_lifecycle() -> None:
    code = """
fn execute() {
    check_preconditions();
}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("hook.cairo", code)])

    rule = TemplateMethodHookLifecycleRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.TEMPLATE_METHOD_HOOK_LIFECYCLE


def test_visitor_flashloan_receiver() -> None:
    code = """
fn on_flash_loan(initiator: ContractAddress, amount: u256) {}
"""
    parser = NativeCairoParserAdapter()
    model = parser.parse_codebase([("flash.cairo", code)])

    rule = VisitorFlashloanReceiverRule()
    detections = rule.evaluate(model)

    assert len(detections) == 1
    assert detections[0].pattern_type == PatternType.VISITOR_FLASHLOAN_RECEIVER
