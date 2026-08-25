"""Rules registry and aggregation factory for Cairo & Starknet pattern detector."""

from __future__ import annotations

from pattern_detector.domain.rules.base import BaseRule
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
from pattern_detector.domain.rules.components_upgrades_rules import (
    ComponentStorageEmbeddingRule,
    OwnableAccessControlComponentRule,
    ReentrancyGuardComponentRule,
    UpgradeableContractClassHashRule,
)
from pattern_detector.domain.rules.creational_rules import (
    AbstractFactoryPoolCreatorRule,
    BuilderMultisigPayloadRule,
    FactoryContractDeploySyscallRule,
    PrototypeArraySpanSliceRule,
    SingletonContractStateRule,
)
from pattern_detector.domain.rules.events_errors_zk_rules import (
    Felt252ShortStringErrorsRule,
    PedersenPoseidonHashBuiltinRule,
    StarknetEventVariantEmissionRule,
)
from pattern_detector.domain.rules.idiomatic_rules import (
    AccountAbstractionValidationRule,
    Felt252FieldArithmeticRule,
    StarknetContractComponentCompositionRule,
    StarknetInterfaceAbiDefinitionRule,
    StarknetSyscallDispatcherRule,
    StorageMappingDataLayoutRule,
)
from pattern_detector.domain.rules.security_rules import (
    L1L2ReentrancyHazardRule,
    MissingCallerVerificationHazardRule,
    UnboundedStorageLoopDosHazardRule,
    UnprotectedExternalEntryHazardRule,
)
from pattern_detector.domain.rules.solid_principles_rules import (
    FatComponentInterfaceIspRule,
    HardcodedContractAddressOcpRule,
    MonolithicContractSrpRule,
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

DEFAULT_RULES: list[type[BaseRule]] = [
    # 1. Cairo Idiomatic, Starknet & Sierra Architecture (6)
    StarknetContractComponentCompositionRule,
    StarknetInterfaceAbiDefinitionRule,
    StorageMappingDataLayoutRule,
    AccountAbstractionValidationRule,
    Felt252FieldArithmeticRule,
    StarknetSyscallDispatcherRule,

    # 2. Upgradability & Component Mixins (4)
    UpgradeableContractClassHashRule,
    ComponentStorageEmbeddingRule,
    ReentrancyGuardComponentRule,
    OwnableAccessControlComponentRule,

    # 3. Events, Errors & ZK Primitives (3)
    StarknetEventVariantEmissionRule,
    Felt252ShortStringErrorsRule,
    PedersenPoseidonHashBuiltinRule,

    # 4. Creational Patterns (5/5)
    SingletonContractStateRule,
    FactoryContractDeploySyscallRule,
    AbstractFactoryPoolCreatorRule,
    BuilderMultisigPayloadRule,
    PrototypeArraySpanSliceRule,

    # 5. Structural Patterns (7/7)
    AdapterOraclePragmaWrapperRule,
    BridgeL1L2MessagingRule,
    CompositeMulticallBatchRule,
    DecoratorStakingBoosterRule,
    FacadeRouterDispatcherRule,
    FlyweightClassHashRegistryRule,
    ProxyDelegateDispatcherRule,

    # 6. Behavioral Patterns (11/11)
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

    # 7. Starknet Security Hazards (4)
    UnprotectedExternalEntryHazardRule,
    MissingCallerVerificationHazardRule,
    UnboundedStorageLoopDosHazardRule,
    L1L2ReentrancyHazardRule,

    # 8. SOLID Principles & Smells (3)
    MonolithicContractSrpRule,
    FatComponentInterfaceIspRule,
    HardcodedContractAddressOcpRule,
]


def get_default_rules() -> list[BaseRule]:
    """Instantiate and return full suite of default Cairo rules."""
    return [rule_cls() for rule_cls in DEFAULT_RULES]
