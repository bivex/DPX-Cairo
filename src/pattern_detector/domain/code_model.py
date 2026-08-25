"""Domain CodeModel entities representing Cairo modules, Starknet contracts, components, storage, and interfaces."""

from __future__ import annotations

from dataclasses import dataclass, field
from pattern_detector.domain.value_objects import SourceLocation


@dataclass
class CairoField:
    """Field inside a Cairo struct or storage."""

    name: str
    type_str: str


@dataclass
class CairoStorage:
    """Starknet contract #[storage] struct definition."""

    fields: list[CairoField] = field(default_factory=list)
    has_mapping: bool = False
    has_vec: bool = False
    location: SourceLocation | None = None
    raw_text: str = ""


@dataclass
class CairoComponentDecl:
    """Starknet component declaration (component!(path: ..., storage: ..., event: ...))."""

    name: str
    path: str
    storage_name: str = ""
    event_name: str = ""
    location: SourceLocation | None = None


@dataclass
class CairoFunction:
    """Cairo function or Starknet contract entrypoint."""

    name: str
    visibility: str = "private"  # "pub", "private"
    is_external: bool = False
    is_view: bool = False
    is_l1_handler: bool = False
    is_constructor: bool = False
    parameters: list[str] = field(default_factory=list)
    return_type: str = ""
    body: str = ""
    has_assert: bool = False
    has_emit: bool = False
    has_caller_check: bool = False
    has_syscall: bool = False
    location: SourceLocation | None = None
    raw_text: str = ""


@dataclass
class CairoTrait:
    """Cairo trait / Starknet interface definition (#[starknet::interface])."""

    name: str
    is_starknet_interface: bool = False
    methods: list[str] = field(default_factory=list)
    location: SourceLocation | None = None
    raw_text: str = ""


@dataclass
class CairoImpl:
    """Cairo impl block (#[abi(embed_v0)] impl ... of ...)."""

    name: str
    trait_name: str = ""
    target_type: str = ""
    is_embedded_abi: bool = False
    functions: list[CairoFunction] = field(default_factory=list)
    location: SourceLocation | None = None
    raw_text: str = ""


@dataclass
class CairoEvent:
    """Starknet #[event] enum or struct."""

    name: str
    variants: list[str] = field(default_factory=list)
    location: SourceLocation | None = None
    raw_text: str = ""


@dataclass
class CairoContract:
    """Starknet contract or component module (#[starknet::contract] / #[starknet::component])."""

    name: str
    is_starknet_contract: bool = False
    is_starknet_component: bool = False
    components: list[CairoComponentDecl] = field(default_factory=list)
    storage: CairoStorage | None = None
    impls: list[CairoImpl] = field(default_factory=list)
    functions: list[CairoFunction] = field(default_factory=list)
    events: list[CairoEvent] = field(default_factory=list)
    location: SourceLocation | None = None
    raw_text: str = ""

    @property
    def all_functions(self) -> list[CairoFunction]:
        fns = list(self.functions)
        for impl in self.impls:
            fns.extend(impl.functions)
        return fns


@dataclass
class CairoFile:
    """Parsed Cairo source file (.cairo)."""

    file_path: str
    raw_content: str
    lines: list[str] = field(default_factory=list)
    contracts: list[CairoContract] = field(default_factory=list)
    traits: list[CairoTrait] = field(default_factory=list)
    free_functions: list[CairoFunction] = field(default_factory=list)


@dataclass
class CodeModel:
    """Aggregated structural model of a scanned Cairo codebase."""

    target_path: str = ""
    files: list[CairoFile] = field(default_factory=list)

    @property
    def all_contracts(self) -> list[CairoContract]:
        return [c for f in self.files for c in f.contracts]

    @property
    def all_traits(self) -> list[CairoTrait]:
        return [t for f in self.files for t in f.traits]

    @property
    def all_functions(self) -> list[CairoFunction]:
        fns: list[CairoFunction] = []
        for f in self.files:
            fns.extend(f.free_functions)
            for c in f.contracts:
                fns.extend(c.all_functions)
        return fns

    @property
    def all_components(self) -> list[CairoComponentDecl]:
        return [comp for c in self.all_contracts for comp in c.components]

    @property
    def all_events(self) -> list[CairoEvent]:
        return [ev for c in self.all_contracts for ev in c.events]
