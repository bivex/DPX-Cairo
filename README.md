# ⚡ DPX-Cairo: Starknet Components, Storage Mapping, Syscalls, Upgrades & GoF 23 Static Analyzer

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Cairo Version](https://img.shields.io/badge/Cairo-1.0%20--%202.8+%20%7C%20Starknet-ff385c?logo=starknet&logoColor=white)](https://book.cairo-lang.org/)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![Architecture: Hexagonal DDD](https://img.shields.io/badge/Architecture-Hexagonal%20DDD-blueviolet)](https://alistair.cockburn.us/hexagonal-architecture/)
[![CLI: Typer & Rich](https://img.shields.io/badge/CLI-Typer%20%26%20Rich-009688)](https://typer.tiangolo.com)
[![SARIF OASIS v2.1.0](https://img.shields.io/badge/SARIF-OASIS%20v2.1.0-blue)](https://sarifweb.azurewebsites.net)

**DPX-Cairo** is an enterprise-grade static analysis engine and architectural pattern detector for Cairo smart contracts on **Starknet L2**. Engineered for **Starknet Component Composition (`component!`, `#[abi(embed_v0)]`), Contract Interfaces (`#[starknet::interface]`), Storage Mapping (`Map`, `Vec`), Native Account Abstraction (`__validate__`, `__execute__`), Syscalls (`call_contract_syscall`, `replace_class_hash_syscall`), Upgradeable Proxies, ZK Hashes (Poseidon / Pedersen), all 23 GoF Design Patterns**, and **Starknet Security Hazards (Unprotected External Entries, Missing Caller Checks, Unbounded Storage Loops, L1-L2 Reentrancy)**.

[Features](#-key-features) • [Installation](#-installation) • [CLI Usage](#-cli-usage) • [Supported Rules](#-supported-pattern-rules--checks) • [The DPX Suite Family](#-the-dpx-suite-family)

</div>

---

## 🌟 Key Features

- 🧩 **Starknet Component Composition:** Audits modular component mixins (`component!`, `#[substorage(v0)]`, `#[abi(embed_v0)]`, `OwnableComponent`, `ReentrancyGuardComponent`).
- 🏛️ **Contract Storage & Interfaces:** Identifies persistent storage layouts (`#[storage]` struct with `Map` / `Vec`) and external ABI traits (`#[starknet::interface]`).
- 🔑 **Native Account Abstraction:** Audits account contract validation entrypoints (`__validate__`, `__execute__`, `__validate_declare__`).
- ⚡ **Syscall & Upgradeable Architecture:** Audits execution environment syscalls (`get_caller_address`, `get_contract_address`, `replace_class_hash_syscall`).
- 📐 **ZK Cryptographic Builtins:** Detects STARK algebraic hash builtins (`poseidon_hash_span`, `pedersen`) and felt252 short string panics.
- 🏛️ **100% Complete Gang of Four (GoF 23/23):** Full coverage of all 23 Creational, Structural, and Behavioral design patterns tailored for Cairo smart contracts.
- 🛡️ **Starknet Security Hazards:** Detects unprotected external writes, missing caller access control, unbounded storage loops, and cross-layer L1-L2 reentrancy.
- 📊 **Interactive Architecture Observability HUD:** Zero-dependency interactive HTML dashboard with instant search, KPI breakdown, and built-in **`🤖 Copy AI Context Prompt`** generator for LLMs (Claude, GPT-4, Gemini).
- 🔒 **CI/CD & GitHub Security Ready:** Standardized **OASIS SARIF v2.1.0**, JSON, and Markdown reports.

---

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/bivex/DPX-Cairo.git
cd DPX-Cairo

# Install dependencies using uv or pip
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

---

## 💻 CLI Usage

### 1. Scan a Cairo Smart Contract Package
```bash
# Terminal scan with Rich formatting
dpx-cairo scan /path/to/cairo/package

# Export Interactive HTML Observability HUD
dpx-cairo scan src/ -H reports/cairo_hud.html

# Generate AI Context Prompt for LLMs
dpx-cairo scan src/ --llm

# Filter for specific Component or Upgrade rules
dpx-cairo scan src/ -p starknet_contract_component_composition -p upgradeable_contract_class_hash

# Export SARIF for GitHub Code Scanning
dpx-cairo scan src/ -S reports/results.sarif
```

### 2. Inspect Supported Architectural Rules
```bash
dpx-cairo rules
```

### 3. Query Deep Pattern Documentation
```bash
dpx-cairo info starknet_contract_component_composition
dpx-cairo info upgradeable_contract_class_hash
```

---

## 📋 Supported Pattern Rules & Checks

### 1. ⚡ Cairo Idiomatic, Starknet & Sierra Architecture
- `starknet_contract_component_composition`: Modular contract composition using `component!(path, storage, event)` and `#[abi(embed_v0)]` mixins.
- `starknet_interface_abi_definition`: Explicit external contract ABI traits declared with `#[starknet::interface]` and ContractState generic.
- `storage_mapping_data_layout`: Persistent contract storage declaring `Map<K, V>`, `Vec<T>`, or `LegacyMap` under `#[storage]` struct.
- `account_abstraction_validation`: Native Account Abstraction implementing `__validate__`, `__execute__`, and `__validate_declare__` entrypoints.
- `felt252_field_arithmetic`: Prime field element (`felt252`) operations adhering to STARK curve prime modulo arithmetic.
- `starknet_syscall_dispatcher`: Low-level execution context syscalls (`get_caller_address`, `get_contract_address`, `get_block_timestamp`).

### 2. 🧩 Upgradability & Component Mixins
- `upgradeable_contract_class_hash`: Starknet proxy/upgrade architecture using `replace_class_hash_syscall` for atomic code evolution.
- `component_storage_embedding`: Embedding component substorage structs into the main contract `#[storage]` with `#[substorage(v0)]`.
- `reentrancy_guard_component`: Component preventing reentrancy attacks across external call boundaries via storage mutex lock.
- `ownable_access_control_component`: Role-based or single-owner access control component verifying caller permissions.

### 3. 📐 Events, Errors & ZK Primitives
- `starknet_event_variant_emission`: Starknet typed event enum deriving `starknet::Event` emitted via `self.emit(Event::...)`.
- `felt252_short_string_errors`: Gas-efficient short string error codes passed to `assert(cond, 'ERROR_MESSAGE')`.
- `pedersen_poseidon_hash_builtin`: Algebraic STARK-friendly hash functions (`poseidon_hash_span`, `pedersen`) optimized for ZK proofs.

### 4. 🏛️ GoF Creational Patterns (5/5)
- `singleton_contract_state`: Starknet contract singleton instance managing persistent storage variables at a deterministic address.
- `factory_contract_deploy_syscall`: Factory pattern deploying new child contract instances on-chain via `deploy_syscall`.
- `abstract_factory_pool_creator`: Abstract factory trait creating decentralized AMM pairs and lending pools on Starknet.
- `builder_multisig_payload`: Builder pattern assembling arrays of execution calls (`Array<Call>`) for atomic execution.
- `prototype_array_span_slice`: Prototype pattern cloning or slicing data views via `span.slice(...)` without reallocations.

### 5. 🧱 GoF Structural Patterns (7/7)
- `adapter_oracle_pragma_wrapper`: Adapter pattern transforming Pragma/Empiric oracle price feeds into uniform quotation structs.
- `bridge_l1_l2_messaging`: Starknet cross-layer communication using `send_message_to_l1_syscall` and `#[l1_handler]`.
- `composite_multicall_batch`: Composite pattern executing multiple heterogeneous contract calls in a single transaction.
- `decorator_staking_booster`: Decorator pattern augmenting base staking balances with reward multiplier components.
- `facade_router_dispatcher`: Unified entrypoint facade abstracting multi-hop routing across individual AMM pools.
- `flyweight_class_hash_registry`: Flyweight pattern reusing shared class hashes across multiple proxy instances.
- `proxy_delegate_dispatcher`: Proxy pattern forwarding calls via `library_call_syscall` or contract dispatchers.

### 6. 🎯 GoF Behavioral Patterns (11/11)
- `chain_of_responsibility_permission_pipe`: Passing transaction requests through sequenced permission check functions.
- `command_account_call_payload`: Encapsulating executable actions into Starknet `Call` structs passed to account executors.
- `interpreter_bytecode_evaluator`: Evaluating on-chain DSL rules or state transition byte instructions from spans.
- `iterator_span_cursor_scan`: Cursor-based iteration over Span elements (`span.pop_front()`, `loop`).
- `mediator_escrow_atomic_swap`: Central escrow contract mediating atomic token exchanges between counterparties.
- `memento_checkpoint_snapshot`: Recording historical block or epoch checkpoints for governance and reward calculations.
- `observer_event_emission`: Observer pattern broadcasting typed event variants (`self.emit`) for indexers.
- `state_machine_vault_lifecycle`: Finite State Machine enforcing protocol states (Pending, Active, Paused, Settled).
- `strategy_yield_harvest_injection`: Strategy pattern injecting interchangeable yield/rebalance dispatchers into vaults.
- `template_method_hook_lifecycle`: Fixed execution skeleton coordinating entrypoints with pre/post execution hooks.
- `visitor_flashloan_receiver`: Callback receiver invoked by flashloan pools during borrow transactions.

### 7. 🛡️ Starknet Security Hazards
- `unprotected_external_entry_hazard`: Public external function modifying contract storage without caller verification.
- `missing_caller_verification_hazard`: Critical admin or upgrade function lacking access control verification.
- `unbounded_storage_loop_dos_hazard`: Unbounded loop over dynamic storage or array risking transaction step exhaustion.
- `l1_l2_reentrancy_hazard`: L1 message handler invoking external contract calls before updating local storage state.

### 8. 📐 SOLID Principles & Smells
- `monolithic_contract_srp`: Contract declaring excessive functions (>= 15) or storage fields (>= 10), violating Single Responsibility.
- `fat_component_interface_isp`: Interface trait declaring excessive methods (>= 10), violating Interface Segregation.
- `hardcoded_contract_address_ocp`: Hardcoding literal contract addresses (`contract_address_const::<0x...>`) instead of configurable parameters.

---

## 🌐 The DPX Suite Family

Cross-language architectural static analysis across all modern programming languages:

| Repository | Language / Ecosystem | Primary Paradigms & Focus |
|---|---|---|
| **[`DPX-Cairo`](https://github.com/bivex/DPX-Cairo)** | **Cairo** (Cairo 1.0 - 2.8+ / Starknet) | **Components, Storage Mapping, Syscalls, Account Abstraction, Upgrades, GoF 23** |
| **[`DPX-Move`](https://github.com/bivex/DPX-Move)** | **Move** (Move 2024 / Aptos / Sui) | **Linear Resources, Abilities, Sui Objects, Hot Potato, Prover, GoF 23** |
| **[`DPX-Lua`](https://github.com/bivex/DPX-Lua)** | **Lua / Luau** (5.1 - 5.4 / LuaJIT) | **Metatable OOP, Coroutines, LuaJIT FFI, GameDev (Roblox/Neovim), GoF 23** |
| **[`DPX-Solidity`](https://github.com/bivex/DPX-Solidity)** | **Solidity** (0.8.x - 0.8.28+) | **EVM Gas Optimization, Proxies, CEI Reentrancy, Yul, GoF 23, Security** |
| **[`DPX-Zig`](https://github.com/bivex/DPX-Zig)** | **Zig** (0.11 - 0.14+) | **Comptime Generics, Allocator RAII, Defer Cleanup, SIMD, GoF 23** |
| **[`DPX-Gleam`](https://github.com/bivex/DPX-Gleam)** | **Gleam** (1.0 - 1.8+) | **Type-Safe OTP Actors, Algebraic Data Types, Railway Monads, GoF 23** |
| **[`DPX-Mojo`](https://github.com/bivex/DPX-Mojo)** | **Mojo** (24.x - 25.x+) | **SIMD Vectorization, Ownership, Memory Safety, GoF 23, AI Acceleration** |
| **[`DPX-Julia`](https://github.com/bivex/DPX-Julia)** | **Julia** (1.6 - 1.11+) | **Multiple Dispatch, Holy Traits, Metaprogramming, Tasks, GoF 23** |
| **[`DPX-Kotlin`](https://github.com/bivex/DPX-Kotlin)** | **Kotlin** (1.8 - 2.0+) | **Coroutines, Flow, Jetpack Compose, Multiplatform, GoF 23** |
| **[`DPX-Swift`](https://github.com/bivex/DPX-Swift)** | **Swift** (5.5 - 6.0+) | **Protocol-Oriented, Actor Concurrency, SwiftUI, ARC Safety** |
| **[`DPX-CSharp`](https://github.com/bivex/DPX-CSharp)** | **C#** (10 - 13 / .NET 8-9) | **Clean Architecture, CQRS MediatR, Channel Pipelines** |
| **[`DPX-TypeScript`](https://github.com/bivex/DPX-TypeScript)** | **TypeScript / JavaScript** | **Hexagonal DI, Decorator Meta, Reactive Streams, React/NestJS** |
| **[`DPX-Rust`](https://github.com/bivex/DPX-Rust)** | **Rust** (Edition 2021/2024) | **Zero-Cost Abstractions, RAII Lifetimes, Typestate Pattern** |
| **[`DPX-Go`](https://github.com/bivex/DPX-Go)** | **Go** (1.18 - 1.24+) | **Goroutine Channels, CSP Concurrency, Pipeline Streaming** |
| **[`DPX-Py`](https://github.com/bivex/DPX-Py)** | **Python** (3.8 - 3.13+) | **Multi-Paradigm Hexagonal, Data Flow Engine, AsyncIO** |
| **[`DPX-Php`](https://github.com/bivex/DPX-Php)** | **PHP** (8.1 - 8.4+) | **Attribute-driven DDD, Fiber Concurrency, Laravel/Symfony** |
| **[`DPX-Haskell`](https://github.com/bivex/DPX-Haskell)** | **Haskell** (GHC 9.2 - 9.12+) | **Category Theory, Monad Transformers, Free Monads, Optics** |
| **[`DPX-OCaml`](https://github.com/bivex/DPX-OCaml)** | **OCaml** (4.14 - 5.3+ Multicore) | **Functor Modules, Effect Handlers, GADTs, Railway Monads** |
| **[`DPX-Elixir`](https://github.com/bivex/DPX-Elixir)** | **Elixir** (OTP 25 - 27+) | **GenServer, DynamicSupervisor, Actor Fault Tolerance** |
| **[`DPX-Erlang`](https://github.com/bivex/DPX-Erlang)** | **Erlang/OTP** (24 - 27+) | **OTP Behaviors, Supervision Trees, Message Passing** |
| **[`DPX-C`](https://github.com/bivex/DPX-C)** | **C** (C99 - C23) | **Opaque Structs, VTables, MISRA/CERT Safety, Arena Allocators** |
| **[`DPX-Cpp`](https://github.com/bivex/DPX-Cpp)** | **C++** (C++14 - C++20) | **CRTP, Policy-Based Design, RAII Memory Safety, ANTLR4 AST** |
| **[`DPX-Java`](https://github.com/bivex/DPX-Java)** | **Java** (17 - 23+) | **Virtual Threads, Spring Boot / Jakarta EE, GoF Patterns** |
| **[`DPX`](https://github.com/bivex/DPX)** | **Clojure** / Meta Engine | **Pure Functional, Multimethods, Homoiconic Macro Architecture** |
---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
