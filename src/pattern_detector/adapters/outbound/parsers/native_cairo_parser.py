"""High-speed native parser adapter for Cairo smart contract source code (.cairo)."""

from __future__ import annotations

import re
from pattern_detector.domain.code_model import (
    CairoComponentDecl,
    CairoContract,
    CairoEvent,
    CairoField,
    CairoFile,
    CairoFunction,
    CairoImpl,
    CairoStorage,
    CairoTrait,
    CodeModel,
)
from pattern_detector.domain.value_objects import SourceLocation
from pattern_detector.ports.outbound import ParserPort


def _split_top_level_commas(s: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    depth = 0
    for char in s:
        if char in "([{<":
            depth += 1
            current.append(char)
        elif char in ")]}>":
            depth -= 1
            current.append(char)
        elif char == "," and depth == 0:
            parts.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        parts.append("".join(current).strip())
    return [p for p in parts if p]


class NativeCairoParserAdapter(ParserPort):
    """Single-pass robust parser extracting Starknet contracts, components, storage, traits, and functions."""

    CONTRACT_ATTR_PATTERN = re.compile(r"^\s*#\[starknet::contract\]")
    COMPONENT_ATTR_PATTERN = re.compile(r"^\s*#\[starknet::component\]")
    INTERFACE_ATTR_PATTERN = re.compile(r"^\s*#\[starknet::interface\]")
    ABI_EMBED_ATTR_PATTERN = re.compile(r"^\s*#\[abi\((?:embed_v0|per_item)\)\]")
    STORAGE_ATTR_PATTERN = re.compile(r"^\s*#\[storage\]")
    EVENT_ATTR_PATTERN = re.compile(r"^\s*#\[event\]")
    L1_HANDLER_ATTR_PATTERN = re.compile(r"^\s*#\[l1_handler\]")
    CONSTRUCTOR_ATTR_PATTERN = re.compile(r"^\s*#\[constructor\]")
    EXTERNAL_ATTR_PATTERN = re.compile(r"^\s*#\[external\((?:v0)?\)\]")

    MOD_DECL_PATTERN = re.compile(r"^\s*(?:pub\s+)?mod\s+(?P<name>[a-zA-Z0-9_]+)\s*\{")
    TRAIT_DECL_PATTERN = re.compile(r"^\s*(?:pub\s+)?trait\s+(?P<name>[a-zA-Z0-9_]+)(?:<(?P<generics>[^>]+)>)?\s*\{")
    IMPL_DECL_PATTERN = re.compile(r"^\s*(?:pub\s+)?impl\s+(?P<name>[a-zA-Z0-9_]+)(?:<[^>]+>)?\s+of\s+(?P<trait>[a-zA-Z0-9_:]+)(?:<[^>]+>)?\s*\{")
    FN_HEADER_PATTERN = re.compile(r"^\s*(?P<vis>pub\s+)?fn\s+(?P<name>[a-zA-Z0-9_]+)(?:<(?P<generics>[^>]+)>)?\s*\(")
    COMPONENT_MACRO_PATTERN = re.compile(r"^\s*component!\s*\(\s*path:\s*(?P<path>[a-zA-Z0-9_:]+)\s*,\s*storage:\s*(?P<storage>[a-zA-Z0-9_]+)\s*,\s*event:\s*(?P<event>[a-zA-Z0-9_]+)\s*\)\s*;")

    def parse_file(self, file_path: str, content: str) -> CairoFile:
        lines = content.splitlines()
        file_obj = CairoFile(file_path=file_path, raw_content=content, lines=lines)

        pending_contract_attr = False
        pending_component_attr = False
        pending_interface_attr = False
        pending_abi_embed = False
        pending_storage = False
        pending_event = False
        pending_l1_handler = False
        pending_constructor = False
        pending_external = False

        current_contract: CairoContract | None = None
        contract_brace_depth = 0

        current_trait: CairoTrait | None = None
        trait_brace_depth = 0

        current_impl: CairoImpl | None = None
        impl_brace_depth = 0

        current_storage: CairoStorage | None = None
        storage_brace_depth = 0
        storage_lines: list[str] = []

        current_function: CairoFunction | None = None
        func_brace_depth = 0
        current_func_body: list[str] = []

        for line_idx, raw_line in enumerate(lines, 1):
            trimmed = raw_line.strip()

            if trimmed.startswith("//") or not trimmed:
                continue

            # Check attributes
            if self.CONTRACT_ATTR_PATTERN.match(trimmed):
                pending_contract_attr = True
                continue
            if self.COMPONENT_ATTR_PATTERN.match(trimmed):
                pending_component_attr = True
                continue
            if self.INTERFACE_ATTR_PATTERN.match(trimmed):
                pending_interface_attr = True
                continue
            if self.ABI_EMBED_ATTR_PATTERN.match(trimmed):
                pending_abi_embed = True
                continue
            if self.STORAGE_ATTR_PATTERN.match(trimmed):
                pending_storage = True
                continue
            if self.EVENT_ATTR_PATTERN.match(trimmed):
                pending_event = True
                continue
            if self.L1_HANDLER_ATTR_PATTERN.match(trimmed):
                pending_l1_handler = True
                continue
            if self.CONSTRUCTOR_ATTR_PATTERN.match(trimmed):
                pending_constructor = True
                continue
            if self.EXTERNAL_ATTR_PATTERN.match(trimmed):
                pending_external = True
                continue

            # Module / Contract Declaration
            mod_m = self.MOD_DECL_PATTERN.match(trimmed)
            if mod_m and not current_contract:
                m_name = mod_m.group("name")
                current_contract = CairoContract(
                    name=m_name,
                    is_starknet_contract=pending_contract_attr,
                    is_starknet_component=pending_component_attr,
                    location=SourceLocation(file_path=file_path, line=line_idx, column=1),
                    raw_text=raw_line,
                )
                pending_contract_attr = False
                pending_component_attr = False
                contract_brace_depth = raw_line.count("{") - raw_line.count("}")
                continue

            # Trait / Interface Declaration
            trait_m = self.TRAIT_DECL_PATTERN.match(trimmed)
            if trait_m and not current_trait and not current_function:
                t_name = trait_m.group("name")
                current_trait = CairoTrait(
                    name=t_name,
                    is_starknet_interface=pending_interface_attr,
                    location=SourceLocation(file_path=file_path, line=line_idx, column=1),
                    raw_text=raw_line,
                )
                pending_interface_attr = False
                trait_brace_depth = raw_line.count("{") - raw_line.count("}")
                continue

            if current_trait:
                trait_brace_depth += raw_line.count("{") - raw_line.count("}")
                fn_m = self.FN_HEADER_PATTERN.match(trimmed)
                if fn_m:
                    current_trait.methods.append(fn_m.group("name"))
                if trait_brace_depth <= 0:
                    file_obj.traits.append(current_trait)
                    current_trait = None
                    trait_brace_depth = 0
                continue

            # Inside Contract:
            if current_contract:
                # Component Macro (component!(...))
                comp_m = self.COMPONENT_MACRO_PATTERN.match(trimmed)
                if comp_m:
                    c_path = comp_m.group("path")
                    c_storage = comp_m.group("storage")
                    c_event = comp_m.group("event")
                    current_contract.components.append(
                        CairoComponentDecl(
                            name=c_path.split("::")[-1],
                            path=c_path,
                            storage_name=c_storage,
                            event_name=c_event,
                            location=SourceLocation(file_path=file_path, line=line_idx, column=1),
                        )
                    )
                    continue

                # Storage Struct
                if pending_storage and "struct Storage" in trimmed:
                    pending_storage = False
                    storage_lines = [raw_line]
                    current_storage = CairoStorage(
                        location=SourceLocation(file_path=file_path, line=line_idx, column=1),
                        raw_text=raw_line,
                    )
                    storage_brace_depth = raw_line.count("{") - raw_line.count("}")
                    if storage_brace_depth <= 0 and "{" in raw_line and "}" in raw_line:
                        current_storage.raw_text = "\n".join(storage_lines)
                        current_contract.storage = current_storage
                        current_storage = None
                        storage_brace_depth = 0
                    continue

                if current_storage:
                    storage_lines.append(raw_line)
                    storage_brace_depth += raw_line.count("{") - raw_line.count("}")
                    if ":" in trimmed and not trimmed.startswith("//"):
                        f_part = trimmed.rstrip(",").rstrip(";").strip()
                        if ":" in f_part:
                            fname, ftype = f_part.split(":", 1)
                            fname = fname.strip()
                            ftype = ftype.strip()
                            current_storage.fields.append(CairoField(name=fname, type_str=ftype))
                            if "Map<" in ftype or "LegacyMap<" in ftype:
                                current_storage.has_mapping = True
                            if "Vec<" in ftype:
                                current_storage.has_vec = True

                    if storage_brace_depth <= 0:
                        current_storage.raw_text = "\n".join(storage_lines)
                        current_contract.storage = current_storage
                        current_storage = None
                        storage_brace_depth = 0
                    continue

                # Impl block
                impl_m = self.IMPL_DECL_PATTERN.match(trimmed)
                if impl_m and not current_impl and not current_function:
                    i_name = impl_m.group("name")
                    i_trait = impl_m.group("trait")
                    current_impl = CairoImpl(
                        name=i_name,
                        trait_name=i_trait,
                        is_embedded_abi=pending_abi_embed,
                        location=SourceLocation(file_path=file_path, line=line_idx, column=1),
                        raw_text=raw_line,
                    )
                    pending_abi_embed = False
                    impl_brace_depth = raw_line.count("{") - raw_line.count("}")
                    continue

                # Functions inside Impl or Contract
                if not current_function:
                    fn_m = self.FN_HEADER_PATTERN.match(trimmed)
                    if fn_m:
                        f_vis = (fn_m.group("vis") or "").strip() or "private"
                        f_name = fn_m.group("name")

                        # Parse parameters
                        rest = trimmed[fn_m.end():]
                        depth = 1
                        i = 0
                        while i < len(rest) and depth > 0:
                            if rest[i] == "(":
                                depth += 1
                            elif rest[i] == ")":
                                depth -= 1
                            i += 1

                        params_str = rest[:i-1] if i > 0 else ""
                        params = [p.strip() for p in _split_top_level_commas(params_str) if p.strip()]

                        is_ext = pending_external or (current_impl and current_impl.is_embedded_abi)
                        current_function = CairoFunction(
                            name=f_name,
                            visibility=f_vis,
                            is_external=is_ext,
                            is_l1_handler=pending_l1_handler,
                            is_constructor=pending_constructor,
                            parameters=params,
                            location=SourceLocation(file_path=file_path, line=line_idx, column=1),
                            raw_text=raw_line,
                        )
                        pending_external = False
                        pending_l1_handler = False
                        pending_constructor = False

                        current_func_body = [raw_line]
                        func_brace_depth = raw_line.count("{") - raw_line.count("}")

                        if "get_caller_address" in raw_line:
                            current_function.has_caller_check = True
                        if "assert!" in raw_line or "assert(" in raw_line:
                            current_function.has_assert = True
                        if "self.emit(" in raw_line:
                            current_function.has_emit = True

                        if func_brace_depth <= 0 and "{" in raw_line:
                            current_function.body = "\n".join(current_func_body)
                            if current_impl:
                                current_impl.functions.append(current_function)
                            else:
                                current_contract.functions.append(current_function)
                            current_function = None
                            current_func_body = []
                            func_brace_depth = 0
                        continue

                if current_function:
                    current_func_body.append(raw_line)
                    func_brace_depth += raw_line.count("{") - raw_line.count("}")

                    if "get_caller_address" in raw_line:
                        current_function.has_caller_check = True
                    if "assert!" in raw_line or "assert(" in raw_line:
                        current_function.has_assert = True
                    if "self.emit(" in raw_line:
                        current_function.has_emit = True

                    if func_brace_depth <= 0:
                        current_function.body = "\n".join(current_func_body)
                        if current_impl:
                            current_impl.functions.append(current_function)
                        else:
                            current_contract.functions.append(current_function)
                        current_function = None
                        current_func_body = []
                        func_brace_depth = 0
                    continue

                if current_impl:
                    impl_brace_depth += raw_line.count("{") - raw_line.count("}")
                    if impl_brace_depth <= 0:
                        current_contract.impls.append(current_impl)
                        current_impl = None
                        impl_brace_depth = 0
                    continue

                contract_brace_depth += raw_line.count("{") - raw_line.count("}")
                if contract_brace_depth <= 0:
                    file_obj.contracts.append(current_contract)
                    current_contract = None
                    contract_brace_depth = 0
                continue

            # Free functions outside contracts
            if not current_function:
                fn_m = self.FN_HEADER_PATTERN.match(trimmed)
                if fn_m:
                    f_vis = (fn_m.group("vis") or "").strip() or "private"
                    f_name = fn_m.group("name")

                    # Parse parameters
                    rest = trimmed[fn_m.end():]
                    depth = 1
                    i = 0
                    while i < len(rest) and depth > 0:
                        if rest[i] == "(":
                            depth += 1
                        elif rest[i] == ")":
                            depth -= 1
                        i += 1

                    params_str = rest[:i-1] if i > 0 else ""
                    params = [p.strip() for p in _split_top_level_commas(params_str) if p.strip()]

                    current_function = CairoFunction(
                        name=f_name,
                        visibility=f_vis,
                        is_external=pending_external,
                        is_l1_handler=pending_l1_handler,
                        is_constructor=pending_constructor,
                        parameters=params,
                        location=SourceLocation(file_path=file_path, line=line_idx, column=1),
                        raw_text=raw_line,
                    )
                    pending_external = False
                    pending_l1_handler = False
                    pending_constructor = False

                    current_func_body = [raw_line]
                    func_brace_depth = raw_line.count("{") - raw_line.count("}")

                    if "get_caller_address" in raw_line:
                        current_function.has_caller_check = True
                    if "assert!" in raw_line or "assert(" in raw_line:
                        current_function.has_assert = True
                    if "self.emit(" in raw_line:
                        current_function.has_emit = True

                    if func_brace_depth <= 0 and "{" in raw_line:
                        current_function.body = "\n".join(current_func_body)
                        file_obj.free_functions.append(current_function)
                        current_function = None
                        current_func_body = []
                        func_brace_depth = 0
                    continue

            if current_function:
                current_func_body.append(raw_line)
                func_brace_depth += raw_line.count("{") - raw_line.count("}")

                if "get_caller_address" in raw_line:
                    current_function.has_caller_check = True
                if "assert!" in raw_line or "assert(" in raw_line:
                    current_function.has_assert = True
                if "self.emit(" in raw_line:
                    current_function.has_emit = True

                if func_brace_depth <= 0:
                    current_function.body = "\n".join(current_func_body)
                    file_obj.free_functions.append(current_function)
                    current_function = None
                    current_func_body = []
                    func_brace_depth = 0
                continue

        if current_contract:
            file_obj.contracts.append(current_contract)
        if current_trait:
            file_obj.traits.append(current_trait)

        return file_obj

    def parse_codebase(self, files: list[tuple[str, str]], target_path: str = "") -> CodeModel:
        model = CodeModel(target_path=target_path)
        for fpath, content in files:
            c_file = self.parse_file(fpath, content)
            model.files.append(c_file)
        return model
