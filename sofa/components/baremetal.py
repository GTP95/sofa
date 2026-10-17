"""Configurable direct invocation of prebuilt ARM64 and RISC-V ELF routines."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile
from qiling import Qiling
from qiling.const import QL_OS, QL_VERBOSE

from sofa.components.qiling_profile import QilingProfile
from sofa.components.sym_parser import SymParser
from sofa.utils.architectures import ARCHITECTURES, Architecture, decode_access, instruction_type
from sofa.utils.register_access import DecodedRegisterAccess, PendingInstruction


class BaremetalRecorder:
    """Capture physical pre/post state in the version-two trace format."""

    def __init__(self, ql: Qiling, arch: Architecture, traces: list[list[Any]],
                 begin: int, end: int, model: str) -> None:
        """Initialize one recorder with a shared physical register layout."""
        self.arch = arch
        self.traces = traces
        self.begin, self.end = begin, end
        self.model = model
        self.disassembler = ql.arch.disassembler
        self.cache: dict[tuple[int, bytes], DecodedRegisterAccess] = {}
        self.active = False
        self.pending: PendingInstruction | None = None
        self.window_id = -1
        self.header = ["PC", "Machine", "Ins", "Type", "Operands", "trace_schema", "architecture",
                       "window_id", "read_mask", "write_mask", "status_pre", *arch.names]
        if model == "accessed":
            self.header.extend(f"post_{name}" for name in arch.names)

    def values(self, ql: Qiling) -> tuple[int, ...]:
        """Read complete physical registers without truncating FP or SIMD bits."""
        return tuple(int(ql.arch.regs.read(name)) & ((1 << width) - 1)
                     for name, width in zip(self.arch.names, self.arch.widths, strict=True))

    def finalize(self, ql: Qiling, next_address: int) -> None:
        """Finalize one instruction, suppressing a branch PC write on fallthrough."""
        if self.pending is None:
            return
        pending = self.pending
        decoded = pending.decoded
        writes = decoded.write_mask
        if decoded.conditional_control_flow and next_address == decoded.address + decoded.size:
            writes &= ~(1 << self.arch.names.index("pc"))
        row = [hex(decoded.address), decoded.machine, decoded.mnemonic, instruction_type(decoded), decoded.operands,
               f"sofa-{self.model}-v2", self.arch.name, pending.window_id, hex(decoded.read_mask),
               hex(writes), hex(pending.status_pre), *(hex(v) for v in pending.pre_values)]
        if self.model == "accessed":
            row.extend(hex(v) for v in self.values(ql))
        self.traces.append(row)
        self.pending = None

    def on_instruction(self, ql: Qiling, address: int, size: int, user_data: object = None) -> None:
        """Capture instructions between explicit start and end marker events."""
        if address == self.begin:
            self.finalize(ql, address)
            self.active = True
            self.window_id += 1
        if not self.active:
            return
        self.finalize(ql, address)
        if address == self.end:
            self.active = False
            return
        code = bytes(ql.mem.read(address, size))
        key = (address, code)
        decoded = self.cache.get(key)
        if decoded is None:
            decoded = decode_access(self.arch, self.disassembler, code, address)
            self.cache[key] = decoded
        status = int(ql.arch.regs.read(self.arch.status))
        self.pending = PendingInstruction(decoded, self.values(ql), status, self.window_id)

    def validate_complete(self) -> None:
        """Reject missing or unfinished capture windows."""
        if self.window_id < 0 or self.active or self.pending is not None:
            raise RuntimeError("Bare-metal execution did not complete its capture window")


class BaremetalProfile(QilingProfile):
    """Adapt existing algorithm input rows to profile-defined direct calls."""

    def __init__(self, config: dict[str, Any]) -> None:
        """Retain raw settings without imposing UART-specific fields."""
        super().__init__()
        self.config = config
        self.input_format = "hex"

    def get_algorithm_name(self) -> str:
        """Return the base algorithm used for generation and validation."""
        return self.config["target"].split("_")[0].upper()

    def get_profile_range(self, sym_parser: SymParser) -> tuple[int, int]:
        """Resolve explicit capture markers without Thumb address adjustment."""
        return tuple(resolve(self.config[name], sym_parser) for name in ("trace_start", "trace_end"))

    def init_uart(self, ql: Qiling, input_format: str) -> None:
        """Remember input encoding; bare-metal calls do not use a UART."""
        self.input_format = input_format

    def hook_cmds(self, ql: Qiling, sym_parser: SymParser, target_data: list[str]) -> None:
        """Populate buffers and configure the routine's integer arguments."""
        arch: Architecture = ql.sofa_architecture
        call = self.config["direct_call"]
        fields = {"AES": ["key", "plaintext", "iv"], "ASCON": ["key", "plaintext", "nonce", "ad"],
                  "KECCAK": ["plaintext"]}[self.get_algorithm_name()]
        inputs = {name: (value.encode("utf-8") if self.input_format == "plaintext" else bytes.fromhex(value))
                  for name, value in zip(fields, target_data) if value is not None}
        buffers = call.get("buffers", {})
        for name, spec in buffers.items():
            address, size = spec["address"], spec["size"]
            if "input" in spec and spec["input"] not in inputs:
                raise ValueError(f"Unavailable input source for buffer {name!r}: {spec['input']!r}")
            data = inputs[spec["input"]] if "input" in spec else b""
            if len(data) > size:
                raise ValueError(f"Input exceeds buffer {name!r} ({len(data)} > {size})")
            ql.mem.write(address, data.ljust(size, b"\0"))
        arguments = []
        for arg in call.get("arguments", []):
            if isinstance(arg, int) and not isinstance(arg, bool):
                value = arg
            elif isinstance(arg, dict) and set(arg) == {"buffer"}:
                if arg["buffer"] not in buffers:
                    raise ValueError(f"Unknown direct-call buffer: {arg['buffer']!r}")
                value = buffers[arg["buffer"]]["address"]
            elif isinstance(arg, dict) and set(arg) == {"length"}:
                if arg["length"] not in inputs:
                    raise ValueError(f"Unavailable input length: {arg['length']!r}")
                value = len(inputs[arg["length"]])
            else:
                raise ValueError(f"Invalid direct-call argument: {arg!r}")
            if not 0 <= value < 1 << arch.bits:
                raise ValueError("Direct-call argument exceeds architecture width")
            arguments.append(value)
        stack = call["stack_address"]
        for index, value in enumerate(arguments):
            if index < len(arch.arguments):
                ql.arch.regs.write(arch.arguments[index], value)
            else:
                address = stack + (index - len(arch.arguments)) * (arch.bits // 8)
                require_range(ql, address, arch.bits // 8, 2, "stack argument")
                ql.mem.write_ptr(address, value, arch.bits // 8)
        ql.arch.regs.arch_sp = stack
        ql.arch.regs.write(arch.link, call["return_address"])
        ql.sofa_entry = resolve(call["entry"], sym_parser)
        require_range(ql, ql.sofa_entry, 4, 4, "entry point")
        ql.arch.regs.arch_pc = ql.sofa_entry


def resolve(value: str | int, symbols: SymParser) -> int:
    """Resolve a numeric address or an exact ELF symbol."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        return symbols.get_symbol_by_name(value)
    raise ValueError(f"Expected a symbol or numeric address, got {value!r}")


def require_range(ql: Qiling, address: int, size: int, permission: int, description: str) -> None:
    """Require every page of a range to be mapped with specified permissions."""
    if not isinstance(address, int) or not isinstance(size, int) or size <= 0 or address < 0 or address + size > 1 << ql.arch.bits:
        raise ValueError(f"Invalid {description} range")
    cursor = address
    for start, end, perms, *_ in sorted(ql.mem.map_info):
        if start <= cursor < end:
            if perms & permission != permission:
                raise ValueError(f"Insufficient permissions for {description}")
            cursor = min(end, address + size)
            if cursor == address + size:
                return
    raise ValueError(f"Unmapped {description} range at {cursor:#x}")


def initialize_baremetal(elf: str, config: dict[str, Any], profile: BaremetalProfile,
                         symbols: SymParser, traces: list[list[Any]], model: str) -> Qiling:
    """Load a static ELF and install architecture-aware capture and return hooks."""
    if config.get("platform") != "baremetal" or config.get("execution_mode") != "baremetal-direct":
        raise ValueError("Bare-metal profiles require platform 'baremetal' and execution_mode 'baremetal-direct'")
    if model not in {"accessed", "all"}:
        raise ValueError(f"Unsupported register model: {model}")
    with Path(elf).open("rb") as source:
        image = ELFFile(source)
        machine = image.header["e_machine"]
        name = "arm64" if machine == "EM_AARCH64" and image.elfclass == 64 else f"riscv{image.elfclass}" if machine == "EM_RISCV" else ""
        if not image.little_endian or name not in ARCHITECTURES:
            raise ValueError("Expected a little-endian ARM64, RV32, or RV64 ELF")
        if config.get("architecture", name) != name:
            raise ValueError("Profile architecture does not match ELF")
        arch = ARCHITECTURES[name]
        if image.header["e_type"] != "ET_EXEC" or any(s["p_type"] in {"PT_INTERP", "PT_DYNAMIC"} for s in image.iter_segments()):
            raise ValueError("Bare-metal execution requires a statically linked ET_EXEC ELF")
        if any(s["sh_type"] in {"SHT_REL", "SHT_RELA"} and s["sh_flags"] & 2 and s["sh_size"] for s in image.iter_sections()):
            raise ValueError("Unresolved ELF relocations are unsupported")
        segments = [(int(s["p_vaddr"]), int(s["p_memsz"]), int(s["p_flags"]), s.data())
                    for s in image.iter_segments() if s["p_type"] == "PT_LOAD" and s["p_memsz"]]
    if not segments:
        raise ValueError("ELF has no loadable segments")
    pages: dict[int, int] = {}
    for address, size, flags, data in segments:
        if address + size > 1 << arch.bits or len(data) > size:
            raise ValueError("Invalid ELF load segment")
        perms = (1 if flags & 4 else 0) | (2 if flags & 2 else 0) | (4 if flags & 1 else 0)
        for page in range(address & ~4095, (address + size + 4095) & ~4095, 4096):
            pages[page] = pages.get(page, 0) | perms
    mappings = config.get("memory_mappings", [])
    for spec in mappings:
        address, size, perms = spec["base_address"], spec["size"], spec["perms"]
        if address < 0 or size <= 0 or address % 4096 or size % 4096 or address + size > 1 << arch.bits or not 0 < perms < 8:
            raise ValueError("Memory mappings require aligned, positive, architecture-sized ranges and valid permissions")
        for page in range(address, address + size, 4096):
            if page in pages:
                raise ValueError("Additional memory mappings overlap ELF segments or each other")
            pages[page] = perms
    bootstrap = 0x10000
    while bootstrap in pages or bootstrap + 4096 in pages:
        bootstrap += 8192
    ql = Qiling(code=b"\0" * 4, archtype=arch.qiling_arch, ostype=QL_OS.BLOB,
                profile={"CODE": {"load_address": str(bootstrap), "entry_point": str(bootstrap), "ram_size": "8192"}},
                verbose=QL_VERBOSE.DEBUG if logging.getLogger().isEnabledFor(logging.DEBUG) else QL_VERBOSE.DISABLED)
    ql.mem.unmap(bootstrap, 8192)
    for address, perms in sorted(pages.items()):
        ql.mem.map(address, 4096, perms=perms)
    # Newly mapped pages are zeroed by Unicorn, including BSS.
    for address, _size, _flags, data in segments:
        ql.mem.write(address, data)
    if name != "arm64":
        # The pinned Qiling backend exposes ABI aliases but omits x0-x31.
        from qiling.arch.riscv_const import reg_general_map
        ql.arch.regs.register_mapping.update(reg_general_map)
    ql.sofa_architecture = arch
    if name == "arm64":
        ql.arch.enable_vfp()
    else:
        ql.arch.enable_float()
    call = config["direct_call"]
    stack, stop = call["stack_address"], call["return_address"]
    if not isinstance(stack, int) or isinstance(stack, bool) or stack % 16:
        raise ValueError("The direct-call stack must be 16-byte aligned")
    alignment = 4 if name == "arm64" else 2
    entry = resolve(call["entry"], symbols)
    if not isinstance(stop, int) or isinstance(stop, bool) or stop % alignment or entry % alignment:
        raise ValueError("Entry and return addresses must be instruction aligned")
    require_range(ql, stack - 16, 16, 2, "stack")
    require_range(ql, stop, 4, 4, "return address")
    # A valid sentinel avoids RISC-V translation faults before its hook fires.
    ql.mem.write(stop, bytes.fromhex("1f2003d5" if name == "arm64" else "13000000"))
    require_range(ql, resolve(call["entry"], symbols), 4, 4, "entry point")
    for spec in call.get("buffers", {}).values():
        require_range(ql, spec["address"], spec["size"], 3, "buffer")
    begin, end = profile.get_profile_range(symbols)
    if begin == end or begin == stop:
        raise ValueError("Capture start must differ from capture end and return address")
    for marker in (begin, end):
        if marker % (4 if name == "arm64" else 2):
            raise ValueError("Unaligned capture marker")
        require_range(ql, marker, 2, 4, "capture marker")
    recorder = BaremetalRecorder(ql, arch, traces, begin, end, model)
    ql.sofa_access_recorder = recorder
    ql.sofa_trace_header = recorder.header
    ql.sofa_returned = False
    ql.hook_code(recorder.on_instruction)

    def stop_call(emulator: Qiling) -> None:
        """Finalize the final sample even if the address hook runs first."""
        recorder.on_instruction(emulator, stop, 4)
        recorder.validate_complete()
        emulator.sofa_returned = True
        emulator.stop()

    ql.hook_address(stop_call, stop)
    return ql
