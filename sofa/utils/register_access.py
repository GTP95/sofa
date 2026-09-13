"""Instruction-level ARM register access capture for refined leakage models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from capstone import CS_GRP_CALL, CS_GRP_JUMP, Cs
from capstone.arm import ARM_CC_AL, ARM_CC_INVALID
from qiling import Qiling

from sofa.utils.arm_helpers import return_instruction_type_arm


REGISTER_NAMES: tuple[str, ...] = tuple(
    [f"r{index}" for index in range(13)] + ["sp", "lr", "pc"]
)
REGISTER_INDEX: dict[str, int] = {
    register: index for index, register in enumerate(REGISTER_NAMES)
}
REGISTER_ALIASES: dict[str, str] = {
    "r13": "sp",
    "r14": "lr",
    "r15": "pc",
    "sb": "r9",
    "sl": "r10",
    "fp": "r11",
    "ip": "r12",
}

ACCESSED_TRACE_HEADER: list[str] = [
    "PC",
    "Machine",
    "Ins",
    "Type",
    "Operands",
    "trace_schema",
    "window_id",
    "read_mask",
    "write_mask",
    "status_pre",
    *REGISTER_NAMES,
    *(f"post_{register}" for register in REGISTER_NAMES),
]


@dataclass(frozen=True)
class DecodedRegisterAccess:
    """Describe one decoded instruction and its architectural register sets."""

    address: int
    size: int
    machine: str
    mnemonic: str
    operands: str
    read_mask: int
    write_mask: int
    changes_control_flow: bool
    conditional_control_flow: bool


@dataclass
class PendingInstruction:
    """Hold an instruction until its post-execution state is observable."""

    decoded: DecodedRegisterAccess
    pre_values: tuple[int, ...]
    status_pre: int
    window_id: int


def register_mask(registers: set[str]) -> int:
    """Return the bit mask for canonical register names in ``registers``."""
    mask = 0
    for register in registers:
        index = REGISTER_INDEX.get(register)
        if index is not None:
            mask |= 1 << index
    return mask


def canonical_register_name(name: str) -> str:
    """Normalize a Capstone ARM register name to Sofa's register spelling."""
    lowered = name.lower()
    return REGISTER_ALIASES.get(lowered, lowered)


def decode_register_access(
    disassembler: Cs,
    code: bytes,
    address: int,
) -> DecodedRegisterAccess:
    """Decode one instruction and return its corrected register access sets.

    Capstone 5.0.9 supplies most explicit and implicit operands through
    ``regs_access()``.  ARM branch and address-generation metadata still has a
    few omissions, which are corrected here.  Processor status registers are
    deliberately outside Sofa's 16-register power model.
    """
    disassembler.detail = True
    instructions = list(disassembler.disasm(code, address, count=1))
    if len(instructions) != 1:
        raise ValueError(f"Unable to decode instruction at {address:#x}")

    instruction = instructions[0]
    read_ids, write_ids = instruction.regs_access()
    reads = {
        canonical_register_name(disassembler.reg_name(register_id))
        for register_id in read_ids
    }
    writes = {
        canonical_register_name(disassembler.reg_name(register_id))
        for register_id in write_ids
    }
    mnemonic = instruction.mnemonic.lower()
    groups = set(instruction.groups)
    changes_control_flow = CS_GRP_JUMP in groups or CS_GRP_CALL in groups

    # Capstone 5.0.9 omits PC accesses for several Thumb control-flow
    # instructions and the PC-relative ADR pseudo-instruction.
    if mnemonic.startswith("adr"):
        reads.add("pc")
    if changes_control_flow:
        writes.add("pc")
    if changes_control_flow and "#" in instruction.op_str:
        reads.add("pc")
    conditional_control_flow = changes_control_flow and (
        instruction.cc not in (ARM_CC_AL, ARM_CC_INVALID)
        or mnemonic in {"cbz", "cbnz"}
    )

    return DecodedRegisterAccess(
        address=instruction.address,
        size=instruction.size,
        machine=bytes(instruction.bytes).hex(),
        mnemonic=instruction.mnemonic,
        operands=instruction.op_str,
        read_mask=register_mask(reads),
        write_mask=register_mask(writes),
        changes_control_flow=changes_control_flow,
        conditional_control_flow=conditional_control_flow,
    )


class AccessedRegisterRecorder:
    """Capture pre/post register state for instructions inside a profile window."""

    TRACE_SCHEMA = "sofa-accessed-v1"

    def __init__(
        self,
        disassembler: Cs,
        trace_data: list[list[Any]],
        cache: dict[tuple[int, bytes, int], DecodedRegisterAccess],
        begin: int,
        end: int,
    ) -> None:
        """Initialize an instruction recorder for the inclusive/exclusive range."""
        self.disassembler = disassembler
        self.trace_data = trace_data
        self.cache = cache
        self.begin = begin
        self.end = end
        self.active = False
        self.pending: PendingInstruction | None = None
        self.window_id = -1

    @staticmethod
    def _read_registers(ql: Qiling) -> tuple[int, ...]:
        """Read Sofa's supported general-purpose architectural registers."""
        return tuple(ql.arch.regs.read(register) & 0xFFFFFFFF for register in REGISTER_NAMES)

    @staticmethod
    def _read_status(ql: Qiling) -> int:
        """Read xPSR when the backend exposes it, otherwise return zero."""
        try:
            return ql.arch.regs.read("xpsr") & 0xFFFFFFFF
        except (KeyError, AttributeError):
            return 0

    def _finalize_pending(self, ql: Qiling, next_address: int) -> None:
        """Append the pending instruction using the current post-state."""
        if self.pending is None:
            return

        pending = self.pending
        decoded = pending.decoded
        write_mask = decoded.write_mask
        fallthrough = decoded.address + decoded.size
        if decoded.conditional_control_flow and next_address == fallthrough:
            # A conditional control-flow instruction that falls through did not
            # write its target to PC. Ordinary sequential PC progression is not
            # treated as register leakage.
            write_mask &= ~(1 << REGISTER_INDEX["pc"])

        post_values = self._read_registers(ql)
        self.trace_data.append(
            [
                hex(decoded.address),
                decoded.machine,
                decoded.mnemonic,
                return_instruction_type_arm(decoded.mnemonic.upper()),
                decoded.operands,
                self.TRACE_SCHEMA,
                pending.window_id,
                hex(decoded.read_mask),
                hex(write_mask),
                hex(pending.status_pre),
                *(hex(value) for value in pending.pre_values),
                *(hex(value) for value in post_values),
            ]
        )
        self.pending = None

    def on_instruction(
        self,
        ql: Qiling,
        address: int,
        size: int,
        _user_data: object = None,
    ) -> None:
        """Handle a pre-instruction Qiling code-hook event."""
        if address == self.begin:
            if self.active:
                self._finalize_pending(ql, address)
            self.active = True
            self.window_id += 1

        if not self.active:
            return

        status = self._read_status(ql)
        if status & 0x1FF:
            raise RuntimeError(
                "The accessed register model does not support instructions "
                "executed in an exception or interrupt handler"
            )

        self._finalize_pending(ql, address)
        if address == self.end:
            self.active = False
            return

        code = bytes(ql.mem.read(address, size))
        cache_key = (address, code, int(self.disassembler.mode))
        decoded = self.cache.get(cache_key)
        if decoded is None:
            decoded = decode_register_access(self.disassembler, code, address)
            self.cache[cache_key] = decoded
        self.pending = PendingInstruction(
            decoded=decoded,
            pre_values=self._read_registers(ql),
            status_pre=status,
            window_id=self.window_id,
        )

    def validate_complete(self) -> None:
        """Raise when execution stopped before the configured window closed."""
        if self.window_id < 0:
            raise RuntimeError(
                "Execution never reached the accessed-register trace window "
                f"start marker at {self.begin:#x}"
            )
        if self.active or self.pending is not None:
            raise RuntimeError(
                "Execution ended before the accessed-register trace window "
                f"reached its end marker at {self.end:#x}"
            )
