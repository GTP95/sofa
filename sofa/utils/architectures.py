"""Register banks and instruction access rules for bare-metal architectures."""

from __future__ import annotations

from dataclasses import dataclass
import re

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, Cs, CsInsn
from qiling.const import QL_ARCH

from sofa.utils.register_access import DecodedRegisterAccess


@dataclass(frozen=True)
class Architecture:
    """Describe the physical register bank and integer calling convention."""

    name: str
    bits: int
    qiling_arch: QL_ARCH
    names: tuple[str, ...]
    widths: tuple[int, ...]
    arguments: tuple[str, ...]
    link: str
    status: str

    def canonical(self, name: str) -> str:
        """Normalize operand aliases without duplicating physical registers."""
        name = name.lower()
        if self.name == "arm64":
            if name in {"xzr", "wzr"}:
                return "zero"
            if name in {"sp", "wsp"}:
                return "sp"
            if name in {"lr", "fp"}:
                return {"lr": "x30", "fp": "x29"}[name]
            if re.fullmatch(r"w\d+", name):
                return "x" + name[1:]
            if re.fullmatch(r"[bhsdqv]\d+", name):
                return "v" + name[1:]
        else:
            integer_aliases = (
                "zero ra sp gp tp t0 t1 t2 s0 s1 a0 a1 a2 a3 a4 a5 a6 a7 "
                "s2 s3 s4 s5 s6 s7 s8 s9 s10 s11 t3 t4 t5 t6"
            ).split()
            float_aliases = (
                "ft0 ft1 ft2 ft3 ft4 ft5 ft6 ft7 fs0 fs1 fa0 fa1 fa2 fa3 fa4 fa5 fa6 fa7 "
                "fs2 fs3 fs4 fs5 fs6 fs7 fs8 fs9 fs10 fs11 ft8 ft9 ft10 ft11"
            ).split()
            if name == "fp":
                return "x8"
            if name in integer_aliases:
                return "x" + str(integer_aliases.index(name))
            if name in float_aliases:
                return "f" + str(float_aliases.index(name))
        return name

    def mask(self, registers: set[str]) -> int:
        """Return a physical-bank mask, excluding constant zero operands."""
        normalized = {self.canonical(name) for name in registers}
        if self.name != "arm64":
            normalized.discard("x0")
        return sum(1 << index for index, name in enumerate(self.names) if name in normalized)


ARM64 = Architecture(
    "arm64", 64, QL_ARCH.ARM64,
    tuple([f"x{i}" for i in range(31)] + ["sp", "pc"] + [f"v{i}" for i in range(32)]),
    (64,) * 33 + (128,) * 32, tuple(f"x{i}" for i in range(8)), "x30", "pstate",
)
RV32 = Architecture(
    "riscv32", 32, QL_ARCH.RISCV,
    tuple([f"x{i}" for i in range(32)] + ["pc"] + [f"f{i}" for i in range(32)]),
    (32,) * 33 + (64,) * 32, tuple(f"x{i}" for i in range(10, 18)), "x1", "fcsr",
)
RV64 = Architecture("riscv64", 64, QL_ARCH.RISCV64, RV32.names, (64,) * 65,
                    RV32.arguments, "x1", "fcsr")
ARCHITECTURES = {arch.name: arch for arch in (ARM64, RV32, RV64)}


def _riscv_access(instruction: CsInsn, disassembler: Cs) -> tuple[set[str], set[str], bool, bool]:
    """Decode integer, compressed, atomic and scalar F/D operand effects."""
    # RISC-V Capstone 5 has operands but no regs_access implementation.
    mnemonic = instruction.mnemonic.lower()
    compressed = mnemonic.startswith("c.")
    op = mnemonic.removeprefix("c.")
    operands = instruction.operands
    registers = [disassembler.reg_name(o.reg) for o in operands if o.type == 1]
    bases = {disassembler.reg_name(o.mem.base) for o in operands if o.type == 3 and o.mem.base}
    reads: set[str] = set(bases)
    writes: set[str] = set()
    conditional = False
    flow = False
    arithmetic = {
        "add", "addi", "addw", "addiw", "sub", "subw", "xor", "xori", "or", "ori", "and", "andi",
        "sll", "slli", "sllw", "slliw", "srl", "srli", "srlw", "srliw", "sra", "srai", "sraw", "sraiw",
        "slt", "slti", "sltu", "sltiu", "mul", "mulh", "mulhsu", "mulhu", "mulw", "div", "divu",
        "divw", "divuw", "rem", "remu", "remw", "remuw", "mv", "li", "lui", "neg", "negw", "not",
        "sext.w", "seqz", "snez", "sltz", "sgtz", "add16sp", "addi16sp", "addi4spn", "auipc",
    }
    loads = {"lb", "lbu", "lh", "lhu", "lw", "lwu", "ld", "flw", "fld", "lwsp", "ldsp", "flwsp", "fldsp"}
    stores = {"sb", "sh", "sw", "sd", "fsw", "fsd", "swsp", "sdsp", "fswsp", "fsdsp"}
    branches = {"beq", "bne", "blt", "bge", "bltu", "bgeu", "beqz", "bnez", "blez", "bgez", "bltz", "bgtz", "bgt", "ble", "bgtu", "bleu"}
    if op in branches:
        reads.update(registers)
        reads.add("pc")
        writes.add("pc")
        flow = conditional = True
    elif op in {"j", "jr", "jal", "jalr", "ret", "call", "tail"}:
        flow = True
        writes.add("pc")
        if op == "ret":
            reads.add("ra")
        elif op in {"jr", "tail"}:
            reads.update(registers)
        elif op in {"jal", "jalr", "call"}:
            if len(operands) > 1 and registers:
                writes.add(registers[0])
                reads.update(registers[1:])
            else:
                writes.add("ra")
                reads.update(registers)
        if op in {"j", "jal", "call", "tail"}:
            reads.add("pc")
    elif op in loads:
        writes.update(registers[:1])
        reads.update(registers[1:])
        if op.endswith("sp"):
            reads.add("sp")
    elif op in stores:
        reads.update(registers)
        if op.endswith("sp"):
            reads.add("sp")
    elif op in arithmetic or re.fullmatch(
        r"(?:f(?:add|sub|mul|div|min|max|sqrt|sgnj|sgnjn|sgnjx|madd|msub|nmadd|nmsub|eq|lt|le|class|mv|abs|neg)\.[sd](?:\.[xw])?|"
        r"fmv\.(?:[xw]\.[sdw]|[sdw]\.[xw])|fcvt\.(?:w|wu|l|lu|s|d)\.(?:w|wu|l|lu|s|d))", op
    ):
        writes.update(registers[:1])
        reads.update(registers[1:])
        if compressed and op in {"add", "addi", "addw", "addiw", "sub", "subw", "xor", "or", "and", "andi", "slli", "srli", "srai"}:
            reads.update(registers[:1])
        if op in {"addi16sp", "add16sp"}:
            reads.add("sp")
            writes.add("sp")
        if op == "addi4spn":
            reads.add("sp")
        if op == "auipc":
            reads.add("pc")
    elif re.fullmatch(r"(?:lr|sc|amo(?:swap|add|xor|and|or|min|max|minu|maxu))\.[wd](?:\.(?:aq|rl|aqrl))?", op):
        writes.update(registers[:1])
        reads.update(registers[1:])
    elif op not in {"nop", "fence", "fence.i"}:
        raise ValueError(f"Unsupported RISC-V instruction in accessed mode: {mnemonic}")
    return reads, writes, flow, conditional


def decode_access(arch: Architecture, disassembler: Cs, code: bytes, address: int) -> DecodedRegisterAccess:
    """Decode one instruction using architecture-specific physical registers."""
    disassembler.detail = True
    instruction = next(disassembler.disasm(code, address, count=1), None)
    if instruction is None:
        raise ValueError(f"Unable to decode instruction at {address:#x}")
    if arch.name != "arm64":
        reads, writes, flow, conditional = _riscv_access(instruction, disassembler)
    else:
        if re.search(r"\b(?:z\d+|p\d+|za)\b", instruction.op_str):
            raise ValueError("ARM SVE/SME instructions are unsupported")
        if instruction.mnemonic in {"svc", "hvc", "smc", "eret", "brk"}:
            raise ValueError(f"Unsupported bare-metal instruction: {instruction.mnemonic}")
        read_ids, write_ids = instruction.regs_access()
        reads = {disassembler.reg_name(i) for i in read_ids}
        writes = {disassembler.reg_name(i) for i in write_ids}
        flow = bool({CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET}.intersection(instruction.groups))
        mnemonic = instruction.mnemonic
        conditional = mnemonic.startswith("b.") or mnemonic in {"cbz", "cbnz", "tbz", "tbnz"}
        if mnemonic == "ret" and not instruction.op_str:
            reads.add("x30")
        if mnemonic in {"bl", "blr"}:
            writes.add("x30")
        if mnemonic in {"adr", "adrp"} or (flow and any(o.type == 2 for o in instruction.operands)):
            reads.add("pc")
        if flow:
            writes.add("pc")
        # Lane insertion preserves and therefore reads the rest of its vector.
        for operand in instruction.operands:
            if operand.type == 1 and operand.access & 2 and getattr(operand, "vector_index", -1) >= 0:
                reads.add(disassembler.reg_name(operand.reg))
    return DecodedRegisterAccess(address, instruction.size, bytes(instruction.bytes).hex(),
                                 instruction.mnemonic, instruction.op_str, arch.mask(reads), arch.mask(writes),
                                 flow, conditional)


def instruction_type(decoded: DecodedRegisterAccess) -> str:
    """Classify common instruction families without ARM-specific mnemonic tables."""
    op = decoded.mnemonic.removeprefix("c.")
    if decoded.changes_control_flow:
        return "CBRANCH" if decoded.conditional_control_flow else "UBRANCH"
    if op.startswith(("ldr", "ldp", "ldur", "ldar", "ldxr", "ldaxr")) or op in {
        "lb", "lbu", "lh", "lhu", "lw", "lwu", "ld", "flw", "fld", "lwsp", "ldsp", "flwsp", "fldsp"
    }:
        return "LOAD"
    if op.startswith(("str", "stp", "stur", "stlr", "stxr", "stlxr")) or op in {
        "sb", "sh", "sw", "sd", "fsw", "fsd", "swsp", "sdsp", "fswsp", "fsdsp"
    }:
        return "STORE"
    if op in {"nop", "hint"}:
        return "NOP"
    if op.startswith(("and", "or", "eor", "xor", "bic", "not")):
        return "LOGICAL"
    if op.startswith(("add", "sub", "mul", "div", "rem", "fadd", "fsub", "fmul", "fdiv")):
        return "ARITHMETIC"
    return "OTHER"
