"""Minimal RP2350 support required by the hacking-challenge firmware."""

from __future__ import annotations

import ctypes

from elftools.elf.elffile import ELFFile
from qiling import Qiling
from qiling.hw.peripheral import QlPeripheral


# RP2350 address ranges from the Raspberry Pi Pico SDK address map.  Peripheral
# ranges are MMIO-backed so firmware can access registers that Qiling does not
# model yet without accidentally treating them as ordinary RAM.
RP2350 = {
    "ROM": {"base": 0x00000000, "size": 0x00010000, "type": "memory"},
    "XIP": {"base": 0x10000000, "size": 0x04000000, "type": "memory"},
    "SRAM": {"base": 0x20000000, "size": 0x00082000, "type": "memory"},
    "PERIPHERALS": {"base": 0x40000000, "size": 0x00200000, "type": "mmio"},
    "AHB_PERIPHERALS": {"base": 0x50000000, "size": 0x00800000, "type": "mmio"},
    "SIO": {"base": 0xD0000000, "size": 0x00040000, "type": "mmio"},
    "PPB": {"base": 0xE0000000, "size": 0x00100000, "type": "mmio"},
}

SHA256_BASE = 0x400F8000


class Rp2350Sha256(QlPeripheral):
    """Small functional model of the RP2350 SHA-256 register block.

    The challenge uses this peripheral as a deterministic random-state mixer.
    Modelling its status flags and digest registers avoids an infinite poll in
    ``gen_rand_sha_nonpres`` while preserving the firmware's instruction flow.
    """

    class Type(ctypes.Structure):
        _fields_ = [
            ("csr", ctypes.c_uint32),
            ("wdata", ctypes.c_uint32),
            ("sum", ctypes.c_uint32 * 8),
        ]

    CSR = 0x00
    WDATA = 0x04
    SUM0 = 0x08
    CSR_WDATA_READY = 0x02
    CSR_SUM_VALID = 0x04
    CSR_WRITABLE = 0x1311
    INITIAL_STATE = (
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    )
    ROUND_CONSTANTS = (
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    )

    def __init__(self, ql: Qiling, label: str = "sha256") -> None:
        super().__init__(ql, label)
        self._message = bytearray()
        self._state = list(self.INITIAL_STATE)
        self.instance.csr = 0x1206
        self._publish_state()

    @staticmethod
    def _rotate_right(value: int, amount: int) -> int:
        return ((value >> amount) | (value << (32 - amount))) & 0xFFFFFFFF

    def _publish_state(self) -> None:
        for index, word in enumerate(self._state):
            self.instance.sum[index] = word

    def _compress(self, block: bytes) -> None:
        schedule = [
            int.from_bytes(block[index : index + 4], "big")
            for index in range(0, 64, 4)
        ]
        for index in range(16, 64):
            word15 = schedule[index - 15]
            word2 = schedule[index - 2]
            sigma0 = (
                self._rotate_right(word15, 7)
                ^ self._rotate_right(word15, 18)
                ^ (word15 >> 3)
            )
            sigma1 = (
                self._rotate_right(word2, 17)
                ^ self._rotate_right(word2, 19)
                ^ (word2 >> 10)
            )
            schedule.append(
                (schedule[index - 16] + sigma0 + schedule[index - 7] + sigma1)
                & 0xFFFFFFFF
            )

        a, b, c, d, e, f, g, h = self._state
        for constant, word in zip(self.ROUND_CONSTANTS, schedule):
            sum1 = (
                self._rotate_right(e, 6)
                ^ self._rotate_right(e, 11)
                ^ self._rotate_right(e, 25)
            )
            choose = (e & f) ^ ((~e) & g)
            temp1 = (h + sum1 + choose + constant + word) & 0xFFFFFFFF
            sum0 = (
                self._rotate_right(a, 2)
                ^ self._rotate_right(a, 13)
                ^ self._rotate_right(a, 22)
            )
            majority = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (sum0 + majority) & 0xFFFFFFFF
            h, g, f, e, d, c, b, a = (
                g, f, e, (d + temp1) & 0xFFFFFFFF,
                c, b, a, (temp1 + temp2) & 0xFFFFFFFF,
            )

        self._state = [
            (old + new) & 0xFFFFFFFF
            for old, new in zip(self._state, (a, b, c, d, e, f, g, h))
        ]
        self._publish_state()

    def read(self, offset: int, size: int) -> int:
        if offset == self.CSR:
            return int(self.instance.csr)
        return self.raw_read(offset, size)

    def write(self, offset: int, size: int, value: int) -> None:
        if offset == self.CSR:
            self.instance.csr = (
                (value & self.CSR_WRITABLE & ~1)
                | self.CSR_WDATA_READY
                | self.CSR_SUM_VALID
            )
            if value & 1:
                self._message.clear()
                self._state = list(self.INITIAL_STATE)
                self._publish_state()
            return

        if offset == self.WDATA:
            self.instance.csr &= ~self.CSR_SUM_VALID
            byteorder = "big" if self.instance.csr & 0x1000 else "little"
            self._message.extend(value.to_bytes(size, byteorder=byteorder))
            if len(self._message) == 64:
                self._compress(bytes(self._message))
                self._message.clear()
                self.instance.csr |= self.CSR_SUM_VALID
            return

        self.raw_write(offset, size, value)


def initialize_rp2350(ql: Qiling, elf_path: str) -> None:
    """Finish loading an RP2350 ELF and install the required SHA peripheral."""

    # Qiling's generic MCU loader writes PT_LOAD data to p_paddr.  Pico SDK
    # flash binaries intentionally give initialized RAM segments a flash load
    # address and a different runtime address, normally copied by reset code.
    with open(elf_path, "rb") as elf_file:
        elf = ELFFile(elf_file)
        for segment in elf.iter_segments(type="PT_LOAD"):
            if segment["p_filesz"] and segment["p_vaddr"] != segment["p_paddr"]:
                ql.mem.write(segment["p_vaddr"], segment.data())

    # On hardware, the boot ROM transfers control using the vector table in
    # XIP flash.  Qiling initializes Cortex-M registers from address zero, so
    # mirror the table there and refresh the initial core state.
    ql.mem.write(0, bytes(ql.mem.read(0x10000000, 0x110)))
    ql.arch.regs.msp = ql.mem.read_ptr(0)
    ql.arch.regs.pc = ql.mem.read_ptr(4)
    ql.loader.entry_point = ql.arch.regs.pc

    sha = Rp2350Sha256(ql)
    ql.hw.entity[sha.label] = sha
    ql.hw.region[sha.label] = [
        (SHA256_BASE + lower, SHA256_BASE + upper)
        for lower, upper in sha.region
    ]
