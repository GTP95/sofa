"""Tests for Capstone-backed ARM register access decoding."""

import unittest

from capstone import CS_ARCH_ARM, CS_MODE_MCLASS, CS_MODE_THUMB, Cs

from sofa.utils.register_access import (
    REGISTER_NAMES,
    canonical_register_name,
    decode_register_access,
)


class RegisterAccessDecodeTests(unittest.TestCase):
    """Check access metadata and Sofa's Capstone 5.0.9 corrections."""

    def setUp(self) -> None:
        """Create a detailed Thumb/M-class disassembler."""
        self.disassembler = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_MCLASS)

    @staticmethod
    def _names(mask: int) -> set[str]:
        """Convert a register mask to its canonical names."""
        return {
            name for index, name in enumerate(REGISTER_NAMES) if mask & (1 << index)
        }

    def assert_access(
        self,
        machine: str,
        reads: set[str],
        writes: set[str],
    ) -> None:
        """Assert decoded read and write sets for one instruction."""
        decoded = decode_register_access(
            self.disassembler, bytes.fromhex(machine), 0x1000
        )
        self.assertEqual(self._names(decoded.read_mask), reads)
        self.assertEqual(self._names(decoded.write_mask), writes)

    def test_data_processing_and_memory_accesses(self) -> None:
        """Retain explicit operands, writeback, and stack accesses."""
        cases = [
            ("81ea0200", {"r1", "r2"}, {"r0"}),
            ("4840", {"r0", "r1"}, {"r0"}),
            ("8858", {"r1", "r2"}, {"r0"}),
            ("51f8040b", {"r1"}, {"r0", "r1"}),
            ("41f8040f", {"r0", "r1"}, {"r1"}),
            ("10b5", {"sp", "r4", "lr"}, {"sp"}),
            ("06c8", {"r0"}, {"r0", "r1", "r2"}),
            ("06c3", {"r1", "r2", "r3"}, {"r3"}),
            ("10bd", {"sp"}, {"sp", "r4", "pc"}),
        ]
        for machine, reads, writes in cases:
            with self.subTest(machine=machine):
                self.assert_access(machine, reads, writes)

    def test_control_flow_corrections(self) -> None:
        """Add PC accesses absent from Capstone's ARM metadata."""
        cases = [
            ("0ee0", {"pc"}, {"pc"}),
            ("0ed0", {"pc"}, {"pc"}),
            ("10b1", {"r0", "pc"}, {"pc"}),
            ("01a0", {"pc"}, {"r0"}),
            ("d0e801f0", {"r0", "r1"}, {"pc"}),
            ("dfe811f0", {"pc", "r1"}, {"pc"}),
            ("00f00ef8", {"pc"}, {"lr", "pc"}),
            ("7047", {"lr"}, {"pc"}),
            ("00bf", set(), set()),
        ]
        for machine, reads, writes in cases:
            with self.subTest(machine=machine):
                self.assert_access(machine, reads, writes)

        unconditional = decode_register_access(
            self.disassembler, bytes.fromhex("0ee0"), 0x1000
        )
        conditional = decode_register_access(
            self.disassembler, bytes.fromhex("0ed0"), 0x1000
        )
        compare_and_branch = decode_register_access(
            self.disassembler, bytes.fromhex("10b1"), 0x1000
        )
        self.assertFalse(unconditional.conditional_control_flow)
        self.assertTrue(conditional.conditional_control_flow)
        self.assertTrue(compare_and_branch.conditional_control_flow)

    def test_aliases_are_canonicalized(self) -> None:
        """Map ARM ABI aliases to the corresponding numbered registers."""
        self.assertEqual(canonical_register_name("sb"), "r9")
        self.assertEqual(canonical_register_name("sl"), "r10")
        self.assertEqual(canonical_register_name("fp"), "r11")
        self.assertEqual(canonical_register_name("ip"), "r12")


if __name__ == "__main__":
    unittest.main()
