"""End-to-end fixtures for prebuilt bare-metal ELF execution and wide traces."""

from __future__ import annotations

import csv
import json
from pathlib import Path
import struct
import tempfile
import unittest
from typing import Any

import numpy as np
from capstone import CS_ARCH_ARM64, CS_ARCH_RISCV, CS_MODE_ARM, CS_MODE_RISCV32, CS_MODE_RISCV64, CS_MODE_RISCVC, Cs
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

from sofa.components.armchair_session_runner import ARMChairSessionRunner
from sofa.components.baremetal import BaremetalProfile, initialize_baremetal
from sofa.components.sym_parser import SymParser
from sofa.components.tvla import analyze_tvla_archive, write_tvla_instruction_reports
from sofa.utils.architectures import ARM64, RV32, RV64, decode_access
from sofa.utils.helpers import create_npz_file, process_csv_file
from sofa.utils.wide_traces import pack_masks, unpack_mask


def elf_fixture(path: Path, arch: str, code: bytes, base: int = 0x100000) -> None:
    """Write a minimal static ELF with loadable code, BSS and one exact symbol."""
    bits = 32 if arch == "riscv32" else 64
    machine = 183 if arch == "arm64" else 243
    ident = b"\x7fELF" + bytes([1 if bits == 32 else 2, 1, 1, 0]) + bytes(8)
    # Include a symbol at an odd address to test that only ARM Thumb is normalized.
    strings = b"\0odd_data\0"
    if bits == 64:
        header = ident + struct.pack('<HHIQQQIHHHHHH', 2, machine, 1, base, 64, 0x2000, 0, 64, 56, 1, 64, 4, 3)
        program = struct.pack('<IIQQQQQQ', 1, 5, 0x1000, base, base, len(code), 0x1000, 0x1000)
        symbol = bytes(24) + struct.pack('<IBBHQQ', 1, 0x11, 0, 1, base + 0x301, 1)
        sections = bytes(64) + struct.pack('<IIQQQQIIQQ', 1, 3, 0, 0, 0x2200, len(strings), 0, 0, 1, 0)
        sections += struct.pack('<IIQQQQIIQQ', 9, 2, 0, 0, 0x2300, len(symbol), 1, 1, 8, 24)
    else:
        header = ident + struct.pack('<HHIIIIIHHHHHH', 2, machine, 1, base, 52, 0x2000, 0, 52, 32, 1, 40, 4, 3)
        program = struct.pack('<IIIIIIII', 1, 0x1000, base, base, len(code), 0x1000, 5, 0x1000)
        symbol = bytes(16) + struct.pack('<IIIBBH', 1, base + 0x301, 1, 0x11, 0, 1)
        sections = bytes(40) + struct.pack('<IIIIIIIIII', 1, 3, 0, 0, 0x2200, len(strings), 0, 0, 1, 0)
        sections += struct.pack('<IIIIIIIIII', 9, 2, 0, 0, 0x2300, len(symbol), 1, 1, 4, 16)
    section_names = b'\0.strtab\0.symtab\0.shstrtab\0'
    if bits == 64:
        sections += struct.pack('<IIQQQQIIQQ', 17, 3, 0, 0, 0x2280, len(section_names), 0, 0, 1, 0)
    else:
        sections += struct.pack('<IIIIIIIIII', 17, 3, 0, 0, 0x2280, len(section_names), 0, 0, 1, 0)
    data = bytearray(0x2400)
    data[:len(header)] = header
    data[len(header):len(header) + len(program)] = program
    data[0x1000:0x1000 + len(code)] = code
    data[0x2000:0x2000 + len(sections)] = sections
    data[0x2200:0x2200 + len(strings)] = strings
    data[0x2300:0x2300 + len(symbol)] = symbol
    data[0x2280:0x2280 + len(section_names)] = section_names
    path.write_bytes(data)


def config_fixture(arch: str, base: int = 0x100000) -> dict[str, Any]:
    """Return a direct AES profile with input/output buffers and a ninth argument."""
    return {
        'platform': 'baremetal', 'execution_mode': 'baremetal-direct', 'architecture': arch,
        'target': 'AES', 'key_length': '128', 'plaintext_length': '16', 'use_iv': 'false', 'masked': 'false',
        'memory_mappings': [{'base_address': 0x300000, 'size': 4096, 'perms': 3, 'info': 'workspace'}],
        'trace_start': base, 'trace_end': base + 0x100,
        'direct_call': {'entry': base, 'stack_address': 0x300F00, 'return_address': base + 0x100,
                        'buffers': {'key': {'address': 0x300000, 'size': 16, 'input': 'key'},
                                    'output': {'address': 0x300200, 'size': 16}},
                        'arguments': [{'buffer': 'key'}, {'buffer': 'output'}, 0, 0, 0, 0, 0, 0, 0x1234]},
    }


def routine(arch: str) -> bytes:
    """Return code loading FP/SIMD state and copying the ninth argument to output."""
    if arch == 'arm64':
        encoding, _ = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN).asm(
            'ldr q0, [x0]; mov v31.16b, v0.16b; ldr x8, [sp]; str x8, [x1]; ret')
        return bytes(encoding)
    width = 2 if arch == 'riscv32' else 3
    instructions = [0x00053F87, 0x03FF8FD3, (2 << 15) | (width << 12) | (5 << 7) | 3,
                    (5 << 20) | (11 << 15) | (width << 12) | 0x23]
    return b''.join(struct.pack('<I', i) for i in instructions) + bytes.fromhex('01008280')


class BaremetalTests(unittest.TestCase):
    """Verify actual Qiling execution, capture, archives and failures."""

    def test_architectures_execute_and_capture(self) -> None:
        """Run static ELFs with integer, FP/SIMD and compressed instructions."""
        for name in ('arm64', 'riscv32', 'riscv64'):
            for model in ('accessed', 'all'):
                with self.subTest(architecture=name, model=model), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    elf = root / 'test.elf'
                    elf_fixture(elf, name, routine(name))
                    config = config_fixture(name)
                    symbols = SymParser(str(elf))
                    self.assertEqual(symbols.get_symbol_by_name('odd_data'), 0x100301)
                    profile = BaremetalProfile(config)
                    traces: list[list[Any]] = []
                    ql = initialize_baremetal(str(elf), config, profile, symbols, traces, model)
                    self.assertEqual(bytes(ql.mem.read(0x100300, 16)), bytes(16))
                    profile.init_uart(ql, 'hex')
                    key = struct.pack('<dd', 1.5, 2.0).hex()
                    profile.hook_cmds(ql, symbols, [key, bytes(16).hex()])
                    ql.run(begin=ql.sofa_entry, end=0x100104, count=100)
                    ql.sofa_access_recorder.validate_complete()
                    self.assertTrue(ql.sofa_returned)
                    self.assertEqual(ql.mem.read_ptr(0x300200), 0x1234)
                    self.assertEqual(len(traces), 5 if name == 'arm64' else 6)
                    register = 'v31' if name == 'arm64' else 'f31'
                    self.assertNotEqual(ql.arch.regs.read(register), 0)
                    csv_path = root / 'traces_1.csv'
                    with csv_path.open('w', newline='') as destination:
                        writer = csv.writer(destination)
                        writer.writerow(ql.sofa_trace_header)
                        writer.writerows(traces)
                    for leakage in ('ID', 'HW', 'HD'):
                        result = process_csv_file(csv_path, None, leakage, model)
                        self.assertEqual(result['read_components'].shape[-1], 65)
                        self.assertEqual(result['write_masks'].shape[-1], 2)
                        self.assertTrue(np.isfinite(result['combined']).all())
                    create_npz_file(root / 'power.npz', root, 'HW', register_model=model)
                    with np.load(root / 'power.npz', allow_pickle=False) as archive:
                        self.assertEqual(archive['pcs'].dtype, np.uint64)
                        self.assertEqual(str(archive['architecture']), name)
                        self.assertIn(register, archive['register_names'])

    def test_invalid_profiles_and_incomplete_windows(self) -> None:
        """Reject wrong architectures, overlap, unmapped memory and unfinished capture."""
        with tempfile.TemporaryDirectory() as directory:
            elf = Path(directory) / 'test.elf'
            elf_fixture(elf, 'arm64', routine('arm64'))
            symbols = SymParser(str(elf))
            for scenario in ('architecture', 'overlap', 'stack', 'buffer', 'mode', 'capture'):
                with self.subTest(scenario=scenario):
                    config = config_fixture('arm64')
                    if scenario == 'architecture':
                        config['architecture'] = 'riscv64'
                    elif scenario == 'overlap':
                        config['memory_mappings'][0]['base_address'] = 0x100000
                    elif scenario == 'stack':
                        config['direct_call']['stack_address'] = 0x500000
                    elif scenario == 'buffer':
                        config['direct_call']['buffers']['key']['address'] = 0x500000
                    elif scenario == 'mode':
                        config['execution_mode'] = 'direct'
                    else:
                        config['trace_end'] = 0x100200
                    profile = BaremetalProfile(config)
                    with self.assertRaises((ValueError, RuntimeError)):
                        ql = initialize_baremetal(str(elf), config, profile, symbols, [], 'accessed')
                        profile.hook_cmds(ql, symbols, ['00' * 16, '00' * 16])
                        ql.run(begin=ql.sofa_entry, end=0x100104, count=100)

    def test_conditional_pc_writes_and_repeated_windows(self) -> None:
        """Suppress untaken PC writes and preserve repeated capture window IDs."""
        assembler = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        for taken in (False, True):
            with self.subTest(taken=taken), tempfile.TemporaryDirectory() as directory:
                code, _ = assembler.asm('cbz x2, #0x100008; add x3, x3, #1; nop; ret', 0x100000)
                elf = Path(directory) / 'test.elf'
                elf_fixture(elf, 'arm64', bytes(code))
                config = config_fixture('arm64')
                config['direct_call']['arguments'][2] = 0 if taken else 1
                profile, symbols = BaremetalProfile(config), SymParser(str(elf))
                traces: list[list[Any]] = []
                ql = initialize_baremetal(str(elf), config, profile, symbols, traces, 'accessed')
                profile.hook_cmds(ql, symbols, ['00' * 16, '00' * 16])
                ql.run(begin=ql.sofa_entry, end=0x100104, count=100)
                self.assertEqual(bool(int(traces[0][9], 16) & ARM64.mask({'pc'})), taken)
        with tempfile.TemporaryDirectory() as directory:
            code, _ = assembler.asm('mov x9, #2; subs x9, x9, #1; b.ne #0x100004; ret', 0x100000)
            elf = Path(directory) / 'test.elf'
            elf_fixture(elf, 'arm64', bytes(code))
            config = config_fixture('arm64')
            config['trace_start'] = 0x100004
            profile, symbols = BaremetalProfile(config), SymParser(str(elf))
            traces = []
            ql = initialize_baremetal(str(elf), config, profile, symbols, traces, 'accessed')
            profile.hook_cmds(ql, symbols, ['00' * 16, '00' * 16])
            ql.run(begin=ql.sofa_entry, end=0x100104, count=100)
            self.assertEqual([row[7] for row in traces], [0, 0, 1, 1, 1])

    def test_input_bounds_and_instruction_limit(self) -> None:
        """Reject unavailable inputs, overflow and routines that fail to return."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf = root / 'test.elf'
            # A valid, supported infinite jump is bounded by the public runner.
            elf_fixture(elf, 'arm64', bytes.fromhex('00000014'))
            config = config_fixture('arm64')
            config['instruction_limit'] = 4
            path = root / 'profile.json'
            path.write_text(json.dumps(config))
            runner = ARMChairSessionRunner(str(elf), 'hex', BaremetalProfile(config), [], str(path))
            runner.output_dir = str(root)
            with self.assertLogs(level='ERROR'), self.assertRaisesRegex(RuntimeError, 'instruction_limit'):
                runner.process_row(['00' * 16, '00' * 16], [0])
            profile, symbols = BaremetalProfile(config), SymParser(str(elf))
            ql = initialize_baremetal(str(elf), config, profile, symbols, [], 'accessed')
            with self.assertRaisesRegex(ValueError, 'exceeds buffer'):
                profile.hook_cmds(ql, symbols, ['00' * 17, '00' * 16])
            config['direct_call']['buffers']['key']['input'] = 'nonce'
            with self.assertRaisesRegex(ValueError, 'Unavailable input source'):
                profile.hook_cmds(ql, symbols, ['00' * 16, '00' * 16])

    def test_runner_and_tvla_pipeline(self) -> None:
        """Exercise the public runner through packed-mask TVLA and CSV reports."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf = root / 'test.elf'
            elf_fixture(elf, 'arm64', routine('arm64'))
            config = config_fixture('arm64')
            path = root / 'profile.json'
            path.write_text(json.dumps(config))
            runner = ARMChairSessionRunner(str(elf), 'hex', BaremetalProfile(config), [], str(path))
            runner.output_dir = str(root)
            for index in range(4):
                runner.process_row(['ff' * 16 if index % 2 else '00' * 16, '00' * 16], [index])
            # A manifest is not required by the recorder; archive labels normally come from TVLA input generation.
            create_npz_file(root / 'power.npz', root, 'HW')
            with np.load(root / 'power.npz') as archive:
                values = dict(archive)
            values['group_labels'] = np.asarray(['fixed', 'random', 'fixed', 'random'])
            np.savez_compressed(root / 'power.npz', **values)
            results = analyze_tvla_archive(root / 'power.npz')
            write_tvla_instruction_reports(results)
            with np.load(results) as archive:
                self.assertEqual(archive['read_masks'].shape, (5, 2))
                self.assertEqual(str(archive['architecture']), 'arm64')
            summary = (root / 'tvla_instruction_occurrences.csv').read_text()
            self.assertIn('v31', summary)


class ArchitectureAccessTests(unittest.TestCase):
    """Verify physical aliases and backend-independent instruction effects."""

    def test_aliases_and_wide_masks(self) -> None:
        """Normalize integer and FP aliases without duplicate register banks."""
        self.assertEqual(ARM64.canonical('w30'), 'x30')
        self.assertEqual(ARM64.canonical('q31'), 'v31')
        self.assertEqual(RV32.canonical('fa0'), 'f10')
        self.assertEqual(RV64.canonical('fp'), 'x8')
        mask = ARM64.mask({'q31', 'w0', 'xzr'})
        self.assertEqual(unpack_mask(pack_masks([mask], 2)[0]), (1 << 64) | 1)
        self.assertEqual(RV32.mask({'zero'}), 0)

    def test_riscv_metadata_and_rejection(self) -> None:
        """Decode F/D, compressed arithmetic and branches without regs_access()."""
        for arch, mode in ((RV32, CS_MODE_RISCV32), (RV64, CS_MODE_RISCV64)):
            decoder = Cs(CS_ARCH_RISCV, mode | CS_MODE_RISCVC)
            add = decode_access(arch, decoder, bytes.fromhex('3385c500'), 0x1000)
            self.assertEqual(add.read_mask, arch.mask({'a1', 'a2'}))
            self.assertEqual(add.write_mask, arch.mask({'a0'}))
            fp = decode_access(arch, decoder, struct.pack('<I', 0x03FF8FD3), 0x1004)
            self.assertEqual(fp.read_mask, 1 << 64)
            self.assertEqual(fp.write_mask, 1 << 64)
            compressed = decode_access(arch, decoder, bytes.fromhex('0505'), 0x1008)
            self.assertEqual(compressed.read_mask, arch.mask({'a0'}))
            self.assertEqual(compressed.write_mask, arch.mask({'a0'}))
            branch = decode_access(arch, decoder, bytes.fromhex('63000500'), 0x100A)
            self.assertTrue(branch.conditional_control_flow)
            self.assertTrue(branch.write_mask & arch.mask({'pc'}))
            # amoadd.w a0, a1, (a2): destination write plus source/base reads.
            atomic = decode_access(arch, decoder, struct.pack('<I', (11 << 20) | (12 << 15) | (2 << 12) | (10 << 7) | 0x2F), 0x100E)
            self.assertEqual(atomic.read_mask, arch.mask({'a1', 'a2'}))
            self.assertEqual(atomic.write_mask, arch.mask({'a0'}))
            with self.assertRaisesRegex(ValueError, 'Unsupported RISC-V'):
                decode_access(arch, decoder, bytes.fromhex('73000000'), 0x100E)

    def test_arm64_register_effects(self) -> None:
        """Capture link registers, zero aliases and conditional branch PCs."""
        decoder = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        assembler = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        for text, reads, writes in (
            ('add w0, w1, w2', {'x1', 'x2'}, {'x0'}),
            ('ret', {'x30'}, {'pc'}),
            ('bl #0x1010', {'pc'}, {'pc', 'x30'}),
            ('mov v31.16b, v0.16b', {'v0'}, {'v31'}),
        ):
            with self.subTest(instruction=text):
                code, _ = assembler.asm(text, 0x1000)
                decoded = decode_access(ARM64, decoder, bytes(code), 0x1000)
                self.assertEqual(decoded.read_mask, ARM64.mask(reads))
                self.assertEqual(decoded.write_mask, ARM64.mask(writes))


if __name__ == '__main__':
    unittest.main()
