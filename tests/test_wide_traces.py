"""Exact arithmetic and archive compatibility tests for wide register banks."""

from __future__ import annotations

import csv
from pathlib import Path
import tempfile
import unittest

import numpy as np

from sofa.components.tvla import analyze_tvla_archive, write_tvla_instruction_reports
from sofa.utils.architectures import ARM64, RV64, Architecture
from sofa.utils.helpers import create_npz_file, process_csv_file


def write_trace(path: Path, arch: Architecture = ARM64, rows: int = 1,
                pc: int = (1 << 60) + 4, model: str = 'accessed') -> None:
    """Write a known wide transition in register 64 with a high exact PC."""
    names = arch.names
    header = ['PC', 'Machine', 'Ins', 'Type', 'Operands', 'trace_schema', 'architecture',
              'window_id', 'read_mask', 'write_mask', 'status_pre', *names]
    if model == 'accessed':
        header.extend(f'post_{name}' for name in names)
    old = (1 << 127) | 3 if arch == ARM64 else (1 << 63) | 3
    new = (1 << 126) | 1 if arch == ARM64 else (1 << 62) | 1
    with path.open('w', newline='') as source:
        writer = csv.writer(source)
        writer.writerow(header)
        for index in range(rows):
            before = [0] * 64 + [old if index % 2 == 0 else new]
            after = [0] * 64 + [new]
            row = [hex(pc + index * 4), '00', 'fixture', 'OTHER', '', f'sofa-{model}-v2', arch.name,
                   0, hex(1 << 64), hex(1 << 64), '0x0', *(hex(value) for value in before)]
            if model == 'accessed':
                row.extend(hex(value) for value in after)
            writer.writerow(row)


class WideTraceTests(unittest.TestCase):
    """Check leakage formulas without losing wide values or high mask bits."""

    def test_wide_formulas_and_selection(self) -> None:
        """Count all 128 SIMD bits and preserve bit 64 of masks."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'traces_1.csv'
            write_trace(path)
            for leakage, expected in [('HW', 5), ('HD', 3), ('ID', float((1 << 127) + (1 << 126) + 4))]:
                with self.subTest(leakage=leakage):
                    result = process_csv_file(path, ['q31'], leakage)
                    self.assertEqual(result['combined'].tolist(), [expected])
                    self.assertEqual(result['write_masks'].tolist(), [[0, 1]])
                    self.assertEqual(result['pcs'].tolist(), [(1 << 60) + 4])
            self.assertEqual(process_csv_file(path, ['x0'], 'HW')['combined'].tolist(), [0])
            with self.assertRaisesRegex(ValueError, 'Unsupported arm64 registers'):
                process_csv_file(path, ['r0'], 'HW')

    def test_all_mode_hd_and_ragged_padding(self) -> None:
        """Retain historical adjacent-state HD with lossless integer diagnostics."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_trace(root / 'traces_1.csv', rows=2, model='all')
            write_trace(root / 'traces_2.csv', rows=3, model='all')
            create_npz_file(root / 'power.npz', root, 'HD', cols=['v31'], register_model='all')
            with np.load(root / 'power.npz', allow_pickle=False) as archive:
                np.testing.assert_array_equal(archive['lengths'], [1, 2])
                np.testing.assert_array_equal(archive['arr_0'][1], [3, 3])
                self.assertTrue(np.isnan(archive['arr_0'][0, 1]))
                self.assertEqual(archive['instruction_ids'][0, 1], -1)
                self.assertEqual(archive['pcs'][0, 1], 0)
                self.assertEqual(int(archive['pcs'][0, 0]), (1 << 60) + 4)
                self.assertEqual(archive['read_components'].shape, (2, 2, 65))
                self.assertEqual(archive['selected_registers'].tolist(), ['v31'])

    def test_mixed_architectures_are_rejected(self) -> None:
        """Never combine incompatible register banks in a power archive."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_trace(root / 'traces_1.csv')
            write_trace(root / 'traces_2.csv', arch=RV64)
            with self.assertRaisesRegex(ValueError, 'different architectures'):
                create_npz_file(root / 'power.npz', root, 'HW')

    def test_tvla_preserves_high_pc_and_validates_packed_masks(self) -> None:
        """Localize packed masks and report the sample rather than its word offset."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(4):
                write_trace(root / f'traces_{index + 1}.csv', rows=2)
            power = root / 'power.npz'
            create_npz_file(power, root, 'HW')
            with np.load(power) as archive:
                values = dict(archive)
            values['group_labels'] = np.asarray(['fixed', 'random', 'fixed', 'random'])
            # Make one sample separate perfectly while retaining aligned instruction identities.
            values['arr_0'][1::2, 0] += 1
            np.savez_compressed(power, **values)
            results = analyze_tvla_archive(power)
            write_tvla_instruction_reports(results)
            self.assertIn(hex((1 << 60) + 4), (root / 'tvla_instruction_occurrences.csv').read_text())
            self.assertIn('v31', (root / 'tvla_instruction_occurrences.csv').read_text())
            values['read_masks'][1, 1, 1] = 0
            np.savez_compressed(power, **values)
            with self.assertRaisesRegex(ValueError, 'read-mask alignment diverges at sample 1'):
                analyze_tvla_archive(power)
            values['read_masks'][1, 1, 1] = 2
            np.savez_compressed(power, **values)
            with self.assertRaisesRegex(ValueError, 'exceeds register bank'):
                analyze_tvla_archive(power)


if __name__ == '__main__':
    unittest.main()
