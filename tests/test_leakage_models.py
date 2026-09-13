"""Tests for instruction-accessed and historical all-register models."""

import csv
import tempfile
import unittest
from pathlib import Path

import numpy as np

from sofa.utils.helpers import create_npz_file, process_csv_file
from sofa.utils.register_access import ACCESSED_TRACE_HEADER, REGISTER_NAMES


def _accessed_row(
    pre: dict[str, int],
    post: dict[str, int],
    read_mask: int,
    write_mask: int,
    pc: int = 0x1000,
) -> list[object]:
    """Build one rich CSV row for leakage arithmetic tests."""
    pre_values = [pre.get(register, 0) for register in REGISTER_NAMES]
    post_values = [post.get(register, pre.get(register, 0)) for register in REGISTER_NAMES]
    return [
        hex(pc), "00bf", "nop", "NOP", "", "sofa-accessed-v1", 0,
        hex(read_mask), hex(write_mask), "0x0",
        *(hex(value) for value in pre_values),
        *(hex(value) for value in post_values),
    ]


class LeakageModelTests(unittest.TestCase):
    """Verify formulas, diagnostics, selection, and archive padding."""

    def _write_accessed_csv(self, path: Path, rows: list[list[object]]) -> None:
        """Write an accessed-register execution trace."""
        with path.open("w", newline="", encoding="utf-8") as trace_file:
            writer = csv.writer(trace_file)
            writer.writerow(ACCESSED_TRACE_HEADER)
            writer.writerows(rows)

    def test_accessed_formulas_and_components(self) -> None:
        """Count reads and writes separately for HW/ID and writes for HD."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "traces_1.csv"
            row = _accessed_row(
                {"r0": 0x0F, "r1": 0x03},
                {"r0": 0xF0, "r1": 0x03},
                read_mask=(1 << 0) | (1 << 1),
                write_mask=1 << 0,
            )
            self._write_accessed_csv(path, [row])
            expected = {"HW": 10, "ID": 0x102, "HD": 8}
            for model, value in expected.items():
                with self.subTest(model=model):
                    result = process_csv_file(path, REGISTER_NAMES, model, "accessed")
                    self.assertEqual(result["combined"].tolist(), [value])
                    np.testing.assert_array_equal(
                        result["combined"],
                        np.sum(
                            result["read_components"] + result["write_components"],
                            axis=1,
                        ),
                    )

    def test_selected_registers_intersect_access_masks(self) -> None:
        """Exclude accessed registers omitted by the API selection."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "traces_1.csv"
            self._write_accessed_csv(
                path,
                [_accessed_row({"r0": 3, "r1": 7}, {}, 3, 0)],
            )
            result = process_csv_file(path, ["r1"], "ID", "accessed")
            self.assertEqual(result["combined"].tolist(), [7])

    def test_npz_pads_ragged_diagnostics_without_object_arrays(self) -> None:
        """Pad every numeric archive array consistently and retain metadata."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = _accessed_row({}, {}, 0, 0)
            self._write_accessed_csv(root / "traces_1.csv", [row])
            self._write_accessed_csv(root / "traces_2.csv", [row, row])
            output = root / "power.npz"
            create_npz_file(output, root, "HW", num_cores=1)
            with np.load(output, allow_pickle=False) as archive:
                self.assertEqual(archive["arr_0"].shape, (2, 2))
                self.assertEqual(archive["read_components"].shape, (2, 2, 16))
                np.testing.assert_array_equal(archive["lengths"], [1, 2])
                self.assertTrue(np.isnan(archive["arr_0"][0, 1]))
                self.assertEqual(archive["register_model"].item(), "accessed")
                self.assertEqual(archive["capstone_version"].item(), "5.0.9")


if __name__ == "__main__":
    unittest.main()
