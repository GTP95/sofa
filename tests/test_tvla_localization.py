"""Tests for instruction metadata, leakage localization, and TVLA reports."""

import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
from bokeh.models import DataTable, HoverTool
from bokeh.plotting import save

from sofa.components.tvla import (
    INSTRUCTION_FIELDS,
    analyze_tvla_archive,
    compute_welch_t_scores,
    show_tvla_results,
    write_tvla_instruction_reports,
)
from sofa.utils.helpers import create_npz_file
from sofa.utils.register_access import ACCESSED_TRACE_HEADER, REGISTER_NAMES


class InstructionArchiveTests(unittest.TestCase):
    """Verify aligned descriptions and backward-compatible archive analysis."""

    def setUp(self) -> None:
        """Create an isolated directory and aligned two-group power fixture."""
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.values = {
            "arr_0": np.asarray([[1, 2], [1, 2], [3, 4], [3, 4]], dtype=float),
            "lengths": np.full(4, 2),
            "pcs": np.tile([0x1000, 0x1002], (4, 1)),
            "window_ids": np.tile([0, 1], (4, 1)),
            "trace_filenames": np.asarray([f"traces_{index}.csv" for index in range(4)]),
            "group_labels": np.asarray(["fixed", "fixed", "random", "random"]),
            "register_model": np.asarray("accessed"),
            "leakage_model": np.asarray("HD"),
            "read_masks": np.tile([1, 2], (4, 1)),
            "write_masks": np.tile([2, 4], (4, 1)),
            "register_names": np.asarray(REGISTER_NAMES),
            "instruction_ids": np.tile([0, 1], (4, 1)).astype(float),
            "instruction_machines": np.asarray(["0001", "0020"]),
            "instruction_mnemonics": np.asarray(["movs", "movs"]),
            "instruction_operands": np.asarray(["r1, #1", "r2, #0"]),
        }

    def _analyze(self) -> Path:
        """Write the current fixture and analyze it using normal validation."""
        power = self.root / "power.npz"
        np.savez_compressed(power, **self.values)
        return analyze_tvla_archive(power, tested_variable="plaintext", effective_seed=123)

    def test_reference_metadata_and_scores_are_preserved(self) -> None:
        """Retain reference descriptions and masks without changing scores."""
        result = self._analyze()
        with np.load(result, allow_pickle=False) as archive:
            for key in INSTRUCTION_FIELDS:
                np.testing.assert_array_equal(archive[key], self.values[key])
            for key in ("read_masks", "write_masks"):
                np.testing.assert_array_equal(archive[key], self.values[key][0])
            np.testing.assert_array_equal(
                archive["t_scores"],
                compute_welch_t_scores(self.values["arr_0"], self.values["group_labels"]),
            )
            self.assertEqual(int(archive["effective_seed"]), 123)

    def test_instruction_identity_divergence_with_matching_pc(self) -> None:
        """Reject different instruction descriptions even when addresses match."""
        self.values["instruction_ids"][2, 1] = 0
        with self.assertRaisesRegex(ValueError, "instruction-identity.*sample 1.*traces_0.csv.*traces_2.csv"):
            self._analyze()

    def test_equivalent_table_entries_do_not_diverge(self) -> None:
        """Compare descriptions rather than arbitrary instruction-ID numbers."""
        for key in INSTRUCTION_FIELDS:
            self.values[key] = np.concatenate([self.values[key], self.values[key][:1]])
        self.values["instruction_ids"][1, 0] = 2
        self._analyze()

    def test_legacy_archive_produces_pc_only_reports(self) -> None:
        """Analyze older archives without instruction tables or access masks."""
        for key in ("instruction_ids", *INSTRUCTION_FIELDS, "read_masks", "write_masks"):
            del self.values[key]
        self.values["register_model"] = np.asarray("all")
        self.values["selected_registers"] = np.asarray(["r1"])
        result = self._analyze()
        occurrences, _summary = write_tvla_instruction_reports(result)
        with occurrences.open(newline="") as source:
            rows = list(csv.DictReader(source))
        self.assertEqual(rows[0]["pc"], "0x1000")
        self.assertEqual(rows[0]["mnemonic"], "")
        self.assertEqual(rows[0]["write_registers"], "r1")
        self.assertEqual(rows[0]["read_registers"], "")

    def test_partial_metadata_is_rejected(self) -> None:
        """Reject incomplete tables instead of presenting misleading descriptions."""
        del self.values["instruction_operands"]
        with self.assertRaisesRegex(ValueError, "incomplete instruction metadata"):
            self._analyze()

    def test_invalid_instruction_ids_are_rejected(self) -> None:
        """Reject fractional, nonfinite, negative, and out-of-range identifiers."""
        for invalid in (0.5, np.nan, np.inf, -1, 2):
            with self.subTest(invalid=invalid):
                self.values["instruction_ids"][0, 0] = invalid
                with self.assertRaisesRegex(ValueError, "instruction IDs must be finite integers"):
                    self._analyze()

    def test_invalid_metadata_shapes_and_types_are_rejected(self) -> None:
        """Reject malformed tables and arrays before indexing their entries."""
        cases = [
            ("instruction_ids", np.zeros((4, 1)), "not aligned"),
            ("instruction_ids", np.asarray(["0", "1"]), "not aligned"),
            ("instruction_machines", np.asarray([["00", "01"]]), "Unicode arrays"),
            ("instruction_machines", np.asarray([0, 1]), "Unicode arrays"),
            ("instruction_operands", np.asarray(["r0"]), "table lengths differ"),
        ]
        for key, value, message in cases:
            with self.subTest(key=key, value=value):
                original = self.values[key]
                self.values[key] = value
                with self.assertRaisesRegex(ValueError, message):
                    self._analyze()
                self.values[key] = original

    def test_instruction_padding_is_ignored(self) -> None:
        """Ignore padded identifiers outside the declared sample length."""
        self.values["instruction_ids"] = np.column_stack([
            self.values["instruction_ids"], np.full(4, np.nan),
        ])
        self._analyze()

    def test_existing_alignment_failures_remain_errors(self) -> None:
        """Preserve PC, window, and register-access alignment checks."""
        for key, message in (
            ("pcs", "PC"), ("window_ids", "window-ID"),
            ("read_masks", "read-mask"), ("write_masks", "write-mask"),
        ):
            with self.subTest(key=key):
                original = self.values[key].copy()
                self.values[key][1, 0] += 1
                with self.assertRaisesRegex(ValueError, f"{message} alignment diverges"):
                    self._analyze()
                self.values[key] = original

    def test_invalid_access_masks_are_rejected(self) -> None:
        """Reject invalid masks before exposing register names in reports."""
        self.values["read_masks"] = self.values["read_masks"].astype(float)
        self.values["read_masks"][0, 0] = np.nan
        with self.assertRaisesRegex(ValueError, "16-bit register masks"):
            self._analyze()


class InstructionReportTests(unittest.TestCase):
    """Verify occurrence filtering, summary grouping, and standalone HTML."""

    def setUp(self) -> None:
        """Prepare repeated instruction occurrences across capture windows."""
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.result = self.root / "tvla_results.npz"
        self.values = {
            "t_scores": np.asarray([9, np.inf, -9, -np.inf, 4.5, 0]),
            "threshold": np.asarray(4.5),
            "pcs": np.asarray([0x1000, 0x2000, 0x1000, 0x1000, 0x3000, 0x1000]),
            "window_ids": np.asarray([0, 0, 1, 1, 1, 2]),
            "instruction_machines": np.asarray(["01", "02", "01", "03", "04", "01"]),
            "instruction_mnemonics": np.asarray(["mov", "ldrb", "mov", "eor", "nop", "mov"]),
            "instruction_operands": np.asarray(["r0, r1", "r2, [r1]", "r0, r1", "r0, r2", "", "r0, r1"]),
            "register_names": np.asarray(REGISTER_NAMES),
            "read_masks": np.full(6, 2),
            "write_masks": np.full(6, 1),
            "leakage_model": np.asarray("HD"),
            "register_model": np.asarray("accessed"),
            "tested_variable": np.asarray("plaintext"),
        }

    def _reports(self) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
        """Save the current results and read the generated CSV reports."""
        np.savez_compressed(self.result, **self.values)
        paths = write_tvla_instruction_reports(self.result)
        rows = []
        for path in paths:
            with path.open(encoding="utf-8", newline="") as source:
                rows.append(list(csv.DictReader(source)))
        return rows[0], rows[1]

    def test_occurrences_and_summary_preserve_dynamic_identity(self) -> None:
        """Filter strict crossings and summarize repeated descriptions separately."""
        occurrences, summary = self._reports()
        self.assertEqual([int(row["sample_index"]) for row in occurrences], [0, 1, 2, 3])
        self.assertEqual([row["window_id"] for row in occurrences], ["0", "0", "1", "1"])
        self.assertEqual([row["pc"] for row in summary], ["0x1000", "0x2000", "0x1000"])
        self.assertEqual([row["mnemonic"] for row in summary], ["eor", "ldrb", "mov"])
        repeated = summary[2]
        self.assertEqual(repeated["total_occurrences"], "3")
        self.assertEqual(repeated["flagged_occurrences"], "2")
        self.assertEqual(repeated["sample_index_at_max"], "0")
        self.assertEqual(float(repeated["t_score_at_max"]), 9)
        self.assertEqual(float(occurrences[1]["t_score"]), np.inf)
        self.assertEqual(float(occurrences[3]["t_score"]), -np.inf)
        self.assertEqual(occurrences[0]["read_registers"], "")
        self.assertEqual(occurrences[0]["write_registers"], "r0")

    def test_hw_and_id_report_reads_and_writes(self) -> None:
        """Expose both modeled contribution sides for accessed HW and ID."""
        for model in ("HW", "ID"):
            with self.subTest(model=model):
                self.values["leakage_model"] = np.asarray(model)
                occurrences, _summary = self._reports()
                self.assertEqual(occurrences[0]["read_registers"], "r1")
                self.assertEqual(occurrences[0]["write_registers"], "r0")

    def test_no_crossings_produce_header_only_files(self) -> None:
        """Keep reports valid when every score is at or below the threshold."""
        self.values["t_scores"] = np.asarray([4.5, -4.5, 0, 0, 0, 0])
        occurrences, summary = self._reports()
        self.assertEqual(occurrences, [])
        self.assertEqual(summary, [])
        for name in ("tvla_instruction_occurrences.csv", "tvla_instruction_summary.csv"):
            self.assertEqual(len((self.root / name).read_text().splitlines()), 1)
        self.assertTrue(show_tvla_results(self.result, display=False).is_file())

    def test_html_contains_hover_summary_and_unclipped_scores(self) -> None:
        """Render an offline HTML report with original scores in its models."""
        self._reports()
        with patch("sofa.components.tvla.save", wraps=save) as saved:
            path = show_tvla_results(self.result, display=False)
        layout = saved.call_args.args[0]
        hover = list(layout.select({"type": HoverTool}))[0]
        self.assertIn(("Instruction", "@mnemonic @operands"), hover.tooltips)
        line_data = hover.renderers[0].data_source.data
        self.assertEqual(line_data["score_text"][1], "inf")
        self.assertEqual(line_data["score_text"][3], "-inf")
        self.assertTrue(np.isfinite(line_data["y"]).all())
        table = list(layout.select({"type": DataTable}))[0]
        self.assertTrue(table.sortable)
        self.assertEqual(table.source.data["mnemonic"], ["eor", "ldrb", "mov"])
        self.assertEqual(table.source.data["t_score_at_max"][0], -np.inf)
        html = path.read_text(encoding="utf-8")
        self.assertIn("Public-input variation", html)
        self.assertIn("pre/post transitions", html)
        self.assertNotIn('src="https://cdn.bokeh.org', html)

    def test_all_mode_attribution_and_register_labels(self) -> None:
        """Describe historical observations without claiming decoded accesses."""
        self.values["register_model"] = np.asarray("all")
        self.values["leakage_model"] = np.asarray("HW")
        self.values["read_masks"] = np.full(6, 6)
        self.values["write_masks"] = np.zeros(6)
        occurrences, _summary = self._reports()
        self.assertEqual(occurrences[0]["read_registers"], "r1 r2")
        self.assertEqual(occurrences[0]["write_registers"], "")
        html = show_tvla_results(self.result, display=False).read_text(encoding="utf-8")
        self.assertIn("model-selected registers", html)
        self.assertIn("pre-instruction register state", html)
        self.values["leakage_model"] = np.asarray("HD")
        self._reports()
        html = show_tvla_results(self.result, display=False).read_text(encoding="utf-8")
        self.assertIn("span capture boundaries", html)

    def test_older_results_support_blank_descriptions(self) -> None:
        """Generate reports and HTML from results predating localization."""
        for key in (*INSTRUCTION_FIELDS, "read_masks", "write_masks"):
            del self.values[key]
        occurrences, _summary = self._reports()
        self.assertEqual(occurrences[0]["machine"], "")
        self.assertEqual(occurrences[0]["read_registers"], "")
        self.assertTrue(show_tvla_results(self.result, display=False).is_file())

    def test_partial_result_descriptions_are_rejected(self) -> None:
        """Reject partial reference descriptions in directly loaded results."""
        del self.values["instruction_operands"]
        np.savez_compressed(self.result, **self.values)
        with self.assertRaisesRegex(ValueError, "incomplete instruction metadata"):
            write_tvla_instruction_reports(self.result)

    def test_result_descriptions_must_match_score_count(self) -> None:
        """Reject mismatched reference metadata before writing any report."""
        self.values["instruction_operands"] = np.asarray(["r0"])
        np.savez_compressed(self.result, **self.values)
        with self.assertRaisesRegex(ValueError, "aligned with scores"):
            show_tvla_results(self.result, display=False)


class InstructionPipelineTests(unittest.TestCase):
    """Check sample mapping through CSV conversion, analysis, and export."""

    @staticmethod
    def _write_trace(path: Path, value: int) -> None:
        """Write three completed instructions, including a varying final write."""
        with path.open("w", encoding="utf-8", newline="") as output:
            writer = csv.writer(output)
            writer.writerow(ACCESSED_TRACE_HEADER)
            for sample in range(3):
                pre = [0] * 16
                post = [value] + [0] * 15
                writer.writerow([
                    hex(0x1000 + 2 * sample), "0001", "movs", "MOV", "r0, #1", "sofa-accessed-v1",
                    sample // 2, "0x2", "0x1", "0x0",
                    *(hex(item) for item in pre), *(hex(item) for item in post),
                ])

    def test_accessed_models_map_final_sample_and_keep_scores(self) -> None:
        """Map every completed instruction for HD, HW, and ID without shifting."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index, value in enumerate((0, 0, 3, 3)):
                self._write_trace(root / f"traces_{index + 1}.csv", value)
            for model in ("HD", "HW", "ID"):
                with self.subTest(model=model):
                    power = root / "power.npz"
                    create_npz_file(power, root, model, cols=["r0"])
                    with np.load(power, allow_pickle=False) as archive:
                        values = {key: archive[key] for key in archive.files}
                        expected = compute_welch_t_scores(
                            values["arr_0"], ["fixed", "fixed", "random", "random"],
                        )
                        self.assertEqual(len(values["instruction_machines"]), 1)
                        self.assertEqual(values["instruction_machines"][0], "0001")
                        self.assertEqual(values["instruction_ids"].shape, (4, 3))
                    values["group_labels"] = np.asarray(["fixed", "fixed", "random", "random"])
                    np.savez_compressed(power, **values)
                    result = analyze_tvla_archive(power)
                    with np.load(result, allow_pickle=False) as archive:
                        np.testing.assert_array_equal(archive["t_scores"], expected)
                    occurrences, _summary = write_tvla_instruction_reports(result)
                    with occurrences.open(newline="") as source:
                        rows = list(csv.DictReader(source))
                    self.assertEqual([row["pc"] for row in rows], ["0x1000", "0x1002", "0x1004"])
                    self.assertEqual(rows[-1]["sample_index"], "2")
                    self.assertEqual(rows[-1]["window_id"], "1")
                    self.assertEqual(rows[-1]["read_registers"], "")
                    self.assertEqual(rows[-1]["write_registers"], "r0")

    def test_historical_hd_keeps_first_n_minus_one_descriptions(self) -> None:
        """Map consecutive pre-states to the earlier CSV instruction row."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._write_trace(root / "traces_1.csv", 3)
            create_npz_file(root / "power.npz", root, "HD", register_model="all")
            with np.load(root / "power.npz", allow_pickle=False) as archive:
                self.assertEqual(archive["arr_0"].shape, (1, 2))
                np.testing.assert_array_equal(archive["pcs"][0], [0x1000, 0x1002])
                self.assertEqual(archive["instruction_ids"].shape, (1, 2))


if __name__ == "__main__":
    unittest.main()
