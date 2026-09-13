"""Tests for first-order TVLA generation and statistics."""

import tempfile
import unittest
from pathlib import Path

import numpy as np

from sofa.components.tvla import (
    analyze_tvla_archive,
    compute_welch_t_scores,
    generate_tvla_inputs,
)


class TvlaStatisticsTests(unittest.TestCase):
    """Verify Welch calculations and archive validation."""

    def test_welch_supports_unequal_groups_and_variances(self) -> None:
        """Match a direct Welch calculation for unequal group sizes."""
        traces = np.asarray([[1, 2], [3, 4], [2, 8], [4, 10], [8, 12]], dtype=float)
        labels = np.asarray(["fixed", "fixed", "random", "random", "random"])
        expected = (
            traces[:2].mean(axis=0) - traces[2:].mean(axis=0)
        ) / np.sqrt(
            traces[:2].var(axis=0, ddof=1) / 2
            + traces[2:].var(axis=0, ddof=1) / 3
        )
        np.testing.assert_allclose(compute_welch_t_scores(traces, labels), expected)

    def test_zero_denominator_is_explicit(self) -> None:
        """Return zero or signed infinity for deterministic samples."""
        traces = np.asarray([[2, 3, 1], [2, 3, 1], [2, 1, 4], [2, 1, 4]], dtype=float)
        scores = compute_welch_t_scores(traces, ["fixed", "fixed", "random", "random"])
        np.testing.assert_array_equal(scores, [0.0, np.inf, -np.inf])

    def test_archive_uses_strict_threshold(self) -> None:
        """Do not flag a score exactly equal to the threshold."""
        with tempfile.TemporaryDirectory() as temporary_dir:
            source = Path(temporary_dir) / "power_traces.npz"
            traces = np.asarray([[0.0], [2.0], [-3.5], [-1.5]])
            labels = np.asarray(["fixed", "fixed", "random", "random"])
            exact_threshold = float(compute_welch_t_scores(traces, labels)[0])
            common = np.zeros((4, 1))
            np.savez_compressed(
                source,
                arr_0=traces,
                lengths=np.full(4, 1),
                pcs=common,
                window_ids=common,
                trace_filenames=np.asarray([f"traces_{i}.csv" for i in range(4)]),
                group_labels=labels,
                register_model=np.asarray("all"),
            )
            result = analyze_tvla_archive(source, threshold=exact_threshold)
            with np.load(result) as archive:
                self.assertEqual(float(archive["t_scores"][0]), exact_threshold)
                self.assertFalse(bool(archive["exceeds_threshold"][0]))


class TvlaGenerationTests(unittest.TestCase):
    """Verify balanced and reproducible input generation."""

    def test_aes_defaults_to_fixed_key_random_plaintext(self) -> None:
        """Keep the AES key fixed and vary only random-group plaintexts."""
        settings = {"key_length": 16, "plaintext_length": 16, "use_iv": True}
        rows, manifest, effective_seed = generate_tvla_inputs(
            "AES", settings, 4, seed=123, overrides={"key": "11" * 16}
        )
        self.assertEqual(effective_seed, 123)
        self.assertEqual([row["group"] for row in manifest], ["fixed", "random", "fixed", "random"])
        self.assertEqual({row["key"] for row in manifest}, {"11" * 16})
        self.assertEqual(manifest[0]["plaintext"], manifest[2]["plaintext"])
        self.assertNotEqual(manifest[0]["plaintext"], manifest[1]["plaintext"])
        self.assertEqual(rows[0][0], "11" * 16)
        repeated = generate_tvla_inputs("AES", settings, 4, seed=123, overrides={"key": "11" * 16})
        self.assertEqual(rows, repeated[0])

    def test_variable_availability_and_count_are_validated(self) -> None:
        """Reject inactive fields and invalid trace counts."""
        with self.assertRaisesRegex(ValueError, "even integer"):
            generate_tvla_inputs("KECCAK", {"plaintext_length": 8}, 3)
        with self.assertRaisesRegex(ValueError, "not active"):
            generate_tvla_inputs("KECCAK", {"plaintext_length": 8}, 4, variable="key")
        with self.assertRaisesRegex(ValueError, "not active"):
            generate_tvla_inputs(
                "ASCON", {"plaintext_length": 8, "ad_length": 0}, 4, variable="ad"
            )


if __name__ == "__main__":
    unittest.main()
