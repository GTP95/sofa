"""First-order fixed-versus-random TVLA generation and analysis."""

from __future__ import annotations

import csv
import secrets
from html import escape
from pathlib import Path
from random import Random
from typing import Iterable, Mapping, Sequence

import numpy as np
from bokeh.layouts import column
from bokeh.models import ColumnDataSource, DataTable, Div, HoverTool, TableColumn
from bokeh.plotting import figure, output_file, save, show
from bokeh.resources import INLINE

from sofa.utils.constants import AES_BLOCK_SIZE, ASCON_KEY_SIZE, ASCON_NONCE_SIZE


TVLA_THRESHOLD = 4.5
TVLA_MANIFEST = "tvla_inputs.csv"
TVLA_RESULTS = "tvla_results.npz"
TVLA_PLOT = "tvla_plot.html"
TVLA_OCCURRENCES = "tvla_instruction_occurrences.csv"
TVLA_SUMMARY = "tvla_instruction_summary.csv"
INSTRUCTION_FIELDS = (
    "instruction_machines", "instruction_mnemonics", "instruction_operands",
)
OCCURRENCE_FIELDS = (
    "sample_index", "window_id", "pc", "machine", "mnemonic", "operands",
    "t_score", "abs_t_score", "read_registers", "write_registers",
    "leakage_model", "register_model", "tested_variable", "threshold",
)
SUMMARY_FIELDS = (
    "pc", "machine", "mnemonic", "operands", "total_occurrences",
    "flagged_occurrences", "max_abs_t_score", "t_score_at_max", "sample_index_at_max",
)


def tvla_field_lengths(
    algorithm: str, settings: Mapping[str, object]
) -> dict[str, int]:
    """Return active TVLA input fields and their lengths in bytes."""
    if algorithm == "AES":
        fields = {
            "key": int(settings["key_length"]),
            "plaintext": int(settings["plaintext_length"]),
        }
        if bool(settings["use_iv"]):
            fields["iv"] = AES_BLOCK_SIZE
        return fields
    if algorithm == "ASCON":
        fields = {
            "key": ASCON_KEY_SIZE,
            "plaintext": int(settings["plaintext_length"]),
            "nonce": ASCON_NONCE_SIZE,
        }
        if int(settings["ad_length"]) > 0:
            fields["ad"] = int(settings["ad_length"])
        return fields
    if algorithm == "KECCAK":
        return {"plaintext": int(settings["plaintext_length"])}
    raise ValueError(f"TVLA is not supported for algorithm {algorithm!r}")


def _validate_hex_override(field: str, value: str, length: int) -> str:
    """Validate and normalize one hexadecimal baseline override."""
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"TVLA baseline --{field} must be hexadecimal") from error
    if len(decoded) != length:
        raise ValueError(
            f"TVLA baseline --{field} must be exactly {length} bytes, "
            f"but got {len(decoded)}"
        )
    return decoded.hex()


def generate_tvla_inputs(
    algorithm: str,
    target_settings: Mapping[str, object],
    count: int,
    variable: str = "plaintext",
    seed: int | None = None,
    overrides: Mapping[str, str | None] | None = None,
) -> tuple[list[list[str]], list[dict[str, str]], int]:
    """Generate balanced, interleaved fixed-versus-random input vectors.

    Returns target rows, manifest rows, and the effective random seed.
    """
    if count < 4 or count % 2:
        raise ValueError("TVLA --count must be an even integer of at least 4")
    fields = tvla_field_lengths(algorithm, target_settings)
    if variable not in fields:
        available = ", ".join(fields)
        raise ValueError(
            f"TVLA variable {variable!r} is not active for {algorithm}; "
            f"choose one of: {available}"
        )
    if fields[variable] <= 0:
        raise ValueError(
            f"TVLA variable {variable!r} has no bytes to vary for {algorithm}"
        )
    if seed is None:
        seed = secrets.randbits(64)
    if seed < 0 or seed >= 2**64:
        raise ValueError("--tvla_seed must be between 0 and 2^64 - 1")
    rng = Random(seed)
    supplied = overrides or {}
    baseline: dict[str, str] = {}
    for field, length in fields.items():
        override = supplied.get(field)
        baseline[field] = (
            _validate_hex_override(field, override, length)
            if override is not None
            else rng.randbytes(length).hex()
        )

    order = {
        "AES": ["key", "plaintext"] + (["iv"] if "iv" in fields else []),
        "ASCON": ["key", "plaintext", "nonce", "ad"],
        "KECCAK": ["plaintext"],
    }[algorithm]
    target_rows: list[list[str]] = []
    manifest_rows: list[dict[str, str]] = []
    for index in range(count):
        group = "fixed" if index % 2 == 0 else "random"
        values = baseline.copy()
        if group == "random":
            candidate = baseline[variable]
            while candidate == baseline[variable]:
                candidate = rng.randbytes(fields[variable]).hex()
            values[variable] = candidate
        target_rows.append([values.get(field, "") for field in order])
        manifest_rows.append(
            {
                "trace_filename": f"traces_{index + 1}.csv",
                "group": group,
                "tested_variable": variable,
                "effective_seed": str(seed),
                **values,
            }
        )
    return target_rows, manifest_rows, seed


def write_tvla_manifest(
    path: str | Path, rows: Sequence[Mapping[str, str]]
) -> None:
    """Write generated TVLA vectors and their group labels to CSV."""
    if not rows:
        raise ValueError("Cannot write an empty TVLA manifest")
    fieldnames = list(rows[0])
    with Path(path).open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def load_tvla_group_labels(
    manifest_path: str | Path, trace_filenames: Sequence[str]
) -> np.ndarray:
    """Load manifest labels in execution-trace filename order."""
    with Path(manifest_path).open(encoding="utf-8", newline="") as source:
        rows = list(csv.DictReader(source))
    labels = {row["trace_filename"]: row["group"] for row in rows}
    missing = [name for name in trace_filenames if name not in labels]
    if missing:
        raise ValueError(f"TVLA manifest has no label for {missing[0]}")
    result = np.asarray([labels[name] for name in trace_filenames], dtype="U6")
    invalid = sorted(set(result) - {"fixed", "random"})
    if invalid:
        raise ValueError(f"Unsupported TVLA group label: {invalid[0]!r}")
    return result


def compute_welch_t_scores(
    traces: np.ndarray, group_labels: Sequence[str]
) -> np.ndarray:
    """Compute point-wise Welch scores using online Welford accumulation."""
    samples = np.asarray(traces, dtype=np.float64)
    labels = np.asarray(group_labels)
    if samples.ndim != 2 or len(labels) != len(samples):
        raise ValueError("TVLA traces must be a 2-D array aligned with group labels")
    invalid_labels = sorted(set(labels.tolist()) - {"fixed", "random"})
    if invalid_labels:
        raise ValueError(f"Unsupported TVLA group label: {invalid_labels[0]!r}")
    counts = {"fixed": 0, "random": 0}
    means = {
        group: np.zeros(samples.shape[1], dtype=np.float64) for group in counts
    }
    m2_values = {
        group: np.zeros(samples.shape[1], dtype=np.float64) for group in counts
    }
    for label, row in zip(labels, samples, strict=True):
        group = str(label)
        counts[group] += 1
        delta = row - means[group]
        means[group] += delta / counts[group]
        m2_values[group] += delta * (row - means[group])
    states: dict[str, tuple[int, np.ndarray, np.ndarray]] = {}
    for group, count in counts.items():
        if count < 2:
            raise ValueError(f"TVLA requires at least two {group} traces")
        states[group] = (count, means[group], m2_values[group] / (count - 1))
    fixed_count, fixed_mean, fixed_variance = states["fixed"]
    random_count, random_mean, random_variance = states["random"]
    difference = fixed_mean - random_mean
    denominator = np.sqrt(
        fixed_variance / fixed_count + random_variance / random_count
    )
    scores = np.empty_like(difference)
    nonzero = denominator != 0
    scores[nonzero] = difference[nonzero] / denominator[nonzero]
    zero = ~nonzero
    scores[zero & (difference == 0)] = 0.0
    scores[zero & (difference > 0)] = np.inf
    scores[zero & (difference < 0)] = -np.inf
    return scores


def _first_divergence(
    values: np.ndarray, filenames: np.ndarray, label: str
) -> None:
    """Raise an informative error for the first row differing from reference."""
    reference = values[0]
    for trace_index in range(1, len(values)):
        differences = np.flatnonzero(values[trace_index] != reference)
        if differences.size:
            sample = int(differences[0])
            raise ValueError(
                f"TVLA {label} alignment diverges at sample {sample} between "
                f"{filenames[0]} and {filenames[trace_index]}"
            )


def _reference_instruction_metadata(
    archive: Mapping[str, np.ndarray],
    expected_shape: tuple[int, int],
    filenames: np.ndarray,
) -> dict[str, np.ndarray]:
    """Validate instruction tables and return aligned reference descriptions."""
    keys = {"instruction_ids", *INSTRUCTION_FIELDS}
    present = keys.intersection(archive)
    if not present:
        return {key: np.full(expected_shape[1], "", dtype="U1") for key in INSTRUCTION_FIELDS}
    if present != keys:
        raise ValueError(
            f"Power archive has incomplete instruction metadata: {', '.join(sorted(keys - present))}"
        )
    tables = {key: np.asarray(archive[key]) for key in INSTRUCTION_FIELDS}
    if any(value.ndim != 1 or value.dtype.kind != "U" for value in tables.values()):
        raise ValueError("TVLA instruction descriptions must be one-dimensional Unicode arrays")
    table_lengths = {len(value) for value in tables.values()}
    if len(table_lengths) != 1:
        raise ValueError("TVLA instruction-description table lengths differ")
    raw_ids = np.asarray(archive["instruction_ids"])
    if raw_ids.ndim != 2 or raw_ids.dtype.kind not in "iuf":
        raise ValueError("TVLA instruction-ID array is not aligned with power samples")
    ids = raw_ids[:, :expected_shape[1]]
    if ids.shape != expected_shape:
        raise ValueError("TVLA instruction-ID array is not aligned with power samples")
    table_length = len(tables[INSTRUCTION_FIELDS[0]])
    if (not np.isfinite(ids).all() or np.any(ids < 0)
            or np.any(ids >= table_length) or np.any(ids != np.floor(ids))):
        raise ValueError("TVLA instruction IDs must be finite integers indexing the description table")
    ids = ids.astype(np.int64)
    reference = {key: values[ids[0]] for key, values in tables.items()}
    for trace_index in range(1, len(ids)):
        differs = np.zeros(expected_shape[1], dtype=bool)
        for key, values in tables.items():
            differs |= values[ids[trace_index]] != reference[key]
        positions = np.flatnonzero(differs)
        if positions.size:
            raise ValueError(
                f"TVLA instruction-identity alignment diverges at sample {int(positions[0])} "
                f"between {filenames[0]} and {filenames[trace_index]}"
            )
    return reference


def analyze_tvla_archive(
    power_file: str | Path,
    output_path: str | Path | None = None,
    tested_variable: str | None = None,
    effective_seed: int | None = None,
    threshold: float = TVLA_THRESHOLD,
) -> Path:
    """Validate a power archive, calculate first-order TVLA, and save results."""
    power_path = Path(power_file)
    destination = (
        Path(output_path) if output_path else power_path.with_name(TVLA_RESULTS)
    )
    with np.load(power_path) as archive:
        required = {
            "arr_0",
            "lengths",
            "pcs",
            "window_ids",
            "trace_filenames",
            "group_labels",
        }
        missing = sorted(required - set(archive.files))
        if missing:
            raise ValueError(f"Power archive is missing TVLA data: {', '.join(missing)}")
        traces = np.asarray(archive["arr_0"], dtype=np.float64)
        lengths = np.asarray(archive["lengths"], dtype=np.int64)
        filenames = np.asarray(archive["trace_filenames"])
        labels = np.asarray(archive["group_labels"])
        if traces.ndim != 2:
            raise ValueError("TVLA combined power traces must be a 2-D array")
        if len(lengths) != len(traces):
            raise ValueError("TVLA trace lengths are not aligned with power rows")
        if len(labels) != len(traces) or len(filenames) != len(traces):
            raise ValueError(
                "TVLA group labels, trace filenames, and power rows are not aligned"
            )
        invalid_labels = sorted(set(labels.tolist()) - {"fixed", "random"})
        if invalid_labels:
            raise ValueError(f"Unsupported TVLA group label: {invalid_labels[0]!r}")
        fixed_count = int(np.count_nonzero(labels == "fixed"))
        random_count = int(np.count_nonzero(labels == "random"))
        if fixed_count < 2 or random_count < 2:
            raise ValueError("TVLA requires at least two traces in each group")
        if fixed_count != random_count:
            raise ValueError(
                "TVLA power archive must contain balanced fixed and random groups"
            )
        if len(set(lengths.tolist())) != 1:
            first = int(lengths[0])
            divergent = int(np.flatnonzero(lengths != first)[0])
            raise ValueError(
                "TVLA sample counts differ between "
                f"{filenames[0]} ({first}) and {filenames[divergent]} "
                f"({lengths[divergent]})"
            )
        sample_count = int(lengths[0])
        if sample_count > traces.shape[1]:
            raise ValueError(
                f"TVLA declared trace length {sample_count} exceeds the "
                f"{traces.shape[1]} stored power samples"
            )
        if sample_count <= 0 or not np.isfinite(traces[:, :sample_count]).all():
            positions = np.argwhere(~np.isfinite(traces[:, :sample_count]))
            trace_index, sample = positions[0] if len(positions) else (0, 0)
            raise ValueError(
                f"TVLA invalid power sample at sample {int(sample)} in "
                f"{filenames[int(trace_index)]}"
            )
        raw_pcs = np.asarray(archive["pcs"])
        raw_windows = np.asarray(archive["window_ids"])
        expected_shape = (len(traces), sample_count)
        if raw_pcs.ndim != 2 or raw_windows.ndim != 2:
            raise ValueError(
                "TVLA PC and window-ID arrays are not aligned with power samples"
            )
        pcs = raw_pcs[:, :sample_count]
        windows = raw_windows[:, :sample_count]
        if pcs.shape != expected_shape or windows.shape != expected_shape:
            raise ValueError(
                "TVLA PC and window-ID arrays are not aligned with power samples"
            )
        _first_divergence(pcs, filenames, "PC")
        _first_divergence(windows, filenames, "window-ID")
        register_model = (
            str(archive["register_model"]) if "register_model" in archive else ""
        )
        reference_metadata = _reference_instruction_metadata(archive, expected_shape, filenames)
        if register_model == "accessed" or {"read_masks", "write_masks"}.intersection(archive):
            mask_arrays = (
                ("read_masks", "read-mask"),
                ("write_masks", "write-mask"),
            )
            for key, description in mask_arrays:
                if key not in archive:
                    raise ValueError(f"Power archive is missing TVLA data: {key}")
                raw_masks = np.asarray(archive[key])
                if raw_masks.ndim != 2:
                    raise ValueError(
                        f"TVLA {description} array is not aligned with power samples"
                    )
                mask_values = raw_masks[:, :sample_count]
                if mask_values.shape != expected_shape:
                    raise ValueError(
                        f"TVLA {description} array is not aligned with power samples"
                    )
                if (mask_values.dtype.kind not in "iuf" or not np.isfinite(mask_values).all()
                        or np.any(mask_values < 0) or np.any(mask_values > 0xFFFF)
                        or np.any(mask_values != np.floor(mask_values))):
                    raise ValueError(f"TVLA {description} values must be 16-bit register masks")
                _first_divergence(
                    mask_values,
                    filenames,
                    description,
                )
                reference_metadata[key] = mask_values[0].astype(np.uint64)
        scores = compute_welch_t_scores(traces[:, :sample_count], labels)
        metadata = {
            key: np.asarray(archive[key])
            for key in (
                "leakage_model",
                "register_model",
                "trace_schema",
                "selected_registers",
                "register_names",
                "capstone_version",
            )
            if key in archive
        }
    np.savez_compressed(
        destination,
        t_scores=scores,
        exceeds_threshold=np.abs(scores) > threshold,
        threshold=np.asarray(threshold),
        fixed_count=np.asarray(fixed_count),
        random_count=np.asarray(random_count),
        pcs=pcs[0],
        window_ids=windows[0],
        tested_variable=np.asarray(tested_variable or "", dtype="U32"),
        effective_seed=np.asarray(
            0 if effective_seed is None else effective_seed, dtype=np.uint64
        ),
        source_archive=np.asarray(power_path.name, dtype="U256"),
        **reference_metadata,
        **metadata,
    )
    return destination


def _instruction_report_data(
    results_file: str | Path,
) -> tuple[dict[str, np.ndarray], list[dict[str, object]]]:
    """Load occurrence columns and summarize existing tests by instruction."""
    with np.load(results_file, allow_pickle=False) as archive:
        scores = np.asarray(archive["t_scores"], dtype=np.float64)
        if scores.ndim != 1 or not scores.size or np.isnan(scores).any():
            raise ValueError("TVLA result scores must be a nonempty one-dimensional array without NaN")
        count = len(scores)
        threshold = float(archive["threshold"])
        leakage_model = str(archive["leakage_model"]) if "leakage_model" in archive else ""
        register_model = str(archive["register_model"]) if "register_model" in archive else ""
        variable = str(archive["tested_variable"]) if "tested_variable" in archive else ""
        names = (
            archive["register_names"].tolist() if "register_names" in archive
            else [f"r{index}" for index in range(13)] + ["sp", "lr", "pc"]
        )
        selected = archive["selected_registers"].tolist() if "selected_registers" in archive else []
        descriptions_present = set(INSTRUCTION_FIELDS).intersection(archive)
        if descriptions_present and descriptions_present != set(INSTRUCTION_FIELDS):
            raise ValueError("TVLA results have incomplete instruction metadata")
        for key in descriptions_present:
            values = np.asarray(archive[key])
            if values.shape != (count,) or values.dtype.kind != "U":
                raise ValueError(f"TVLA result {key} must be a Unicode array aligned with scores")
        for key in ("pcs", "window_ids", "read_masks", "write_masks"):
            if key in archive and np.asarray(archive[key]).shape != (count,):
                raise ValueError(f"TVLA result {key} is not aligned with scores")
        data = {
            "sample_index": np.arange(count),
            "window_id": np.asarray(archive["window_ids"], dtype=np.int64),
            "pc": np.asarray([hex(int(pc)) for pc in archive["pcs"]]),
            "t_score": scores,
            "abs_t_score": np.abs(scores),
            "threshold": np.full(count, threshold),
            "leakage_model": np.full(count, leakage_model),
            "register_model": np.full(count, register_model),
            "tested_variable": np.full(count, variable),
        }
        for field, key in zip(("machine", "mnemonic", "operands"), INSTRUCTION_FIELDS, strict=True):
            data[field] = np.asarray(archive[key]) if key in archive else np.full(count, "")
        for side in ("read", "write"):
            active_side = side == "write" if leakage_model == "HD" else True
            if register_model == "all" and leakage_model != "HD":
                active_side = side == "read"
            key = f"{side}_masks"
            if not active_side:
                registers = [""] * count
            elif key in archive:
                registers = [
                    " ".join(name for bit, name in enumerate(names) if int(mask) & (1 << bit))
                    for mask in archive[key]
                ]
            elif register_model == "all":
                registers = [" ".join(name for name in names if name in selected)] * count
            else:
                registers = [""] * count
            data[f"{side}_registers"] = np.asarray(registers)

    groups: dict[tuple[str, str, str, str], dict[str, object]] = {}
    for sample in range(count):
        identity = tuple(str(data[field][sample]) for field in ("pc", "machine", "mnemonic", "operands"))
        score = float(scores[sample])
        magnitude = abs(score)
        row = groups.get(identity)
        if row is None:
            row = dict(zip(("pc", "machine", "mnemonic", "operands"), identity, strict=True))
            row.update(
                total_occurrences=0, flagged_occurrences=0,
                max_abs_t_score=magnitude, t_score_at_max=score, sample_index_at_max=sample,
            )
            groups[identity] = row
        row["total_occurrences"] += 1
        row["flagged_occurrences"] += int(magnitude > threshold)
        if magnitude > row["max_abs_t_score"]:
            row.update(max_abs_t_score=magnitude, t_score_at_max=score, sample_index_at_max=sample)
    summary = [row for row in groups.values() if row["flagged_occurrences"]]
    summary.sort(key=lambda row: (
        -row["max_abs_t_score"], int(row["pc"], 16), row["machine"], row["mnemonic"], row["operands"],
    ))
    return data, summary


def _write_instruction_csv(
    path: Path, fields: Sequence[str], rows: Iterable[Mapping[str, object]],
) -> None:
    """Write an instruction report, retaining headers when no samples cross."""
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def write_tvla_instruction_reports(results_file: str | Path) -> tuple[Path, Path]:
    """Export flagged occurrences and summaries without performing new tests."""
    results_path = Path(results_file)
    data, summary = _instruction_report_data(results_path)
    flagged = np.flatnonzero(data["abs_t_score"] > data["threshold"])
    occurrences_path = results_path.with_name(TVLA_OCCURRENCES)
    summary_path = results_path.with_name(TVLA_SUMMARY)
    _write_instruction_csv(
        occurrences_path, OCCURRENCE_FIELDS,
        ({field: data[field][sample] for field in OCCURRENCE_FIELDS} for sample in flagged),
    )
    _write_instruction_csv(summary_path, SUMMARY_FIELDS, summary)
    distinct_pcs = len({row["pc"] for row in summary})
    print(
        f"TVLA: {len(flagged)} flagged samples at {distinct_pcs} distinct instruction addresses "
        f"({len(summary)} instruction descriptions)."
    )
    print(f"Instruction occurrences: {occurrences_path}")
    print(f"Instruction summary: {summary_path}")
    return occurrences_path, summary_path


def _attribution_description(leakage_model: str, register_model: str) -> str:
    """Describe the execution event represented by the selected power model."""
    if register_model == "accessed":
        if leakage_model == "HD":
            return "HD observes pre/post transitions in registers written by this instruction. Read registers do not contribute."
        return "HW/ID observes this instruction's operand reads and result writes."
    if register_model == "all":
        if leakage_model == "HD":
            return (
                "HD observes consecutive recorded pre-state transitions associated with the earlier row; "
                "these can span capture boundaries. Register sets are model-selected registers, not decoded accesses."
            )
        return (
            "HW/ID observes pre-instruction register state. "
            "Register sets are model-selected registers, not decoded accesses."
        )
    return "Attribution metadata is unavailable in this older archive."


def show_tvla_results(
    results_file: str | Path, plot_path: str | Path | None = None, display: bool = True
) -> Path:
    """Save a standalone TVLA plot with instruction details and summary table."""
    results_path = Path(results_file)
    destination = Path(plot_path) if plot_path else results_path.with_name(TVLA_PLOT)
    data, summary = _instruction_report_data(results_path)
    scores = data["t_score"]
    threshold = float(data["threshold"][0])
    finite = scores[np.isfinite(scores)]
    display_limit = max(
        threshold * 1.25,
        float(np.max(np.abs(finite))) if finite.size else threshold * 1.25,
    )
    data["x"] = data["sample_index"]
    data["y"] = np.clip(scores, -display_limit, display_limit)
    data["score_text"] = np.asarray([str(float(score)) for score in scores])
    crossing = np.abs(scores) > threshold
    infinite = np.isinf(scores)
    plot = figure(
        title="First-order fixed-versus-random TVLA",
        x_axis_label="Sample index",
        y_axis_label="Welch t-score",
        width=1000,
        height=500,
    )
    line = plot.line("x", "y", source=ColumnDataSource(data), line_width=1.5, legend_label="t-score")
    plot.add_tools(HoverTool(renderers=[line], tooltips=[
        ("Sample", "@sample_index"), ("Window", "@window_id"), ("PC", "@pc"),
        ("Machine", "@machine"), ("Instruction", "@mnemonic @operands"),
        ("t-score", "@score_text"), ("Tested variable", "@tested_variable"),
        ("Leakage model", "@leakage_model"), ("Register model", "@register_model"),
        ("Contributing reads", "@read_registers"), ("Contributing writes", "@write_registers"),
    ]))
    endpoints = [0, max(len(scores) - 1, 0)]
    plot.line(endpoints, [threshold, threshold], line_dash="dashed", color="firebrick")
    plot.line(endpoints, [-threshold, -threshold], line_dash="dashed", color="firebrick")
    plot.scatter(
        "x", "y", source=ColumnDataSource({key: values[crossing] for key, values in data.items()}),
        color="orange", size=5, legend_label=f"|t| > {threshold:g}",
    )
    plot.scatter(
        "x", "y", source=ColumnDataSource({key: values[infinite] for key, values in data.items()}),
        marker="x", color="black", size=10, legend_label="infinite (clipped)",
    )
    summary_data = {field: [row[field] for row in summary] for field in SUMMARY_FIELDS}
    table = DataTable(
        source=ColumnDataSource(summary_data), width=1000, height=300,
        sortable=True, index_position=None,
        columns=[
            TableColumn(field="pc", title="PC"), TableColumn(field="machine", title="Machine"),
            TableColumn(field="mnemonic", title="Instruction"), TableColumn(field="operands", title="Operands"),
            TableColumn(field="total_occurrences", title="Total occurrences"),
            TableColumn(field="flagged_occurrences", title="Flagged occurrences"),
            TableColumn(field="max_abs_t_score", title="Max |t|"),
            TableColumn(field="t_score_at_max", title="t at max"),
            TableColumn(field="sample_index_at_max", title="Sample at max"),
        ],
    )
    attribution = _attribution_description(str(data["leakage_model"][0]), str(data["register_model"][0]))
    description = Div(text=(
        "<p>Potentially leaking instructions under the selected simulated model. "
        "Public-input variation can cause crossings; a crossing does not establish exploitability, "
        "and first-order non-detection does not establish security.</p>"
        f"<p>{escape(attribution)}</p>"
        "<p>The table summarizes existing sample tests across capture windows. "
        "It does not pool occurrences or add statistical confirmation. Infinite scores are clipped only in the plot.</p>"
    ), width=1000)
    layout = column(description, plot, Div(text="<h3>Flagged instruction summary</h3>"), table)
    output_file(destination, title="Sofa TVLA results", mode="inline")
    save(layout, resources=INLINE)
    if display:
        show(layout)
    return destination
