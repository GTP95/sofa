"""Lossless parsing and leakage processing for architecture-aware v2 traces."""

from __future__ import annotations

import csv
from importlib.metadata import version
from pathlib import Path
import tempfile
from typing import Any

import numpy as np

from sofa.utils.architectures import ARCHITECTURES, Architecture


def trace_architecture(path: str | Path) -> Architecture | None:
    """Identify a v2 CSV, returning None for historical ARM traces."""
    with Path(path).open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if "architecture" not in (reader.fieldnames or []):
            return None
        first = next(reader, None)
        if first is None:
            raise ValueError(f"Empty architecture-aware execution trace: {path}")
        if first["architecture"] not in ARCHITECTURES:
            raise ValueError(f"Unsupported trace architecture: {first['architecture']}")
        return ARCHITECTURES[first["architecture"]]


def selected_names(arch: Architecture, cols: list[str] | tuple[str, ...] | None) -> tuple[str, ...]:
    """Resolve optional register selection to canonical physical names."""
    selected = set(arch.names) if cols is None else {arch.canonical(name) for name in cols}
    unknown = selected - set(arch.names)
    if unknown:
        raise ValueError(f"Unsupported {arch.name} registers: {', '.join(sorted(unknown))}")
    if arch.name != "arm64":
        selected.discard("x0")
    return tuple(name for name in arch.names if name in selected)


def pack_masks(values: list[int], words: int) -> np.ndarray:
    """Encode arbitrary-width Python masks into little-endian uint64 words."""
    return np.asarray([[(mask >> (64 * word)) & ((1 << 64) - 1) for word in range(words)]
                       for mask in values], dtype=np.uint64).reshape(len(values), words)


def unpack_mask(value: Any) -> int:
    """Decode either a historical scalar mask or packed uint64 words."""
    if np.ndim(value) == 0:
        return int(value)
    return sum(int(word) << (64 * index) for index, word in enumerate(value))


def process_v2(file: str | Path, cols: list[str] | tuple[str, ...] | None,
               leakage_model: str, register_model: str) -> dict[str, np.ndarray]:
    """Calculate leakage using Python integers for registers up to 128 bits."""
    arch = trace_architecture(file)
    if arch is None:
        raise ValueError("Expected an architecture-aware execution trace")
    if leakage_model not in {"ID", "HW", "HD"} or register_model not in {"accessed", "all"}:
        raise ValueError("Unsupported leakage or register model")
    selected = set(selected_names(arch, cols))
    selected_mask = arch.mask(selected)
    with Path(file).open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        required = {"PC", "Machine", "Ins", "Operands", "trace_schema", "architecture", "window_id",
                    "read_mask", "write_mask", *arch.names}
        if register_model == "accessed":
            required.update(f"post_{name}" for name in arch.names)
        if required - set(reader.fieldnames or []):
            raise ValueError(f"Missing v2 trace columns: {sorted(required - set(reader.fieldnames or []))}")
        rows = list(reader)
    pre: list[list[int]] = []
    post: list[list[int]] = []
    reads, writes = [], []
    for row in rows:
        if row["architecture"] != arch.name or row["trace_schema"] != f"sofa-{register_model}-v2":
            raise ValueError("Mixed architecture, schema, or register model in execution trace")
        before = [int(row[name], 16) for name in arch.names]
        after = [int(row[f"post_{name}"], 16) for name in arch.names] if register_model == "accessed" else before
        if any(not 0 <= value < 1 << width for values in (before, after)
               for value, width in zip(values, arch.widths, strict=True)):
            raise ValueError("Register value exceeds its physical width")
        pre.append(before)
        post.append(after)
        read, write = int(row["read_mask"], 16), int(row["write_mask"], 16)
        if min(read, write) < 0 or max(read, write) >= 1 << len(arch.names):
            raise ValueError("Invalid architecture register mask")
        reads.append(read & selected_mask)
        writes.append(write & selected_mask)
    if register_model == "all":
        if leakage_model == "HD":
            post = pre[1:]
            pre = pre[:-1]
            reads, writes = [0] * len(pre), [selected_mask] * len(pre)
        else:
            reads, writes = [selected_mask] * len(pre), [0] * len(pre)
    count = len(pre)
    read_components = np.zeros((count, len(arch.names)), dtype=np.float64)
    write_components = np.zeros_like(read_components)
    for sample, (before, after) in enumerate(zip(pre, post)):
        for bit, (old, new) in enumerate(zip(before, after, strict=True)):
            if leakage_model != "HD" and reads[sample] & (1 << bit):
                read_components[sample, bit] = old if leakage_model == "ID" else old.bit_count()
            if writes[sample] & (1 << bit):
                write_components[sample, bit] = (old ^ new).bit_count() if leakage_model == "HD" else new if leakage_model == "ID" else new.bit_count()
    words = (len(arch.names) + 63) // 64
    pcs = [int(row["PC"], 16) for row in rows[:count]]
    if any(not 0 <= pc < 1 << arch.bits for pc in pcs):
        raise ValueError("Trace PC exceeds architecture width")
    return {
        "combined": np.sum(read_components + write_components, axis=1),
        "read_components": read_components, "write_components": write_components,
        "read_masks": pack_masks(reads, words), "write_masks": pack_masks(writes, words),
        "pcs": np.asarray(pcs, dtype=np.uint64),
        "window_ids": np.asarray([int(row["window_id"]) for row in rows[:count]], dtype=np.int64),
        "instruction_machines": np.asarray([row["Machine"] for row in rows[:count]], dtype=str),
        "instruction_mnemonics": np.asarray([row["Ins"] for row in rows[:count]], dtype=str),
        "instruction_operands": np.asarray([row["Operands"] for row in rows[:count]], dtype=str),
    }


def create_v2_archive(destination: str | Path, files: list[Path], leakage_model: str,
                      cols: list[str] | tuple[str, ...] | None, register_model: str) -> None:
    """Write padded diagnostics with exact PCs and packed masks using disk backing."""
    arch = trace_architecture(files[0])
    if arch is None:
        raise ValueError("Expected an architecture-aware execution trace")
    lengths = []
    for file in files:
        if trace_architecture(file) != arch:
            raise ValueError("Cannot combine execution traces from different architectures")
        with file.open(newline="", encoding="utf-8") as source:
            count = sum(1 for _ in csv.DictReader(source))
        lengths.append(count - (register_model == "all" and leakage_model == "HD"))
    if min(lengths) <= 0:
        raise ValueError("Execution traces contain no power samples")
    shape = (len(files), max(lengths))
    words = (len(arch.names) + 63) // 64
    specs = {
        "arr_0": (np.float64, shape, np.nan),
        "read_components": (np.float64, (*shape, len(arch.names)), np.nan),
        "write_components": (np.float64, (*shape, len(arch.names)), np.nan),
        "read_masks": (np.uint64, (*shape, words), 0), "write_masks": (np.uint64, (*shape, words), 0),
        "pcs": (np.uint64, shape, 0), "window_ids": (np.int64, shape, -1),
        "instruction_ids": (np.int64, shape, -1),
    }
    with tempfile.TemporaryDirectory(prefix="sofa-power-") as temporary:
        arrays = {key: np.memmap(Path(temporary) / key, mode="w+", dtype=dtype, shape=size)
                  for key, (dtype, size, _) in specs.items()}
        for key, array in arrays.items():
            array[:] = specs[key][2]
        descriptions: dict[tuple[str, str, str], int] = {}
        for index, (file, length) in enumerate(zip(files, lengths, strict=True)):
            values = process_v2(file, cols, leakage_model, register_model)
            arrays["arr_0"][index, :length] = values["combined"]
            for key in ("read_components", "write_components", "read_masks", "write_masks", "pcs", "window_ids"):
                arrays[key][index, :length] = values[key]
            for sample, description in enumerate(zip(values["instruction_machines"], values["instruction_mnemonics"], values["instruction_operands"], strict=True)):
                arrays["instruction_ids"][index, sample] = descriptions.setdefault(description, len(descriptions))
        metadata = {
            "architecture": np.asarray(arch.name), "register_names": np.asarray(arch.names),
            "register_widths": np.asarray(arch.widths, dtype=np.uint16),
            "selected_registers": np.asarray(selected_names(arch, cols), dtype=str),
            "leakage_model": np.asarray(leakage_model), "register_model": np.asarray(register_model),
            "trace_schema": np.asarray(f"sofa-{register_model}-v2"), "capstone_version": np.asarray(version("capstone")),
            "lengths": np.asarray(lengths, dtype=np.int64), "trace_filenames": np.asarray([f.name for f in files]),
        }
        for column, key in enumerate(("instruction_machines", "instruction_mnemonics", "instruction_operands")):
            metadata[key] = np.asarray([description[column] for description in descriptions], dtype=str)
        manifest = files[0].parent / "tvla_inputs.csv"
        if manifest.exists():
            from sofa.components.tvla import load_tvla_group_labels
            metadata["group_labels"] = load_tvla_group_labels(manifest, [f.name for f in files])
        pqc_manifest = files[0].parent / "pqc_inputs.csv"
        if pqc_manifest.exists():
            import json
            with pqc_manifest.open(encoding="utf-8", newline="") as source:
                metadata["pqc_inputs"] = np.asarray(json.dumps(list(csv.DictReader(source))))
        np.savez_compressed(destination, **arrays, **metadata)
        for array in arrays.values():
            array.flush()
        del array
        arrays.clear()
