# Sofa

*A power simulator for side-channel analysis of ARM binaries*

![Sofa](art/CPU.webp)

Sofa identifies architectural leakage in ARM software implementations of
cryptographic algorithms. It uses [Qiling](https://qiling.io/) to emulate a
firmware binary, records register state during the operation of interest, and
applies an Identity (ID), Hamming Weight (HW), or Hamming Distance (HD) leakage
model to the resulting execution trace.

Sofa includes ready-to-build examples for AES, ASCON, and KECCAK, while JSON
simulation profiles make it possible to analyze other binaries supported by
Qiling.

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Building the bundled firmware](#building-the-bundled-firmware)
- [Simulation profiles](#simulation-profiles)
- [Running simulations](#running-simulations)
- [Input modes](#input-modes)
- [First-order TVLA](#first-order-tvla)
- [Output files](#output-files)
- [Leakage and register models](#leakage-and-register-models)
- [How instruction capture works](#how-instruction-capture-works)
- [Command-line reference](#command-line-reference)
- [Benchmarking](#benchmarking)
- [Project background](#project-background)
- [License](#license)

## Features

- AES, ASCON, and KECCAK example targets.
- Identity, Hamming Weight, and Hamming Distance leakage models.
- Instruction-aware register selection and a historical all-register mode.
- User-provided, CSV, and automatically generated inputs.
- Customizable input validation and algorithm-specific padding.
- JSON profiles for configuring binaries, platforms, and capture windows.
- First-order fixed-versus-random TVLA with reproducible, balanced input
  generation and point-wise Welch scores.
- Qiling-based emulation of ARM platforms.
- Makefile-based firmware builds for multiple targets and platforms.

### Supported algorithms

| Algorithm | Supported inputs |
|-----------|------------------|
| AES | Key, IV, and plaintext in user-provided and auto-generated modes. |
| ASCON | Key, nonce, plaintext, and optional associated data. |
| KECCAK | Key, plaintext, and sponge capacity. |

## Requirements

These host requirements can be ignored when using the Docker image:

- Python 3.10 or later. Sofa is tested on Python 3.12. At the time of writing,
  dependency installation fails on Python 3.13, possibly because some wheels
  have not yet been updated.
- Qiling for ARM emulation. It is installed by `requirements.txt`.
- The remaining Python packages listed in `requirements.txt`.
- Optional: `make` and the
  [Arm GNU toolchain](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads)
  (`arm-none-eabi`) for building the bundled examples. They are not required
  when simulating your own prebuilt binaries.

## Installation

### Docker

Build the image:

```bash
docker build -t sofa .
```

Run Sofa by passing its normal command-line arguments to the container:

```bash
docker run sofa --input auto --count 10 AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
```

The Docker image also builds the externally supplied RP2350 challenge used in
one of the examples below.

### Local installation

1. Clone the repository:

   ```bash
   git clone https://github.com/GTP95/sofa.git
   cd sofa
   ```

2. Optionally create and activate a virtual environment:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```

   On Windows, activate it with `.venv\Scripts\activate` instead.

3. Verify the Python version:

   ```bash
   python --version
   ```

4. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```

5. Apply the Qiling extension patch described below.

6. If you want to build the examples, install `make` and the
   `arm-none-eabi` toolchain. On Debian-based Linux distributions, install
   `make` with:

   ```bash
   sudo apt-get install make
   ```

### Required Qiling patch

> [!WARNING]
> Sofa currently needs Qiling's development branch and a small `hook_switch`
> extension. The PyPI release is more than two years old at the time of
> writing, so `requirements.txt` installs the development branch. This should
> change once the required functionality is available in a published Qiling
> release.

After installing the dependencies, run the patch script once:

```bash
python sofa/tools/apply_qiling_patch.py
```

Use `python3` instead of `python` on Debian-based Linux or macOS if necessary.
The script copies the contents of `qilingpatch` into the installed
`qiling/extensions` directory. Its location depends on where Qiling is
installed.

The extension was originally proposed upstream in
[Qiling pull request #1500](https://github.com/qilingframework/qiling/pull/1500).
This patch requirement can be removed once that change is merged and
published.

## Quick start

Build the bundled AES firmware:

```bash
make TARGET=AES
```

Then generate ten traces using automatically generated inputs:

```bash
python main.py --input auto --count 10 AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
```

Sofa logs the unique run directory containing the execution traces and
postprocessed power traces. If you use Docker or supply your own binary, skip
the build step.

## Building the bundled firmware

The example firmware must be built before running it. Select AES, KECCAK, or
one of the ASCON implementations:

```bash
make TARGET=AES
make TARGET=KECCAK
make TARGET=ASCON_REF
```

Available ASCON targets are `ASCON_REF`, `ASCON_ARM`, and
`ASCON_PROTECTED`. Building requires the `arm-none-eabi` toolchain.

Specify a platform when needed:

```bash
make TARGET=AES PLATFORM=CW308_STM32F4
```

Build options can customize the firmware and the generated profile. For
example:

```bash
make TARGET=AES PTLEN=32 MODE=CBC KEYSIZE=256 MASKED=1
make TARGET=ASCON_REF PTLEN=64 AD_LEN=0
make TARGET=KECCAK PTLEN=64 FUNC=SHAKE128 OPLEN=64
```

Clean only one bundled example with `make TARGET=AES clean`, or clean all
examples with:

```bash
make clean
```

The general clean target removes build artifacts and generated root-level
profiles for every example under `Targets/` (AES, ASCON, and KECCAK). It does
not clean the separately supplied Raspberry Pi challenge or remove its
profile.

## Simulation profiles

Every simulation needs an ELF binary and a matching JSON profile. The profile
describes the firmware and its emulation; it does not contain per-run values
such as the key, plaintext, nonce, or associated data. Pass the profile path as
the final command-line argument.

Known-good profiles for the bundled targets are in
[`profiles/examples/`](profiles/examples/):

- `AES-CW308_STM32F4.json`
- `KECCAK-CW308_STM32F4.json`
- `ASCON_REF-CW308_STM32F4.json`
- `ASCON_ARM-CW308_STM32F4.json`
- `ASCON_PROTECTED-CW308_STM32F4.json`
- `rpi_challenge.json`

Use these files directly with the default builds. For a custom binary, copy
the closest example and edit the copy so the known-good example remains
unchanged.

### Common profile fields

| Field | Meaning |
|-------|---------|
| `platform` | Qiling MCU platform identifier, such as `stm32f415` or `rp2350`. |
| `target` | Algorithm or firmware target described by the profile. |
| `plaintext_length` | Exact plaintext size expected by the compiled firmware, in bytes. |
| `memory_mappings` | Additional memory regions required during emulation. Addresses and sizes are decimal JSON numbers; `perms` is the Unicorn permission bitmask. |

Algorithm-specific fields describe settings such as the AES key size and
firmware symbols, the KECCAK function, or the ASCON associated-data length and
build parameters. Properties whose names begin with `__` and end in
`_comment` are documentation only and are ignored by Sofa.

For bundled examples, `make` writes a profile for the selected build to the
repository root. These profiles reflect the selected build options, are
temporary and ignored by Git, can be overwritten by a subsequent build, and
are removed by `make clean`. Externally supplied firmware such as the RP2350
challenge does not generate a profile automatically; copy and customize its
example profile instead.

The profile's input lengths, platform, memory mappings, command symbols, and
execution mode must agree with the ELF. A mismatch normally causes an input
validation, symbol lookup, UART, or unmapped-memory error.

> [!TIP]
> Finding the correct memory mappings is usually the most time-consuming part
> of writing a profile because it requires platform-specific documentation.
> An AI agent can help with this work. Always verify the start and end symbols
> for instruction recording yourself so the selected capture window covers
> the operation you intend to analyze. Incorrect settings elsewhere generally
> cause an explicit simulation error rather than a plausible but incorrect
> result.

## Running simulations

Run `main.py` with an input mode, the ELF path, and the matching profile. The
algorithm comes from the profile's `target` field; it is not a separate
command-line argument. Targets with an implementation suffix, such as
`ASCON_PROTECTED`, select the corresponding base algorithm.

Algorithm-specific options are checked against the selected target. For
example, using `--nonce` with an AES profile or `--iv` with an ASCON profile
produces an error listing both the incompatible and valid options.

### AES examples

Run one trace with user-provided values:

```bash
python main.py --input user --key 00112233445566778899aabbccddeeff --plaintext 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff --iv 000102030405060708090a0b0c0d0e0f AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
```

Generate ten traces automatically:

```bash
python main.py --input auto --count 10 AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
```

Select Hamming Weight leakage:

```bash
python main.py --input auto --count 10 --leakage_model HW AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
```

### KECCAK example

```bash
python main.py --input user --plaintext 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff KECCAK-CW308_STM32F4.elf profiles/examples/KECCAK-CW308_STM32F4.json
```

### ASCON example

```bash
python main.py --input user --key 000102030405060708090a0b0c0d0e0f --nonce 101112131415161718191a1b1c1d1e1f --plaintext 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f ASCON_PROTECTED-CW308_STM32F4.elf profiles/examples/ASCON_PROTECTED-CW308_STM32F4.json
```

### Custom ELF example

The following command analyzes the AES implementation from "RP2350 Hacking
Challenge 2." The binary is not included in this repository, so local users
must download and build it first; the Docker image does this automatically.

```bash
python main.py --no_validation --input user --input_format plaintext --key 66b3ca75e02ad9c8abb06c0b2d297fb660ed5c58c9029ec883f9dbcd2a16195d5e75fadfd32acb297ca03930f1ff08c6714d3f79eb3a26cdc9ef28f553983141 --plaintext "00112233445566778899aabbccddeeff" rp2350_hacking_challenge_2/build/rp2350_hacking_challenge_2.elf profiles/examples/rpi_challenge.json
```

### Debug output

Add `--debug` for verbose input parsing, cryptographic operations, Qiling
interactions, AES command registration, and complete UART command payloads:

```bash
python main.py --debug --input user --key "..." --plaintext "..." --iv "..." AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
```

## Input modes

Sofa supports three input modes:

| Mode | Use |
|------|-----|
| `user` | Supply one set of inputs with options such as `--key`, `--plaintext`, `--iv`, `--nonce`, and `--ad`. |
| `auto` | Generate inputs automatically; requires `--count`. |
| `user-csv` | Run one trace for each data row in a CSV file; requires `--path`. |

### CSV input

Pass the CSV file with `--path`. Sofa ignores its first row as a header:

```bash
python main.py --input user-csv --path inputs.csv AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
```

Each remaining row must contain the target inputs in this order:

| Target | CSV columns |
|--------|-------------|
| AES | `Key,Plaintext,IV` (omit `IV` when the profile has `use_iv: false`) |
| ASCON | `Key,Plaintext,Nonce,AD` (omit `AD` when `ad_length` is zero) |
| KECCAK | `Plaintext` |

Values are hexadecimal by default. Use `--input_format plaintext` for
plaintext values. Sofa does not validate CSV rows in this mode, so their
column order and value lengths must match the selected profile and firmware.

## First-order TVLA

Use `--tvla` to run a first-order fixed-versus-random Test Vector Leakage
Assessment. The trace count must be even and at least four:

```bash
python main.py --tvla --count 100 --tvla_seed 1234 AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
```

TVLA implies `--input auto`, so `--input` may be omitted. Explicitly selecting
`user` or `user-csv` is rejected, and TVLA-generated values always use
hexadecimal input format.

By default, Sofa performs conventional non-specific fixed-versus-random
plaintext TVLA. It creates one baseline vector, repeats its plaintext in the
fixed group, varies only plaintext in the random group, and keeps the key, IV,
nonce, and associated data fixed where applicable. Fixed and random rows
alternate. Existing `--key`, `--plaintext`, `--iv`, `--nonce`, and `--ad`
values override the corresponding generated baseline fields, allowing a known
baseline to be combined with seeded generation for unspecified fields.

Use `--tvla_variable` to choose the only value that varies in random rows:

- AES supports `plaintext`, `key`, and `iv` when the profile enables an IV.
- ASCON supports `plaintext`, `key`, `nonce`, and `ad` when `ad_length` is
  nonzero.
- KECCAK supports only `plaintext`.

Inactive variables, such as `iv` for AES-ECB or `ad` for ASCON with
`ad_length: 0`, are rejected. A generated random value that equals the
baseline is regenerated.

Sofa computes the first-order point-wise Welch two-sample statistic from the
combined power samples using sample variances (`ddof=1`) and online Welford
accumulation. A point exceeds the conventional threshold only when
`abs(t) > 4.5`; equality does not count. If both groups have zero variance at
a point, equal means produce zero and different means produce signed infinity,
representing perfect separation in deterministic simulated traces.

TVLA analysis requires at least two balanced traces per group, equal sample
counts, identical PC and window-ID sequences, identical read/write-mask
sequences for the `accessed` register model, and no invalid samples within
declared trace lengths. Sofa reports the first divergent sample and trace pair
instead of truncating or realigning traces.

This is a qualitative leakage indicator, not proof that leakage is exploitable
or that an implementation is secure. It currently analyzes only first-order
combined power. It does not provide higher-order preprocessing, per-register
tests, fixed-vs-fixed classification, independent confirmation runs, or
automatic attribution to instructions, source lines, or registers.

### TVLA output

Every TVLA run adds these files to its run directory:

- `tvla_inputs.csv` records each trace filename, group, tested variable,
  effective seed, and every active algorithm input. This is the reproduction
  manifest.
- `tvla_results.npz` contains `t_scores`, the strict `exceeds_threshold` mask,
  scalar `threshold`, `fixed_count`, `random_count`, reference `pcs` and
  `window_ids`, leakage and register metadata, the tested variable, effective
  seed, and source power-archive name.
- `tvla_plot.html` is a standalone Welch-score plot with lines at +4.5 and
  -4.5 and highlighted crossings. Infinite scores are clipped only in the
  plot and marked separately; the NPZ retains infinity.

In addition, `power_traces.npz` contains a fixed-width Unicode `group_labels`
array (`fixed` or `random`) aligned with `trace_filenames`.

## Output files

Each simulation creates a unique
`Traces-<algorithm>/run-<unique-id>/` directory and logs its path at startup.
Postprocessing reads only the `traces_*.csv` files from that session, so
manifests and older runs with different firmware or input sizes do not affect
the current run.

The main `power_traces.npz` archive contains:

| Entry | Contents |
|-------|----------|
| `arr_0` | Combined power samples. |
| `lengths` | Original sample count for each trace. |
| `read_components`, `write_components` | Per-register diagnostic arrays with shape `(traces, samples, 16)`. |
| `read_masks`, `write_masks` | Register-access masks for each sample. |
| `window_ids`, `pcs` | Capture-window and program-counter diagnostics. |
| `trace_filenames` | Mapping from each archive row to its execution CSV. |
| `register_names`, `selected_registers` | Register metadata. |
| `leakage_model`, `register_model`, `trace_schema`, `capstone_version` | Reproducibility metadata. |

When instruction counts differ, shorter rows have trailing `NaN` values. Use
`arr_0[i, :lengths[i]]` to recover trace `i` without padding. Numeric
diagnostic arrays use the same padding. Metadata does not require pickle.
Per-register diagnostics substantially increase output size; Sofa uses
temporary disk-backed arrays to avoid multiplying peak memory use while
constructing them.

The optional NPY output contains only combined power traces of equal length.

The richer `accessed`-register CSV schema stores pre- and post-execution
register values and read/write masks. Historical CSV files can still be
postprocessed with `register_model="all"`, but they cannot be converted to
`accessed` traces because they lack each instruction's post-state and decoded
access sets.

## Leakage and register models

The default `--register_model accessed` mode uses Capstone 5.0.9 to determine
which architectural registers each executed ARM or Thumb instruction reads
and writes. For instruction *i*, let `R_i` and `W_i` be those sets, and let
`v_i^-` and `v_i^+` be a register's 32-bit value immediately before and after
execution. Sofa computes:

- `ID(i) = sum(v_i^-[r] for r in R_i) + sum(v_i^+[r] for r in W_i)`
- `HW(i) = sum(HW(v_i^-[r]) for r in R_i) + sum(HW(v_i^+[r]) for r in W_i)`
- `HD(i) = sum(HW(v_i^-[r] XOR v_i^+[r]) for r in W_i)`

A register that is both read and written contributes on both sides of ID and
HW. HD models architectural register-bank transitions and therefore considers
only writes; an unchanged write remains an access but contributes zero HD.
Explicit and implicit general-purpose accesses, including stack-pointer
writeback, link-register updates, and PC-relative operands, are included.
Normal sequential PC advancement is excluded.

The selected-register API filters the supported `r0`-`r12`, `sp`, `lr`, and
`pc` set.

`--register_model all` retains Sofa's earlier behavior for comparison and
reproducibility. ID and HW use the pre-state of every selected register. HD
compares every selected register in consecutive pre-instruction states and
therefore has one fewer sample. The `accessed` mode produces one sample per
completed instruction for all three leakage models.

These models are architectural approximations, not calibrated physical CPU
models. They do not model flags as power-bearing state, memory or data buses,
pipeline state, glitches, or register-specific read/write weights. The
emulator still uses flags to decide which instructions execute. Sofa corrects
Capstone's known missing PC metadata for branches, table branches, and ADR.
Accessed capture rejects interrupt or exception-handler execution and
incomplete capture windows instead of silently attributing their state changes
to an instruction.

## How instruction capture works

Sofa computes one power sample per *recorded* instruction, which is not
necessarily every instruction the firmware executes. Qiling executes the
entire program, including startup and UART handling. Sofa records register
state into a CSV trace during the selected interval and then applies the
chosen leakage model to every CSV row.

A useful side-channel trace normally contains the cryptographic operation,
not unrelated startup, protocol, and output code. Excluding that code reduces
noise, avoids execution-to-execution misalignment, and produces smaller
traces. Capture boundaries must therefore describe a temporal execution
window: recording starts when execution reaches the start marker, includes
every subsequently executed instruction—including helper calls at unrelated
addresses—and stops when execution reaches the end marker.

Qiling's standard `hook_code(begin, end)` instead acts as a static address
filter: its callback runs only while the current program counter is numerically
between `begin` and `end`. It can omit helpers outside that range and record
code inside the range when it executes outside the intended invocation. This
semantic mismatch caused incorrect recordings and divergent traces when
intermediate values were compared.

For the historical `all` register model, Sofa's `hook_switch` extension turns
recording on at `begin` and off at `end`, covering the dynamic execution
interval. The default `accessed` recorder implements the same temporal gating
directly because it must observe both pre- and post-execution instruction
state.

## Command-line reference

| Argument | Description |
|----------|-------------|
| `--debug` | Enable verbose debug output. |
| `--input` | Select `user`, `user-csv`, or `auto` input mode. |
| `--no_validation` | Disable validation of user-provided inputs. |
| `--count` | Number of generated inputs; required for `auto` mode. |
| `--path` | Input CSV path; required for `user-csv` mode. |
| `--input_format` | Interpret inputs as `hex` (default) or `plaintext`. |
| `--key` | Cryptographic key for AES or ASCON. |
| `--plaintext` | Plaintext to encrypt, supplied as a hex string by default. |
| `--leakage_model` | Select `ID`, `HW`, or `HD`; defaults to `HD`. |
| `--register_model` | Select `accessed` (default) for instruction operands and results, or `all` for historical all-selected-register behavior. |
| `--iv` | Initialization vector for AES modes that require one. |
| `--nonce` | The 16-byte ASCON public nonce. |
| `--ad` | ASCON associated data when the firmware uses a nonzero `AD_LEN`. |
| `--capacity` | Capacity for the KECCAK sponge function. |
| `--tvla` | Run first-order fixed-versus-random TVLA; implies `--input auto` and requires an even `--count` of at least four. |
| `--tvla_variable` | Input varied in the random TVLA group; defaults to `plaintext`, with availability determined by the profile. |
| `--tvla_seed` | Optional nonnegative 64-bit seed. If omitted, Sofa generates and records an effective seed. |
| `elf_path` | Required path to the ELF file. |
| `config` | Required path to the JSON profile whose `target` selects the algorithm. |

## Benchmarking

Run the bundled benchmarks with:

```bash
python run_benchmarks.py
```

The script builds the AES, ASCON_REF, and KECCAK firmware, then measures 100
automatically generated inputs for each. Compilation is excluded from reported
timings. This requires `make` and the `arm-none-eabi` toolchain. If a build
fails, the script reports its output and stops before running any benchmarks.
Each benchmark invokes `main.py` with the target's matching ELF and example
profile.

## Project background

Sofa is an improved version of ARCHER's ARM variant, also known as ARMChair, a
side-channel power simulator originally developed at Radboud University. To
the best of the maintainer's knowledge, ARMChair's original developer was
Paolo Scattolin.

The inherited version silently failed during its initial UART communication
phase while continuing to generate traces. Those traces covered only UART
communication rather than encryption. Sofa began as a repair of that problem
and later became a separate fork. It now fixes the original failure and adds
support for reusable JSON simulation profiles and additional analysis
features.

### Future plans

- Add more cryptographic algorithms.
- Extend validation to additional cryptographic modes, such as AES-GCM.

## License

Sofa is licensed under the MIT License.
