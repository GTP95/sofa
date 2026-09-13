# Sofa
## A Power Simulator for SCA analysis of ARM binaries

![Sofa](art/CPU.webp)

Sofa aims at identifying architectural leakage for ARM software implementations of cryptographic algorithms.

This is an improved version of ARCHER's ARM variant (also known as ARMChair), a power simulator for side-channel analysis originally developed at 
Radboud University, with the aim of developing a tool that is actually usable in the real world. To the best of my knowledge, 
ARMChair's original developer was Paolo Scattolin. When I first got this tool, it was broken: it silently failed during the 
initial UART communication phase while still generating traces, therefore the generated traces only covered UART communication and not the encryption. 
So I set to work on it to fix it, and later created this fork after leaving Radboud. It now works properly and has more functionalities than the original. 
By using JSON simulation profiles, it is now possible to use this simulator with any binary, provided that its architecture is supported by Qiling. 

### Warning ⚠️

We need to use Qiling's latest version for this to work. Unfortunately, at the moment of writing, the current version on 
PyPI is more than two years old. For this reason, the `requirements.txt` file installs Qiling's dev branch. This can, and 
should, be changed once Qiling's PyPI version gets updated.

Sofa computes one power sample for each *recorded* instruction, not necessarily for every instruction executed by the
firmware. Qiling still executes the whole program, including startup and UART handling. Its instruction hook records the
register state into a CSV trace, then Sofa applies the selected ID, HW, or HD leakage model to each CSV row.

For side-channel analysis, the trace should normally contain the cryptographic operation rather than unrelated startup,
protocol, and output code. This also avoids extra noise, misalignment between executions, and unnecessarily large traces.
The capture boundaries must be a temporal execution window: start recording when execution reaches the start marker, keep
recording every subsequently executed instruction (including calls to helpers at unrelated addresses), and stop when
execution reaches the end marker.

Qiling's standard `hook_code(begin, end)` has different semantics. It is a static address filter: the callback runs only
when the current program counter lies numerically between `begin` and `end`. Consequently, it can omit helper routines
called from the operation when their code lies outside that address range, and it can record code in the range whenever it
runs, even outside the intended invocation. This mismatch caused incorrect recordings and divergent traces when
intermediate values were compared.

For the historical `all` register model, Sofa therefore uses a small `hook_switch` extension. It switches recording on
when the program counter reaches `begin` and off when it reaches `end`, so the callback covers the dynamic execution
interval rather than an address interval. The default `accessed` recorder implements the same temporal gating directly,
because it must observe both the pre- and post-execution state of each instruction. This extension was originally proposed
upstream in the Qiling project: https://github.com/qilingframework/qiling/pull/1500.

To fix the issue, after installing `qiling`, make sure to run the script `apply_qiling_patch.py` at least once before running Sofa.

- **On Windows**:
   - Run the following command in **Command Prompt** or **PowerShell**:
     ```
     python sofa/tools/apply_qiling_patch.py
     ```

- **On Debian-based Linux distros or macOS**:
   - Run the following command in the terminal:
     ```bash
     python3 sofa/tools/apply_qiling_patch.py
     ```

- **On Arch-based Linux distros, and any distro where the previous command fails**:
    - Run the following command in the terminal:
      ```bash
            python sofa/tools/apply_qiling_patch.py
      ```

This will copy the content of the `qilingpatch` folder into the `qiling/extensions` directory. The location of this directory will depend on where your `qiling` package is installed.

This whole section will be removed once the change is merged and published in the Qiling package.

### Overview

Sofa is a cryptographic analysis tool designed to simulate, test, and validate cryptographic algorithms such as AES, ASCON, 
and KECCAK on embedded systems using the Qiling framework. It supports multiple stages, including firmware compilation, 
simulation, and cryptographic analysis.

Sofa begins by building the project using `make` before executing Python scripts for the cryptographic simulation and analysis.

### Features

- **Support for multiple cryptographic algorithms:** AES, ASCON, KECCAK.
- **Support for multiple leakage models:** Identity (ID), Hamming Weight (HW), Hamming Distance (HD).
- **User-provided or auto-generated input modes** for cryptographic testing.
- **Integration with Qiling** for ARM-based platform simulation.
- **Compilation of firmware using multiple Makefiles** to support diverse platforms and algorithms.
- **Customizable input validation and padding for cryptographic algorithms.**
- **First-order fixed-versus-random TVLA** with reproducible, balanced input generation and point-wise Welch scores.

#### Clarification on leakage models

By default, `--register_model accessed` uses Capstone 5.0.9 to determine the architectural registers read and written by
each executed ARM/Thumb instruction. For instruction *i*, let `R_i` and `W_i` be those sets, and let `v_i^-` and `v_i^+`
be a register's 32-bit value immediately before and after execution. Sofa computes:

- `ID(i) = sum(v_i^-[r] for r in R_i) + sum(v_i^+[r] for r in W_i)`
- `HW(i) = sum(HW(v_i^-[r]) for r in R_i) + sum(HW(v_i^+[r]) for r in W_i)`
- `HD(i) = sum(HW(v_i^-[r] XOR v_i^+[r]) for r in W_i)`

A register that is both read and written contributes on both sides of ID and HW. HD models architectural register-bank
transitions and therefore considers writes only; an unchanged write is still an access but contributes zero HD. Explicit
and implicit general-purpose accesses such as stack-pointer writeback, link-register updates, and PC-relative operands are
included. Normal sequential PC advancement is excluded. The selected-register API remains a filter over the supported
`r0`-`r12`, `sp`, `lr`, and `pc` set.

`--register_model all` retains Sofa's previous behavior for comparison and reproducibility: ID and HW use the pre-state of
every selected register, while HD compares every selected register in consecutive pre-instruction states and consequently
has one fewer sample. `accessed` produces one sample per completed instruction for all three leakage models.

This is an architectural approximation, not a calibrated physical CPU model. It does not model flags as power-bearing
state, memory/data buses, pipeline state, glitches, or register-specific read/write weights. Flags are still used by the
emulator to decide which instructions execute. Capstone's known missing PC metadata for branches, table branches, and ADR
is corrected by Sofa. Accessed capture rejects interrupt/exception-handler execution and incomplete capture windows rather
than silently attributing their state changes to an instruction.

### Requirements (can be ignored if using the Docker image)

- Python 3.10 or higher (for compatibility with some of the libraries used). **Tested on Python 3.12**.  
    **At the time of writing, dependency installation fails on Python 3.13**, but it could be due to outdated wheels that may be updated in the future.
- Qiling for ARM emulation.
- Required Python packages (installable via `requirements.txt`).
- Optional: the `make` build system and the [arm-none-eabi](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads) toolchain for building the default targets. Without this, you will not be able to run the examples,
but you can still run simulations with your own binaries.

### Installation

#### Bare metal
1. Clone the repository:

   ```bash
   git clone https://github.com/GTP95/sofa.git
   cd sofa
   ```
   
    1. Recommended but not mandatory: create and activate a Python virtual environment:
        
        ```bash
        python -m venv venv
        source venv/bin/activate  # On Windows use `venv\Scripts\activate`
        ```
       
2. Verify that you are using Python 3.10 or higher:

   ```bash
   python --version
   ```


3. Install the required dependencies using the provided `requirements.txt`:

   ```bash
   pip install -r requirements.txt
   ```
    1. If there's still a warning at the top of this README, apply the mentioned patch.



4. Optional: install `make` for your platform if it isn't already installed. On Debian-based Linux distributions, you can install it using:

   ```bash
   sudo apt-get install make
   ```
    1. Install the [arm-none-eabi](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads) toolchain.

#### Docker
You can build this Docker image with:
``` bash
docker build -t sofa .
```
And run it with various arguments, for example:
``` bash
docker run sofa --input auto --count 10 AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
```
See the [Usage](#usage) section for more details on how to run the tool.

### Usage

Before running the **example** cryptographic analyses, **build the project** using `make`. This is necessary for preparing the firmware 
and associated cryptographic targets.

#### Step 1: Building the Project (go to step 2 if using Docker, or if you want to analyze your own binary)

The build system is managed using multiple Makefiles. Start by building the example project with the appropriate target, which
can be AES, ASCON, or KECCAK. 
You will need the `arm-none-eabi` toolchain.

```bash
make TARGET=AES
```

You can also build for ASCON or KECCAK by adjusting the `TARGET` parameter:

```bash
make TARGET=KECCAK
```
For ASCON, you need to choose a target between ASCON_REF, ASCON_ARM, and ASCON_PROTECTED.

The `Makefile` also provides options for cleaning the build or compiling for specific platforms.
Running `make clean` removes the build artifacts and generated root-level
profiles for every example bundled under `Targets/` (AES, ASCON, and KECCAK).
It does not clean the separately supplied Raspberry Pi challenge or remove its
profile. To clean only one bundled example, pass it explicitly, for example
`make TARGET=AES clean`.

- **To clean the project:**

    ```bash
    make clean
    ```

- **To specify the platform (e.g., CW308_STM32F4):**

    ```bash
    make TARGET=AES PLATFORM=CW308_STM32F4
    ```

#### Step 2: Writing or Selecting a Profile

Sofa needs a JSON profile in addition to the ELF file. The profile describes some firmware's aspects and how it should be emulated; it does not contain the key, plaintext, nonce, or other per-run input. Pass its path as the final command-line argument in Step 3.

Example profiles for the bundled targets are available in [`profiles/examples/`](profiles/examples/):

- `AES-CW308_STM32F4.json`
- `KECCAK-CW308_STM32F4.json`
- `ASCON_REF-CW308_STM32F4.json`
- `ASCON_ARM-CW308_STM32F4.json`
- `ASCON_PROTECTED-CW308_STM32F4.json`
- `rpi_challenge.json`

Use these files directly for the default builds. To create a profile for a custom binary, copy the closest example to a new file and adjust it to match the binary. Keep the example itself unchanged so it remains a known-good reference.

Every profile contains these common fields:

| Field | Meaning |
|-------|---------|
| `platform` | Qiling MCU platform identifier, such as `stm32f415` or `rp2350`. |
| `target` | Algorithm or firmware target described by the profile. |
| `plaintext_length` | Exact plaintext size expected by the compiled firmware, in bytes. |
| `memory_mappings` | Additional memory regions required during emulation. Addresses and sizes are decimal JSON numbers; `perms` is the Unicorn permission bitmask. |

Algorithm-specific fields describe details such as the AES key size and firmware symbols, the KECCAK function, or the ASCON associated-data length and build parameters. The `__..._comment` properties are documentation only and are ignored by Sofa.

For the bundled examples, `make` also writes a profile for the selected build to the repository root. Build options are reflected in that generated file; for example:

```bash
make TARGET=AES PTLEN=32 MODE=CBC KEYSIZE=256 MASKED=1
make TARGET=ASCON_REF PTLEN=64 AD_LEN=0
make TARGET=KECCAK PTLEN=64 FUNC=SHAKE128 OPLEN=64
```

These root-level profiles are temporary and ignored by Git. A subsequent build can overwrite them, and `make clean` removes them. Externally supplied firmware such as the RP2350 challenge does not generate a profile automatically, so start from the corresponding example when customization is needed.

Whichever profile you use, its input lengths, platform, memory mappings, command symbols, and execution mode must agree with the ELF. A mismatch will usually cause input validation, symbol lookup, UART, or unmapped-memory errors.

**Practical tip:** the most tedious part of writing a profile is likely figuring out the correct memory mappings, as it usually requires to find and go through some platform-specific documentation. However, an AI agent can do this for you. The only thing you have to double check is that the start and and symbols for the instruction recording are correct, i.e. check that it selected the portion of the execution you're actually interested in. A mistake in any other profile's setting will just result in an error during the simulation rather than a wrong result, so there's no risk.

#### Step 3: Running the Python Cryptographic Simulation

Once the firmware and matching profile are ready, run the cryptographic analysis invoking `main.py`. Sofa supports both user-provided and auto-generated inputs.
The cryptographic algorithm is selected from the profile's `target` field; it is
not specified separately on the command line. Targets with an implementation
suffix, such as `ASCON_PROTECTED`, select the corresponding base algorithm.
Algorithm-specific options are checked against that selection. For example,
passing `--nonce` with an AES profile or `--iv` with an ASCON profile produces
an error that lists both the incompatible and valid options.

Each simulation writes its execution traces and `power_traces.npz` to a new
`Traces-<algorithm>/run-<unique-id>/` directory, whose path is logged at startup.
Postprocessing uses only `traces_*.csv` from that session, so manifests and
previous runs with different input sizes or firmware can remain on disk without
affecting the current run.
The NPZ archive stores power samples in `arr_0` and original sample counts in
`lengths`. When instruction counts differ, shorter rows have trailing `NaN`
values; use `arr_0[i, :lengths[i]]` to recover a trace without padding. It also
stores `read_components` and `write_components` with shape
`(traces, samples, 16)`, plus `read_masks`, `write_masks`, `window_ids`, and
`pcs`. Numeric diagnostic arrays use the same `NaN` padding. `register_names`,
`selected_registers`, `leakage_model`, `register_model`, `trace_schema`, and
`capstone_version` describe the archive without requiring pickle, while
`trace_filenames` maps each archive row back to its execution CSV. Per-register
diagnostics increase output size substantially; temporary disk-backed arrays
keep their construction from multiplying peak RAM use. The optional NPY output
contains only combined, equal-length power traces.

In TVLA runs, `power_traces.npz` additionally contains a fixed-width Unicode
`group_labels` array (`fixed` or `random`) aligned with `trace_filenames`.

The richer accessed-register CSV schema contains pre/post register values and
read/write masks. Historical CSV files can still be postprocessed with
`register_model="all"`; they cannot be converted to `accessed` traces because
they do not contain each instruction's post-state or decoded access sets.

##### Command-Line Arguments

| Argument          | Description                                                                                                                            |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| `--debug`         | Enable debug mode for verbose output.                                                                                                  |
| `--input`         | Choose between `user`, `user-csv`, or `auto` input mode.                                                                               |
| `--no_validation` | Disable input validation for user-provided inputs.                                                                                     |
| `--count`         | Number of auto-generated inputs (required for `auto` mode).                                                                            |
| `--path`          | Path to the input .csv file (required for user-csv mode).                                                                              |
| `--input_format`  | Interpret inputs as `hex` (the default) or `plaintext`.                                                                                |
| `--key`           | The cryptographic key for `AES` or `ASCON`.                                                                                            |
| `--plaintext`     | The plaintext (hex string) to encrypt.                                                                                                 |
| `--leakage_model` | Leakage model to use for the analysis. Either `ID`, `HW`, or `HD`.<br/>Defaults to `HD`.                                               |
| `--register_model` | Register selection model: `accessed` (the default) uses only instruction operands/results; `all` retains the historical all-selected-register behavior. |
| `--iv`            | Initialization vector for AES modes that require one.                                                                                  |
| `--nonce`         | The 16-byte ASCON public nonce.                                                                                                        |
| `--ad`            | Optional ASCON associated data when the firmware was built with a nonzero `AD_LEN`.                                                    |
| `--capacity`      | Capacity for `KECCAK` sponge function.                                                                                                 |
| `--tvla`          | Run first-order fixed-versus-random TVLA; implies `--input auto` and requires an even `--count` of at least 4.                         |
| `--tvla_variable` | Input varied in the random group. Defaults to `plaintext`; availability depends on the selected profile.                              |
| `--tvla_seed`     | Optional nonnegative 64-bit seed. If omitted, Sofa generates and records an effective seed.                                              |
| `elf_path`        | Path to the .elf file (this is a mandatory positional argument).                                                                       |
| `config`          | Path to the JSON profile whose `target` field selects the algorithm (this is a mandatory positional argument).                         |

##### Example 1: Running bundled AES implementation with user-provided input

This will generate a single encryption trace using user-provided parameters.
```bash
python main.py --input user --key 00112233445566778899aabbccddeeff --plaintext 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff --iv 000102030405060708090a0b0c0d0e0f AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
```

##### Example 2: Running bundled AES implementation with auto-generated inputs

This will generate multiple encryption traxces using randomly generated parameters.
```bash
python main.py --input auto --count 10 AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
```

##### Example 3: Running bundled AES implementation with auto-generated inputs and a specific leakage model

```bash
python main.py --input auto --count 10 --leakage_model "HW" AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
```

##### Benchmarking the bundled implementations

Run `python run_benchmarks.py` to build the AES, ASCON_REF, and KECCAK firmware
and then measure 100 auto-generated inputs for each. Compilation is not part of
the reported benchmark timings. This requires `make` and the `arm-none-eabi`
toolchain; if a build fails, the script reports its output and stops before any
benchmark runs. Each benchmark invokes `main.py` with the target's matching ELF
file and example profile.

##### First-order TVLA

Use `--tvla` with an even trace count of at least four. `--input` may be omitted
because TVLA implies `--input auto`; explicitly selecting `user` or `user-csv`
is rejected. TVLA-generated values always use hexadecimal input format.

```bash
python main.py --tvla --count 100 --tvla_seed 1234 AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
```

The default is conventional non-specific fixed-versus-random plaintext TVLA.
Sofa generates one baseline vector, repeats its plaintext in the fixed group,
varies only plaintext in the random group, and keeps the key, IV, nonce, and
associated data fixed as applicable. Fixed and random rows alternate. Existing
`--key`, `--plaintext`, `--iv`, `--nonce`, and `--ad` values override their
corresponding generated baseline fields, so a run can combine a known baseline
with seeded generation for unspecified fields.

`--tvla_variable` can instead select the only input varied in random rows:

- AES supports `plaintext`, `key`, and `iv` when the profile enables an IV.
- ASCON supports `plaintext`, `key`, `nonce`, and `ad` when `ad_length` is nonzero.
- KECCAK supports only `plaintext`.

Inactive variables, such as `iv` for AES-ECB or `ad` for an ASCON profile with
`ad_length: 0`, are rejected. A generated random value that happens to equal
the baseline is regenerated.

Every TVLA run writes these additional files in its run directory:

- `tvla_inputs.csv` records each trace filename, its group, tested variable,
  effective seed, and all active algorithm inputs. This is the reproduction
  manifest.
- `tvla_results.npz` contains `t_scores`, the strict `exceeds_threshold` mask,
  scalar `threshold`, `fixed_count`, and `random_count`, reference `pcs` and
  `window_ids`, leakage/register metadata, tested variable, effective seed,
  and the source power-archive name.
- `tvla_plot.html` is a standalone plot of Welch score versus sample index,
  with lines at +4.5 and -4.5 and highlighted crossings. Infinite scores are
  clipped only in the plot and marked separately; the NPZ retains infinity.

Sofa calculates the first-order point-wise Welch two-sample statistic from the
combined power samples, using sample variances (`ddof=1`) and online Welford
accumulation. A sample exceeds the conventional threshold only when
`abs(t) > 4.5`; equality does not count. If both groups have zero variance at a
sample, equal means produce zero and different means produce signed infinity,
which represents perfect separation in deterministic simulated traces.

TVLA analysis is deliberately strict: it requires at least two balanced traces
per group, equal sample counts, identical PC and window-ID sequences, identical
read/write-mask sequences for the `accessed` register model, and no invalid
samples inside declared trace lengths. Sofa reports the first divergent sample
and trace pair rather than truncating or realigning traces.

This mode is a qualitative leakage indicator, not proof that leakage is
exploitable or that an implementation is secure. It currently analyzes only
first-order combined power. It does not provide higher-order preprocessing,
per-register tests, fixed-vs-fixed classification, independent confirmation
runs, or automatic attribution to instructions, source lines, or registers.

##### Example 4: Running bundled KECCAK implementation with user-provided input

```bash
python main.py --input user --plaintext "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" KECCAK-CW308_STM32F4.elf profiles/examples/KECCAK-CW308_STM32F4.json
```

##### Example 5: Running bundled ASCON implementation with user-provided input

```bash
python main.py --input user --key 000102030405060708090a0b0c0d0e0f --nonce 101112131415161718191a1b1c1d1e1f --plaintext 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f ASCON_PROTECTED-CW308_STM32F4.elf profiles/examples/ASCON_PROTECTED-CW308_STM32F4.json
```

##### Example 6: Running a user-provided ELF executable (in this case, "RP2350 Hacking Challenge 2" 's AES implementation)
Note that this is not included in this repository, you will have to download and build it yourself. The Docker image does this for you.
```bash
python main.py --no_validation --input user --input_format plaintext --key 66b3ca75e02ad9c8abb06c0b2d297fb660ed5c58c9029ec883f9dbcd2a16195d5e75fadfd32acb297ca03930f1ff08c6714d3f79eb3a26cdc9ef28f553983141 --plaintext "00112233445566778899aabbccddeeff" rp2350_hacking_challenge_2/build/rp2350_hacking_challenge_2.elf profiles/examples/rpi_challenge.json
```

### Supported Cryptographic Algorithms

- **AES** (Advanced Encryption Standard): Supports key, IV, and plaintext input for both user-provided and auto-generated modes.
- **ASCON**: Supports key, nonce, plaintext, and optional associated-data input.
- **KECCAK**: Supports key, plaintext, and sponge capacity input.

### Debug Mode

Enable debug mode using the `--debug` flag to get verbose output of all operations, including input parsing, cryptographic operations, Qiling interactions, AES command registration, and full UART command payloads:

```bash
python main.py --debug --input user --key "..." --plaintext "..." --iv "..." AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
```

### Future Plans

- Expand support for additional cryptographic algorithms.
- Implement more advanced input generation techniques.
- Extend validation to more cryptographic modes (e.g., GCM for AES).

### License

This project is licensed under the MIT License.
