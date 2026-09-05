
## Sofa: a Power Simulator for SCA analysis of ARM binaries

![Sofa](art/CPU.webp)

Sofa aims at identifying architectural leakage for ARM software implementations of cryptographic algorithms.

This is an improved version of ARCHER's ARM variant (also known as ARMChair), a power simulator for side-channel analysis originally developed at 
Radboud University, with the aim of developing a tool that is actually usable in the real world. To the best of my knowledge, 
ARMChair's original developer was Paolo Scattolin. When I first got this tool, it was broken: it silently failed during the 
initial UART communication phase, so the generated traces only covered UART communication and not the encryption. So I set
to work on it to fix it. It now works properly and has more functionalities than the original. By using JSON simulation profiles,
it is now possible to use this simulator with any binary, provided that its architecture is supported by Qiling. 

### Warning ⚠️

We need to use Qiling's latest version for this to work. Unfortunately, at the moment of writing, the current version on 
PyPI is more than two years old. For this reason, the `requirements.txt` file installs Qiling's dev branch. This can, and 
should, be changed once Qiling's PyPI version gets updated.

There is currently a critical bug that prevents the right instructions from being recorded. In particular, we were seeing 
different branching while comparing traces simulated by Sofa, leading to an incorrect intersection of the intermediates.

Basically, the `hook_code` function in Qiling wasn't working in the way that Scattolin was expecting. He assumed that he 
could define a `begin` and `end` using memory addresses and that the hook would be called from when we hit the start until we hit the end. 

The way that hook actually works is by checking if the program counter is in between the `begin` and the end of the memory 
space that you ask for, plus a couple of minor checks that are not relevant. The result is that by defining a range, he 
was recording the registers any time that some instruction in the code under test would have been in that range. This led 
to a bunch of odd recordings that should not have been there.

He fixed this by creating his own hook that is currently (last checked on 5/9/26) being reviewed in the Qiling repo: https://github.com/qilingframework/qiling/pull/1500.

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

#### Clarification on leakage models
Under the identity (ID) model, the power consumption of each instruction is computed as the sum of the values of *all* the registers.  
Under the Hamming weight (HW) model, the power consumption of each instruction is computed as the sum of the Hamming weights of *all* registers' values.  
Under the Hamming distance (HD) model, the power consumption of each instruction is computed as the sum of the Hamming distances of *all* the registers between their value in the current state and their value in the next state.  

This implementation *does not* differentiate between registers that are accessed by the current instruction and those that aren't. 
Therefore, the generated power traces are usable for statistical testing to find data-dependent leakage, but aren't an accurate 
power simulation on their own.

### Requirements (can be ignored if using the Docker image)

- Python 3.10 or higher (for compatibility with some of the libraries used). **Tested on Python 3.12**.  
    **At the time of writing, dependency installation fails on Python 3.13**, but it could be due to outdated wheels that may be updated in the future.
- The `make` build system (required for compiling the firmware).
- Qiling for ARM emulation.
- Required Python packages (installable via `requirements.txt`).
- Optional: [arm-none-eabi](https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads) toolchain for building the default targets. Without this, you will not be able to run the examples,
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



4. Install `make` for your platform if it isn't already installed. On Debian-based Linux distributions, you can install it using:

   ```bash
   sudo apt-get install make
   ```

#### Docker
You can build this Docker image with:
``` bash
docker build -t sofa .
```
And run it with various arguments, for example:
``` bash
docker run sofa --input auto --count 10 AES AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
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

- **To clean the project:**

    ```bash
    make clean
    ```

- **To specify the platform (e.g., CW308_STM32F4):**

    ```bash
    make TARGET=AES PLATFORM=CW308_STM32F4
    ```

#### Step 2: Writing or Selecting a Profile

Sofa needs a JSON profile in addition to the ELF file. The profile describes how the firmware was built and emulated; it does not contain the key, plaintext, nonce, or other per-run input. Pass its path as the final command-line argument in Step 3.

Stable profiles for the bundled targets are available in [`profiles/examples/`](profiles/examples/):

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

For ASCON and KECCAK, `make` also writes a profile for the selected build to the repository root. Build options are reflected in that generated file; for example:

```bash
make TARGET=ASCON_REF PTLEN=64 AD_LEN=0
make TARGET=KECCAK PTLEN=64 FUNC=SHAKE128 OPLEN=64
```

These root-level profiles are temporary and ignored by Git. A subsequent build can overwrite them, and `make clean` removes them. AES and externally supplied firmware such as the RP2350 challenge do not generate complete profiles automatically, so start from the corresponding example when customization is needed.

Whichever profile you use, its input lengths, platform, memory mappings, command symbols, and execution mode must agree with the ELF. A mismatch will usually cause input validation, symbol lookup, UART, or unmapped-memory errors.

#### Step 3: Running the Python Cryptographic Simulation

Once the firmware and matching profile are ready, run the cryptographic analysis using `main.py`. Sofa supports both user-provided and auto-generated inputs.

Each simulation writes its execution traces and `power_traces.npz` to a new
`Traces-<algorithm>/run-<unique-id>/` directory, whose path is logged at startup.
Postprocessing uses only that session's traces, so previous runs with different
input sizes or firmware can remain on disk without affecting the current run.
The NPZ archive stores power samples in `arr_0` and original sample counts in
`lengths`. When instruction counts differ, shorter rows have trailing `NaN`
values; use `arr_0[i, :lengths[i]]` to recover a trace without padding.

##### Command-Line Arguments

| Argument          | Description                                                                                                                            |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| `--debug`         | Enable debug mode for verbose output.                                                                                                  |
| `--input`         | Choose between `user`, `user-csv`, `user-raw`, or `auto` input mode.                                                                   |
| `--no_validation` | Disable input validation for user-provided inputs.                                                                                     |
| `--count`         | Number of auto-generated inputs (required for `auto` mode).                                                                            |
| `--path`          | Path to the input .csv file (required for user-csv mode).                                                                              |
| `--input_format`  | Interpret inputs as `hex` (the default) or `plaintext`.                                                                                |
| `--key`           | The cryptographic key for `AES` or `ASCON`.                                                                                            |
| `--plaintext`     | The plaintext (hex string) to encrypt.                                                                                                 |
| `--leakage_model` | Leakage model to use for the analysis. Either `ID`, `HW`, or `HD`.<br/>Defaults to `HD`.                                               |
| `--iv`            | Initialization vector for AES modes that require one.                                                                                  |
| `--nonce`         | The 16-byte ASCON public nonce.                                                                                                        |
| `--ad`            | Optional ASCON associated data when the firmware was built with a nonzero `AD_LEN`.                                                    |
| `--capacity`      | Capacity for `KECCAK` sponge function.                                                                                                 |
| `algorithm`       | Choose the cryptographic algorithm. Currently supported choices are `AES`, `ASCON`, `KECCAK`.                                          |
| `elf_path`        | Path to the .elf file (this is a mandatory positional argument).                                                                       |
| `config`          | Path to the JSON configuration file (this is a mandatory positional argument).                                                         |

##### Example 1: Running bundled AES implementation with user-provided input

This will generate a single encryption trace using user-provided parameters.
```bash
python main.py --input user AES --key 00112233445566778899aabbccddeeff --plaintext 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff --iv 000102030405060708090a0b0c0d0e0f AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
```

##### Example 2: Running bundled AES implementation with auto-generated inputs

This will generate multiple encryption traxces using randomly generated parameters.
```bash
python main.py --input auto --count 10 AES AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
```
Note the ordering of the arguments. The `--input` and `--count` arguments must be specified before the cryptographic algorithm.
This is due to AES being a subcommand.

##### Example 3: Running bundled AES implementation with auto-generated inputs and a specific leakage model

```bash
python main.py --input auto --count 10 --leakage_model "HW" AES AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
```

##### Example 4: Running bundled KECCAK implementation with user-provided input

```bash
python main.py --input user KECCAK --plaintext "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" KECCAK-CW308_STM32F4.elf profiles/examples/KECCAK-CW308_STM32F4.json
```

##### Example 5: Running bundled ASCON implementation with user-provided input

```bash
python main.py --no_validation --input user ASCON --key 000102030405060708090a0b0c0d0e0f --nonce 101112131415161718191a1b1c1d1e1f --plaintext 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f ASCON_PROTECTED-CW308_STM32F4.elf profiles/examples/ASCON_PROTECTED-CW308_STM32F4.json
```

##### Example 6: Running a user-provided ELF executable (in this case, "RP2350 Hacking Challenge 2" 's AES implementation)
Note that this is not included in this repository, you will have to download and build it yourself. The Docker image does this for you.
```bash
python main.py --no_validation --input user --input_format plaintext AES --key 66b3ca75e02ad9c8abb06c0b2d297fb660ed5c58c9029ec883f9dbcd2a16195d5e75fadfd32acb297ca03930f1ff08c6714d3f79eb3a26cdc9ef28f553983141 --plaintext "00112233445566778899aabbccddeeff" rp2350_hacking_challenge_2/build/rp2350_hacking_challenge_2.elf profiles/examples/rpi_challenge.json
```

### How It Works

1. **Makefile-based Firmware Compilation**: 
   The project starts with a `make` build that compiles the cryptographic firmware, producing ELF binaries based on the selected cryptographic algorithm and platform. For supported targets, the build also generates a matching runtime profile.

2. **Session Setup**:
   After the build process, the Python scripts handle the session setup. It parses the command-line arguments and ensures that inputs (either user-provided or auto-generated) are ready for use in cryptographic analysis.

3. **Qiling Integration**: 
   The Qiling framework emulates the target ARM platform and executes the compiled firmware, allowing detailed tracing of cryptographic operations, including input/output and disassembly of ARM instructions.

4. **Cryptographic Analysis**: 
   Sofa generates traces of the encryption process, useful for debugging or cryptographic analysis, including side-channel resistance.

### Supported Cryptographic Algorithms

- **AES** (Advanced Encryption Standard): Supports key, IV, and plaintext input for both user-provided and auto-generated modes.
- **ASCON**: Supports key, nonce, plaintext, and optional associated-data input.
- **KECCAK**: Supports key, plaintext, and sponge capacity input.

### Debug Mode

Enable debug mode using the `--debug` flag to get verbose output of all operations, including input parsing, cryptographic operations, and Qiling interactions:

```bash
python main.py --debug --input user AES --key "..." --plaintext "..." --iv "..." AES-CW308_STM32F4.elf profiles/examples/AES-CW308_STM32F4.json
```

### Future Plans

- Expand support for additional cryptographic algorithms.
- Implement more advanced input generation techniques.
- Extend validation to more cryptographic modes (e.g., GCM for AES).

### License

This project is licensed under the MIT License.
