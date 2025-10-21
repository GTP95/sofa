#TODO: this file should go. Either convert it to a proper config file or get rid of this entirely.
# I already moved some parameters to the JSON settings file.

DEFAULT_INPUT_CSV_PATH = "input-csv.csv"

DEFAULT_NR_OF_INPUTS = 10

RNG_BASE = 0x50060800
"""
RNG_BASE (int): The base address for the RNG (Random Number Generator) peripheral memory.
This address is valid for several STM32F4 models, including:
- stm32f405
- stm32f407
- stm32f415
- stm32f417
"""

RNG_SIZE = 0x400  # 1024 bytes
"""
RNG_SIZE (int): The size of the RNG peripheral memory in bytes.
For these STM32 models, the RNG memory range spans 1024 bytes.
"""

PLATFORM = "CW308_STM32F4"
"""
PLATFORM (str): The platform name used by the configuration, representing the target hardware.
In this case, it is 'CW308_STM32F4', which is commonly used for testing with STM32F4 microcontrollers on the CW308 platform.
"""

# Where the traces are going to be saved
TRACESPATH = "Traces"
"""
TRACESPATH (str): The directory where generated traces from the execution (e.g., power traces, side-channel data) will be saved.
"""

MAX_ATTEMPTS = 3
"""
MAX_ATTEMPTS (int): The maximum number of attempts that Qiling will make when trying to communicate with the C code it is running.
If communication fails after this number of attempts, it will stop the process or raise an error.
"""

# region: AES constants

AES_BLOCK_SIZE = 16
"""
AES_BLOCK_SIZE (int): The block size for AES encryption in bytes. The AES block size is fixed at 16 bytes (128 bits).
"""

# endregion

# region: ASCON constants

ASCON_BLOCK_SIZE = 8
ASCON_KEY_SIZE = 16
ASCON_NONCE_SIZE = 16

# endregion

