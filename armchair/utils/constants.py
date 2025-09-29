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

# region: magic constants
# Optimized simulation relies on these constants. Don't change them unless you fully understand what you are doing.
# After a change, do extensive regression tests. You have been warned.
optimized_magics=[67, 70, 85, 70, 69, 81, 103, 105, 40, 54, 42, 130, 113, 45, 126, 129, 127, 134, 118, 127, 141, 53, 134,
                  140, 122, 133, 131, 142, 132, 61, 140, 142, 142, 78, 153, 146, 150, 144, 143, 149, 143, 73, 157, 154,
                  146, 161, 165, 144, 162, 150, 96, 83, 118, 154, 153, 152, 173, 172, 159, 91, 179, 162, 101, 177, 165,
                  97, 180, 168, 183, 170, 167, 185, 171, 177, 175, 189, 191, 121, 110, 189, 191, 197, 114, 183, 185, 203,
                  187, 195, 199, 201, 191, 205, 207, 126, 126, 174, 198, 129, 197, 210, 217, 215, 217, 204, 148, 137, 206,
                  208, 226, 210, 218, 222, 224, 218, 224, 218, 148, 233, 229, 230, 228, 236, 154, 228, 239, 235, 165, 243,
                  32, 98, 34, 117, 105, 120, 107, 104, 122, 108, 114, 112, 126, 52, 129, 47, 125, 114, 123, 129, 52, 137,
                  119, 138, 131, 69, 58, 107, 139, 96, 145, 63, 129, 147, 135, 67, 138, 142, 148, 140, 86, 73, 107, 75, 124,
                  156, 113, 79, 153, 164, 82, 160, 153, 150, 164, 171, 88, 173, 169, 91, 175, 165, 173, 182, 96, 181, 170,
                  164, 184, 101, 167, 181, 104, 178, 174, 176, 173, 109, 197, 190, 194, 188, 197, 127, 116, 182, 196, 187,
                  120, 189, 201, 192, 207, 203, 133, 211, 128, 207, 199, 200, 200, 133, 218, 214, 136, 203, 207, 139, 205,
                  141, 222, 222, 220, 218, 229, 219, 217, 217, 150, 235, 231, 232, 230, 169, 156, 191, 243, 243, 32, 106,
                  104, 35, 120, 109, 107, 39, 88, 120, 77, 43, 117, 129, 129, 116, 124, 119, 50, 119, 131, 122, 137, 133,
                  63, 141, 58, 146, 139, 143, 137, 75, 64, 149, 138, 136, 146, 69, 157, 143, 137, 157, 74, 148, 159, 77,
                  151, 163, 80, 146, 149, 167, 169, 150, 162, 163, 177, 89, 170, 173, 171, 179, 167, 173, 167, 128, 98,
                  150, 169, 170, 102, 168, 180, 188, 185, 107, 180, 193, 194, 191, 195, 139, 129, 130, 200, 190, 196, 208,
                  205, 203, 198, 137, 191, 204, 203, 142, 213, 207, 197, 154, 152, 199, 154, 153]

# endregion