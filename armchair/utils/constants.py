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
                  187, 195, 199, 201, 191, 205, 207, 126, 126, 161, 213, 213, 130, 218, 197, 206, 218, 147, 136, 209, 217,
                  226, 140, 214, 225, 143, 217, 229, 146, 231, 220, 214, 234, 151, 236, 225, 227, 238, 156, 244, 237, 241,
                  107, 116, 34, 119, 108, 106, 116, 70, 40, 75, 111, 110, 109, 130, 129, 116, 60, 49, 115, 121, 136, 122,
                  136, 55, 122, 126, 131, 137, 131, 61, 138, 132, 134, 149, 66, 140, 146, 69, 135, 71, 150, 152, 152, 88,
                  163, 156, 160, 154, 153, 159, 153, 83, 167, 169, 151, 171, 157, 89, 160, 170, 174, 93, 177, 174, 173,
                  166, 98, 183, 173, 178, 171, 115, 104, 188, 185, 184, 177, 188, 188, 180, 112, 189, 183, 180, 202, 190,
                  196, 190, 120, 205, 194, 192, 124, 201, 191, 193, 128, 216, 209, 213, 207, 202, 202, 135, 215, 215, 138,
                  209, 213, 229, 215, 221, 215, 145, 211, 225, 216, 149, 223, 228, 232, 235, 233, 241, 229, 235, 229, 159,
                  105, 117, 34, 48, 36, 120, 117, 39, 119, 126, 124, 43, 128, 127, 111, 115, 121, 133, 123, 130, 130, 53,
                  136, 124, 133, 122, 131, 137, 143, 61, 135, 141, 148, 130, 133, 151, 82, 69, 122, 143, 141, 73, 144, 140,
                  143, 161, 78, 163, 152, 146, 166, 83, 168, 157, 155, 176, 88, 157, 163, 159, 170, 100, 178, 95, 179, 177,
                  177, 183, 100, 185, 174, 176, 187, 105, 175, 172, 191, 193, 179, 193, 112, 182, 185, 186, 116, 182, 194,
                  201, 189, 186, 190, 212, 124, 208, 191, 216, 211, 129, 213, 210, 209, 202, 218, 207, 209, 215, 209, 139,
                  205, 207, 221, 228, 228, 145, 230, 219, 217, 149, 217, 216, 234, 222, 154, 239, 228, 226, 247, 159, 112,
                  118, 118, 35, 109, 115, 38, 123, 112, 110, 115, 125, 44, 128, 125, 117, 132, 136, 115, 133, 121, 67]

# endregion