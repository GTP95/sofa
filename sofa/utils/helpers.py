import os
import re
import shutil
from argparse import Namespace, ArgumentParser
from multiprocessing import Pool, cpu_count
from pathlib import Path
import logging

import numpy as np
import pandas as pd
from capstone import Cs
from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.extensions.hookswitch.hook_switch import hook_switch
from qiling.extensions.mcu import stm32f1
from qiling.extensions.mcu.stm32f1 import stm32f103
from qiling.extensions.mcu.stm32f4 import stm32f415
from tqdm import tqdm

from sofa.components.qiling_profile import QilingProfile
from sofa.components.sym_parser import SymParser
from sofa.targets.aes.aes_settings_loader import AesSettingsLoader
from sofa.targets.ascon.ascon_settings_loader import AsconSettingsLoader
from sofa.targets.keccak.keccak_settings_loader import KeccakHashSettingsLoader
from sofa.utils.arm_helpers import arm_registers, return_instruction_type_arm
from sofa.utils.enums import TargetResponse


# region: PARSERS


def parse_usart_res(res_bytes: bytearray) -> str:
    """
    Parses the USART response by converting bytes to a string and removing special characters.

    Args:
        res_bytes (bytearray): The raw bytes received from the USART.

    Returns:
        str: The parsed response as a string. Returns 'OK' for ack, otherwise the parsed string or an 'ERR'.
    """
    # turn the bytes into a string
    res_string = res_bytes.decode(encoding="ascii")
    # strip special characters
    res_stripped = re.sub(r"\W+", "", res_string)
    # parse the type of text into something understandable
    match res_stripped:
        case "z00":
            return TargetResponse.OK.value
        case _ if (m := re.match(r"^r(.*)z00$", res_stripped)):
            return m.group(1).lower()
        case _:
            return TargetResponse.ERR.value


def parse_args() -> Namespace:
    """
    Parses command-line arguments to determine the cryptographic algorithm and input mode.

    Returns:
        Namespace: Parsed arguments as a namespace object.
    """
    logger=logging.getLogger(__name__)
    parser = ArgumentParser(description="Welcome to Sofa!")

    # Global argument for debugging
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug mode for verbose output."
    )

    parser.add_argument(
        "--input",
        choices=["user", "user-csv", "auto", "user-raw"],
        required=True,
        help="Choose between command line user-provided, user-provided file, auto-generated input or in code not validated input.",
    )

    parser.add_argument(
        "--count",
        type=int,
        help="Number of auto-generated inputs (required for auto mode).",
    )

    parser.add_argument(
        "--path",
        type=str,
        help="Path to the input .csv file (required for user-csv mode).",
    )

    parser.add_argument(
        "--input_format",
        type=str,
        choices=["hex", "plaintext"],
        default="hex",
        help="Format of the inputs such as key and plaintext, either as an hex string or plaintext, hex dy default",
    )

    parser.add_argument("--leakage_model", type=str, choices=["HD", "HW", "ID"], default="HD", help="Leakage model to use for power trace generation (default: HD).")

    parser.add_argument("--no_validation", action="store_true", help="Disable input validation for user-provided inputs.")
    # Positional argument to select the algorithm (AES, ASCON, KECCAK)
    subparsers = parser.add_subparsers(
        dest="target", required=True, help="Choose the cryptographic algorithm."
    )

    parser.add_argument(
        "elf_path",
        type=str,
        help="Path to the elf file.",
    )

    parser.add_argument(
        "config",
        type=str,
        help="Path to the JSON configuration file"
    )



    # AES Subparser
    aes_parser = subparsers.add_parser("AES", help="AES algorithm options")
    # ASCON Subparser
    ascon_parser = subparsers.add_parser("ASCON", help="ASCON algorithm options")
    # KECCAK Subparser
    keccak_parser = subparsers.add_parser("KECCAK", help="KECCAK algorithm options")

    # AES Subparser args
    aes_parser.add_argument("--key", type=str, help="User provided key (hex string).")
    aes_parser.add_argument(
        "--plaintext", type=str, help="User provided plaintext (hex string)."
    )
    aes_parser.add_argument("--iv", type=str, help="User provided IV (hex string).")

    # ASCON Subparser args
    ascon_parser.add_argument(
        "--key",
        type=str,
        help="User provided key (hex string). Must be 16 bytes for this implementation",
    )
    ascon_parser.add_argument(
        "--plaintext", type=str, help="User provided plaintext (hex string)."
    )
    ascon_parser.add_argument(
        "--nonce",
        type=str,
        help="User provided nonce (hex string). Must be 16 bytes for this implementation",
    )
    ascon_parser.add_argument(
        "--ad", type=str, help="User provided associated data (hex string)."
    )

    # KECCAK Subparser args
    keccak_parser.add_argument(
        "--plaintext", type=str, help="User provided plaintext (hex string)."
    )

    keccak_parser.add_argument("--key", type=str, help="User provided key (hex string).")
    keccak_parser.add_argument("--capacity", type=int, default=1600, help="KECCAK capacity in bits (default: 1600).")

    # Parse the arguments
    args = parser.parse_args()

    # Configure global logging level based on --debug
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format="[%(levelname)s] %(name)s: %(message)s")
    # Also set this module's logger to the chosen level
    logger.setLevel(log_level)

    # Debug/info messages rely on configured log level
    logger.debug("Debug mode enabled; log level set to DEBUG")
    logger.info(f"Expected input in {args.input_format} format")

    # Conditional requirements for --input
    if args.input == "user":
        if args.target == "AES" and (not args.key or not args.plaintext):
            parser.error(
                "--key, and --plaintext are required when --input is 'user' for AES"
            )
        if args.target == "ASCON" and (
            not args.key or not args.plaintext or not args.nonce
        ):
            parser.error(
                "--key, --plaintext, and --nonce are required when --input is 'user' for ASCON"
            )
        if args.target == "KECCAK" and not args.plaintext:
            parser.error("--plaintext is required when --input is 'user' for KECCAK")

    if args.input == "auto":
        if not args.count:
            parser.error("--count, --count is required when --input is 'auto'")

    if args.input == "user-csv":
        if not args.path:
            parser.error(
                "--path, --path of the .csv file is required when --input is 'user-csv'"
            )
        if not args.elf_path:
            logger.warning(
                f"No --elf_path argument provided, in this case the SettingsLoader component needs to be created and used for the {args.target} session"
            )

    if args.input == "user-raw":
        if not args.elf_path:
            logger.warning(
                f"No --elf_path argument provided, in this case the SettingsLoader component needs to be created and used for the {args.target} session"
            )

    # Process based on the algorithm (determined by the invoked subparser)
    if args.target == "AES":
        if args.input == "user":
            logger.debug("AES with user-provided input:")
            logger.debug(f"Key: {args.key}")
            logger.debug(f"Plaintext: {args.plaintext}")
            logger.debug(f"IV: {args.iv}")
        elif args.input == "auto":
            count = args.count if args.count else 1
            logger.debug(
                f"AES with auto-generated input. {count} inputs will be generated."
            )
        elif args.input == "user-csv":
            logger.debug(
                f"AES with user provided file. All the inputs in the file will be processed."
            )

    elif args.target == "ASCON":
        if args.input == "user":
            logger.debug("ASCON with user-provided input:")
            logger.debug(f"Key: {args.key}")
            logger.debug(f"Plaintext: {args.plaintext}")
            logger.debug(f"Nonce: {args.nonce}")
            logger.debug(f"Associated Data: {args.ad}")
        elif args.input == "auto":
            count = args.count if args.count else 1
            logger.debug(
                f"ASCON with auto-generated input. Generating {count} inputs..."
            )
        elif args.input == "user-csv":
            logger.debug(
                f"ASCON with user provided file. All the inputs in the file will be processed."
            )

    elif args.target == "KECCAK":
        if args.input == "user":
            logger.debug("KECCAK with user-provided input:")
            logger.debug(f"Plaintext: {args.plaintext}")
        elif args.input == "auto":
            count = args.count if args.count else 1
            logger.debug(
                f"KECCAK with auto-generated input. Generating {count} inputs..."
            )
        elif args.input == "user-csv":
            logger.debug(
                f"KECCAK with user provided file. All the inputs in the file will be processed."
            )

    return args


# endregion

# region: BYTES & HEX UTILS


def string_to_hex(input_string: str):
    """
    Converts a string into its hexadecimal representation if not already an hex string.

    Args:
        input_string (str): The string to encode.

    Returns:
        str: Hexadecimal representation of the string.
    """
    if not input_string.isascii():
        raise ValueError("The provided input string is not ascii")
    else:
        return "".join(f"{ord(char):02X}" for char in input_string)


def str_to_bytes(string: str) -> bytes:
    """
    Converts a string to bytes.

    Args:
        string (str): The string to convert.

    Returns:
        bytes: The encoded byte sequence of the string.
    """
    try:
        return string.encode(encoding="ascii")
    except UnicodeEncodeError as e:
        raise UnicodeDecodeError(f"Error: Failed to encode string {string}. Error: {e}")


def get_str_bytes_nr(string: str) -> int:
    """
    Returns the number of bytes in a string after encoding it.

    Args:
        string (str): The string to measure.

    Returns:
        int: The number of bytes in the encoded string.
    """
    try:
        return len(str_to_bytes(string=string))
    except Exception as e:
        raise Exception(
            f"Error: Failed to get nr of bytes from string {string}. Error: {e}"
        )


def hex_str_to_bytes(hex_string: str) -> bytes:
    """
    Converts a hex string into its corresponding bytes.

    Args:
        hex_string (str): The hex string to convert.

    Returns:
        bytes: The byte sequence represented by the hex string.
    """
    try:
        return bytes.fromhex(hex_string)
    except Exception as e:
        raise Exception(
            f"Error: Failed to convert hex string {hex_string} to bytes. Error: {e}"
        )


def bytes_to_hex_str(bytes: bytes) -> str:
    """
    Converts bytes into a hexadecimal string.

    Args:
        bytes (bytes): The byte sequence to convert.

    Returns:
        str: The corresponding hex string of the bytes.
    """
    try:
        return bytes.hex()
    except Exception as e:
        raise Exception(
            f"Error: Failed to convert bytes {bytes} to hex string. Error: {e}"
        )


def get_hex_str_bytes_nr(string: str) -> int:
    """
    Returns the number of bytes in a hex string.

    Args:
        string (str): The hex string to measure.

    Returns:
        int: The number of bytes in the hex string.
    """
    try:
        return len(hex_str_to_bytes(hex_string=string))
    except Exception as e:
        raise Exception(
            f"Error: Failed to get nr of bytes from hex string string {string}. Error: {e}"
        )


# endregion

# region: COMMANDS MESSAGES (here u can define more if needed)


def get_key_cmd(key: str, input_format: str) -> bytes:
    """
    Prepares a command to send the AES key.

    If the user indicated that it is using plainttext, it will convert the string into
    a hex string first.

    Args:
        key (str): The AES key as a hex string.

    Returns:
        bytes: The command to send the key over UART.
    """
    formatted_key: str = (
        string_to_hex(input_string=key) if input_format == "plaintext" else key
    )
    return b"k" + str_to_bytes(formatted_key) + b"\n"


def get_pt_cmd(pt: str, input_format: str) -> bytes:
    """
    Prepares a command to send the AES plaintext.

    If the user indicated that it is using plainttext, it will convert the string into
    an hex string first.

    Args:
        pt (str): The plaintext as a hex string.

    Returns:
        bytes: The command to send the plaintext over UART.
    """
    formatted_pt: str = (
        string_to_hex(input_string=pt) if input_format == "plaintext" else pt
    )
    return b"p" + str_to_bytes(string=formatted_pt) + b"\n"


def get_iv_cmd(iv: str, input_format: str) -> bytes:
    """
    Prepares a command to send the AES initialization vector (IV).

    If the user indicated that it is using plainttext, it will convert the string into
    a hex string first.

    Args:
        iv (str): The IV as a hex string.

    Returns:
        bytes: The command to send the IV over UART.
    """
    formatted_iv: str = (
        string_to_hex(input_string=iv) if input_format == "plaintext" else iv
    )
    return b"i" + str_to_bytes(string=formatted_iv) + b"\n"


def get_ad_cmd(ad: str, input_format: str) -> bytes:
    """
    Prepares a command to send the ASCON Associated Data.

    If the user indicated that it is using plainttext, it will convert the string into
    a hex string first.

    Args:
        ad (str): The AD as a hex string.

    Returns:
        bytes: The command to send the Associated Data over UART.
    """
    formatted_ad: str = (
        string_to_hex(input_string=ad) if input_format == "plaintext" else ad
    )
    return b"a" + str_to_bytes(string=formatted_ad) + b"\n"


def get_nonce_cmd(nonce: str, input_format: str) -> bytes:
    """
    Prepares a command to send the ASCON nonce.

    If the user indicated that it is using plainttext, it will convert the string into
    a hex string first.

    Args:
        nonce (str): The nonce as a hex string.

    Returns:
        bytes: The command to send the nonce over UART.
    """
    formatted_nonce: str = (
        string_to_hex(input_string=nonce) if input_format == "plaintext" else nonce
    )
    return b"n" + str_to_bytes(string=formatted_nonce) + b"\n"


# endregion

# region: QILING UTILS


def get_current_function_args(ql: Qiling, num_args: int):  # -> list:
    """
    Retrieves arguments from the Qiling virtual CPU for the current function.

    Args:
        ql (Qiling): The Qiling instance running the emulation.
        num_args (int): The number of arguments to retrieve.

    Returns:
        list: A list of arguments retrieved from the registers and stack.
    """
    arguments = []

    # First, retrieve arguments from registers R0 to R3
    if num_args > 0:
        arguments.append(ql.arch.regs.read(register="R0"))
    if num_args > 1:
        arguments.append(ql.arch.regs.read(register="R1"))
    if num_args > 2:
        arguments.append(ql.arch.regs.read(register="R2"))
    if num_args > 3:
        arguments.append(ql.arch.regs.read(register="R3"))

    # If more arguments are required, retrieve them from the stack
    if num_args > 4:
        sp = ql.arch.regs.arch_sp  # Stack pointer
        for i in range(4, num_args):
            arg_address = sp + ((i - 4) * 4)  # Calculate the address on the stack
            arg_value = ql.mem.read_ptr(
                arg_address
            )  # Read a 32-bit value from the stack
            arguments.append(arg_value)

    return arguments


# this is not actively used but it could be a fun idea someone wants to implement it,
# may save some time with different runs.
def arm_disassembler_cached(
    ql: Qiling, address: int, size: int, user_data: tuple[Cs, list, dict]
) -> None:
    """
    Cached Disassembles ARM instructions and appends the results to the trace data.

    Args:
        ql (Qiling): The Qiling instance running the emulation.
        address (int): The address to start disassembling.
        size (int): The size of the instruction block.
        user_data (tuple): A tuple containing the disassembler instance, trace data, and cache.
    """
    md, trace_data, cache = user_data  # Unpack user_data

    # Cache key is a tuple of (address, size)
    cache_key = (address, size)

    # Check if the address and size combination is already in the cache
    if cache_key in cache:
        cached_result = cache[cache_key]
        for cached_ins in cached_result:
            # Copy the cached instruction to avoid modifying the cache
            cached_ins_copy = cached_ins.copy()
            # Append the values of relevant registers
            for reg in arm_registers.values():
                cached_ins_copy.append(hex(ql.arch.regs.read(reg)))
            # Append the modified instruction (with registers) to trace_data
            trace_data.append(cached_ins_copy)
        return

    # Read the instruction bytes from memory
    buf: bytearray = ql.mem.read(addr=address, size=size)

    # List to store the disassembled instructions for caching (without registers)
    to_cache = []

    # Disassemble the instruction(s)
    for addr, sz, mnemonic, op_str in md.disasm_lite(code=buf, offset=address):
        # Store only the instruction data (without registers) in the cache
        read_ins: list = [
            hex(addr),
            buf.hex(),
            mnemonic,
            return_instruction_type_arm(instruction=mnemonic.upper()),
            op_str,
        ]

        # Add to cache without registers
        to_cache.append(read_ins.copy())

        # Append the values of relevant registers
        for reg in arm_registers.values():
            read_ins.append(hex(ql.arch.regs.read(reg)))
    
        # Append the instruction (with registers) to trace_data
        trace_data.append(read_ins)

    # Cache the disassembled instructions (without registers)
    cache[cache_key] = to_cache


def arm_disassembler(
    ql: Qiling, address: int, size: int, user_data: tuple[Cs, list]
) -> None:
    """
    Old Disassembles ARM instructions and appends the results to the trace data.

    Args:
        ql (Qiling): The Qiling instance running the emulation.
        address (int): The address to start disassembling.
        size (int): The size of the instruction block.
        user_data (tuple): A tuple containing the disassembler instance and trace data.
    """

    md, trace_data = user_data  # Unpack user_data

    buf: bytearray = ql.mem.read(addr=address, size=size)

    # According to the doc this version can save some performances and we only care about the address, mnemonic and op_str
    # that are still returned.
    # https://www.capstone-engine.org/lang_python.html#:~:text=2.%20Faster%2Dsimpler%20API%20for%20basic%20information
    for address, size, mnemonic, op_str in md.disasm_lite(code=buf, offset=address):
        read_ins = [
            hex(address),
            buf.hex(),
            mnemonic,
            return_instruction_type_arm(instruction=mnemonic.upper()),
            op_str,
        ]
        # Append the values of relevant registers
        for reg in arm_registers.values():
            read_ins.append(hex(ql.arch.regs.read(reg)))
        trace_data.append(read_ins)


def initialize_qiling(
    profile: QilingProfile,
    sym_parser: SymParser,
    elf: str,
    traces: list,
    cache: dict,
        json_path: str
) -> Qiling:
    """
    Initializes Qiling with the given profile, ELF file, and disassembler hooks.

    Args:
        profile (QilingProfile): The profile to use in the emulation.
        elf (str): The path to the ELF file.
        traces (list): A list to store disassembled traces.

    Returns:
        Qiling: The initialized Qiling instance.
    """

    match profile.get_algorithm_name():
        case 'AES':
            config = AesSettingsLoader(json_path).get_target_settings()
        case 'ASCON':
            logging.getLogger().warning('This part of the codebase needs refactoring and will not work.')
            config = AsconSettingsLoader().get_target_settings()
        case 'KECCAK':
            logging.getLogger().warning('This part of the codebase needs refactoring and will not work.')
            config = KeccakHashSettingsLoader().get_target_settings()
        case _:
            raise ValueError(f"Algorithm {profile.get_algorithm_name()} not supported.")


    #convert platform string into platform constant. The string comes from the JSON config file, the constant is Qiling's internal representation of that
    match config['platform']:
        case 'stm32f103':
            platform=stm32f103
        case 'stm32f1':
            platform=stm32f1
        case 'stm32f415':
            platform=stm32f415
        case _:
            raise ValueError(f"Platform {config['platform']} needs to be added inside 'helpers.py' in the 'initialize_qiling' function.")

    ql = Qiling(
        argv=[elf],
        archtype=QL_ARCH.CORTEX_M,
        ostype=QL_OS.MCU,
        env=platform,
        verbose=QL_VERBOSE.DEBUG if logging.getLogger().isEnabledFor(logging.DEBUG) else QL_VERBOSE.DISABLED,
    )

    # Create peripherals as needed
    ql.hw.create("usart1")
    ql.hw.create("rcc")

    # Load memory mappings form config and apply them
    for memap_obj in config['memory_mappings']:
        ql.mem.map(memap_obj['base_address'], memap_obj['size'], memap_obj['perms'], memap_obj['info'])

    # Add disassembler to the Qiling object
    disassembler: Cs = ql.arch.disassembler

    # This was done for efficiency but it can be adjusted per algorithm
    # the thought is, if we are interested in the traces of the encryption the
    # we should only be recording the instructions during that period.
    # this essentialy cuts the traces number in half.
    begin, end = profile.get_profile_range(sym_parser=sym_parser)

    disassembler_data: tuple[Cs, list] = (disassembler, traces, cache)

    hook_switch(
        ql=ql,
        callback=arm_disassembler_cached,
        user_data=disassembler_data,
        begin=begin,
        end=end,
    )

    return ql


# endregion

# region: FILES AND FOLDERS


def check_environment() -> None:
    """
    Ensures the Traces directory exists by creating it if necessary.
    """
    if os.path.exists(path="Traces"):
        shutil.rmtree("Traces")
    os.makedirs(name="Traces")


# endregion

# region: FUNCTIONS UTILS


def log_data_received(ql: Qiling, description: str) -> None:
    """
    Logs AES data received in the Qiling emulator.

    Args:
        ql (Qiling): The Qiling instance running the emulation.
        description (str): A description of the data being logged.

    Warning:
        this function is very specific to the callbacks given while registering the commands
        For example, I know that all my callbacks are function expecting 2 arguments:
        buffer address and a buffer length,
        therefore I will check in memory at that address for that amount
        of data. If you coded different callbacks and want to have this feature, you have to
        implement your own version. I think this may be automated to some extend by compiling with symbols
        and analysing the elf file but that is a bit out of scope.
    """
    pointer, size = get_current_function_args(ql=ql, num_args=2)
    data: bytearray = ql.mem.read(addr=pointer, size=size)
    ql.log.info(f"Received {description}: {data.hex()}")


def get_command_received(ql: Qiling):
    """
    Retrieves the AES command received by Qiling.

    Args:
        ql (Qiling): The Qiling instance running the emulation.

    Returns:
        list: A list containing the command character and its size.
    """
    cmd, size = get_current_function_args(ql=ql, num_args=2)
    return [chr(cmd), size]


# endregion

#Functions adapted from one of ARCHER's infamous Jupyter notebooks

#### Fundamental HW HD functions
def HD(a,b):
    """
    Computes the hamming distance between two integers
    """
    hd = 0
    diff = a^b
    while diff:
        hd += diff & 1
        diff >>= 1
    return hd

def HD_bin(a,b):
#     print(type(sum(c1 != c2 for c1, c2 in zip(a, b)) ))
    return sum(c1 != c2 for c1, c2 in zip(a, b))

def HW(a):
    """
    Computes the hamming weight of an integer
    """
    return sum([a&(1<<i)>0 for i in range(32)])

def binstr(x, size=32):
    return bin(x)[2:].rjust(size, "0")

def extract_number(filename):
    """## helper for create_trace_file

    ### Args:
        - `filename (_type_)`: _description_

    ### Returns:
        - `_type_`: _description_
    """
    match = re.search(r'trace_(\d+)', filename.stem)
    return int(match.group(1)) if match else float('inf')


#### Functions to generate simulated power traces (HD, HW and ID) for all registers
# ********************************************************************************************************************
def create_opt_HW_trace(filename, cols=['r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','sp','lr','pc']):
    df = pd.read_csv(filename)
    df.fillna('', inplace=True)

    # Convert selected register columns from hex to integer
    reg_int = df[cols].map(lambda x: int(x[2:], 16) if x else 0)

    # Compute the Hamming weights
    hw_ref = reg_int.map(HW).values
    return np.sum(hw_ref, axis=1)


# ********************************************************************************************************************
def create_opt_HD_trace(filename, cols=['r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','sp','lr','pc']):
    df = pd.read_csv(filename)
    df.fillna('', inplace=True)
    reg_int = df[cols].apply(lambda col: col.map(lambda x: int(x[2:], 16) if x else 0))
    NUM_ROWS, NUM_COLS = reg_int.shape

    reg_int_shifted = reg_int.shift(-1)  # Create a shifted DataFrame
    # reg_int = reg_int.iloc[:-1]
    # reg_int_shifted = reg_int_shifted.iloc[:-1]

    reg_int = reg_int.to_numpy()  # Convert to NumPy arrays for efficient computation
    reg_int_shifted = reg_int_shifted.to_numpy()  # Convert to NumPy arrays for efficient computation
    hd_ref = [sum(HD(int(reg_int[i, j]), int(reg_int_shifted[i, j])) for j in range(NUM_COLS))
              for i in range(NUM_ROWS - 1)
              ]
    return hd_ref


# ********************************************************************************************************************
def create_ID_trace(filename, cols):
    """
    reads an execution trace in csv format
    returns
    - the ID or the sum of  the content of all registers for each instruction
    - the total number of instructions

    """
    df = pd.read_csv(filename)
    df.fillna('', inplace=True)
    reg = df[cols]
    # convert hex register values to binary and decimal values
    reg_dec = []
    for col in cols:
        reg_dec.append(reg[col].apply(lambda x: int(x, 16)))
    number_instructions = len(reg_dec[0])  # number of instructions
    ID_ref = np.zeros((number_instructions, len(cols)))
    for col in range(len(cols)):
        for i in range(number_instructions):
            ID_ref[i, col] = reg_dec[col][i]
    return np.sum(ID_ref, axis=1)

#### Optimized code for computing HD, HW and ID simulated traces for all executions

### creates files in order
def create_trace_file(folder, name_output_file, leakage_model, numberTraces=100, cols=['r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','sp','lr','pc']):
    """
     creates a npz file from a folder containing csv with execution traces files
     folder: folder containing the csv files with execution traces
     output_file: name of the npz file to be created
     leakage_model: the leakage model to be used to create the traces (ID, HW, HD)
     cols: list of the columns/registers from the dataset to be used to create the traces
    """
    print("Creating simulation traces model....", leakage_model)
    trace_list = []
    count = 0
    files = sorted(Path(folder).glob('*.csv'), key=extract_number)
    for file in tqdm(files):
        if count >= numberTraces:
            break
        # print('Trace ',count)
        # print('file:', file)
        if leakage_model == 'ID':
            trace = create_ID_trace(file, cols)
        elif leakage_model == 'HW':
            trace = create_opt_HW_trace(file, cols)
        elif leakage_model == 'HD':
            trace = create_opt_HD_trace(file, cols)
        trace_list.append(trace)
        count += 1
    vectors_array = np.array(trace_list)
    np.savez_compressed(name_output_file, vectors_array)

    print("Finished creating the file")


def process_csv_file(file, cols, leakage_model):
    """
    Process a single CSV file based on the specified leakage model and columns.
    """
    #     print('Processing file:', file)
    if leakage_model == 'ID':
        trace = create_ID_trace(file, cols)
    elif leakage_model == 'HW':
        trace = create_opt_HW_trace(file, cols)
    elif leakage_model == 'HD':
        trace = create_opt_HD_trace(file, cols)
    return trace


### code that uses multiprocessing package
def create_npz_file(name_npy_file, folder, leakage_model, cols=['r0','r1','r2','r3','r4','r5','r6','r7','r8','r9','r10','r11','r12','sp','lr','pc'], num_cores=None):
    """
    Creates a numpy file from a folder containing csv files.

    name_npy_file: name of the numpy file to be created
    folder: folder containing the csv files
    leakage_model: the leakage model to be used to create the traces (ID, HW, HD)
    cols: list of the columns/registers from the dataset to be used to create the traces
    num_cores: number of CPU cores to use in multiprocessing (default is None, which uses all available cores)

    Example usage:
    create_npz_file("output.npz", "data_folder", "ID", ["col1", "col2"], num_cores=4) # Use 4 cores
    """
    print("Creating simulation traces model....", leakage_model)
    trace_list = []
    count = 0
    # files = list(Path(folder).glob('*.csv'))
    files = sorted(Path(folder).glob('*.csv'), key=extract_number)

    # Determine number of cores to use
    if num_cores is None:
        num_cores = cpu_count()

    # Define a multiprocessing pool with specified number of cores
    with Pool(processes=num_cores) as pool:
        # Process each CSV file in parallel
        results = pool.starmap(process_csv_file, [(file, cols, leakage_model) for file in files])

    trace_list.extend(results)

    vectors_array = np.array(trace_list)
    np.savez_compressed(name_npy_file, vectors_array)
    print("Finished creating the file")

#********************************************************************************************************************
    #TRACE MANIPULATION FUNCTIONS
#********************************************************************************************************************
def load_trace_file(trace_filename):
    """
    Load a trace file and return the trace data.
    """
    data = np.load(trace_filename)
    trace_set=data[data.files[0]]
    number_samples=len(trace_set[0])
    number_traces=len(trace_set)
    print("Load successful!")
    print("Number of traces: ", number_traces)
    print("Number of samples: ", number_samples)
    return trace_set, number_traces, number_samples

#### Functions to compute simulated traces for selected registers
#** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** ** **

# LM for destination registers
# ********************************************************************************************************************
def create_list_modified_registers(df):
    """
    df : dataframe containing the full reference trace
    return: list of registers that are modified by each instruction
    """
    operands = df['Operands'].to_list()
    types = df['Type'].to_list()
    dest = ['zero']

    for op, typ in zip(operands, types):
        if typ in ['STORE', 'UBRANCH']:
            dest.append('zero')
        else:
            if isinstance(op, str):
                dest.append(op.split(',')[0])
            else:
                dest.append('zero')

    dest.pop()  # remove the last element
    return dest


def select_value(row, col_name='Dest'):
    """
    col_name='Dest' contains a list of columns,
    select the cell which corresponds to the value, column pointed by  the respective value in 'Dest'
    """
    return row[row['Dest']]


def HW_dest(filename, dest_register):
    df = pd.read_csv(filename)
    df.fillna('', inplace=True)

    df['Dest'] = dest_register
    df['Selected_Value'] = df.apply(select_value, axis=1)
    df['HW'] = df['Selected_Value'].apply(lambda x: HW(int(x[2:], 16)))
    hw_trace = df['HW'].to_list()
    return hw_trace


def ID_dest(filename, dest_register):
    df = pd.read_csv(filename)
    df.fillna('', inplace=True)

    df['Dest'] = dest_register
    df['Selected_Value'] = df.apply(select_value, axis=1)
    # df['HW'] = df['Selected_Value'].apply(lambda x: HW(int(x[2:], 16)))
    ID_trace = df['Selected_Value'].to_list()
    int_list = [int(hex_str, 16) for hex_str in ID_trace]
    return int_list


def create_trace_file_dest(folder, name_output_file, leakage_model, list_dest_registers, numberTraces=100, ):
    """
     creates a npz file from a folder containing csv with execution traces files
     folder: folder containing the csv files with execution traces
     output_file: name of the npz file to be created
     leakage_model: the leakage model to be used to create the traces (ID, HW, HD)
     cols: list of the columns/registers from the dataset to be used to create the traces
    """
    print("Creating simulation traces model....", leakage_model)
    trace_list = []
    count = 0
    files = sorted(Path(folder).glob('*.csv'), key=extract_number)
    for file in tqdm(files):
        if count >= numberTraces:
            break
        if leakage_model == 'IDD':
            trace = ID_dest(file, list_dest_registers)
        elif leakage_model == 'HWD':
            trace = HW_dest(file, list_dest_registers)

        trace_list.append(trace)
        count += 1
    vectors_array = np.array(trace_list)
    np.savez_compressed(name_output_file, vectors_array)
    print("Finished creating the file")


def create_HW_trace(filename, cols):
    """
    reads an execution trace in csv format
    returns
    - the hamming weight of  the content of all registers for each instruction
    - the total number of instructions

    """
    df = pd.read_csv(filename)
    df.fillna('', inplace=True)
    # cols = ['zero', 'ra', 'sp', 'gp', 'tp', 't0', 't1','t2', 's0', 's1', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 's2',
    #  's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10', 's11', 't3', 't4','t5', 't6']
    # cols = ['t1', 's0', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 't3']
    reg = df[cols]
    # convert hex register values to binary and decimal values
    reg_bin = []
    for col in cols:
        reg_bin.append(reg[col].apply(lambda x: bin(int(x, 16))[2:]))
    number_instructions = len(reg_bin[0])  # number of instructions
    hw_ref = np.zeros((number_instructions, len(cols)))
    for col in range(len(cols)):
        for i in range(number_instructions):
            hw_ref[i, col] = HW(reg_bin[col][i])
    return np.sum(hw_ref, axis=1)


def create_HD_trace(filename, cols):
    # this is the correct version
    df = pd.read_csv(filename)
    df.fillna('', inplace=True)
    reg = df[cols]

    reg_bin = []
    for col in cols:
        reg_bin.append(reg[col].apply(lambda x: bin(int(x[2:], 16))[2:]))
    number_instructions = len(reg_bin[0])  # number of instructions
    print("number_instructions = ", number_instructions)
    hd_ref = np.zeros((number_instructions - 1, len(cols)))
    for col in range(len(cols)):
        for i in range(number_instructions - 1):
            hd_ref[i, col] = HD(reg_bin[col][i].rjust(32, "0"), reg_bin[col][i + 1].rjust(32, "0"))

    return np.sum(hd_ref, axis=1)


def create_npy_file(name_npy_file, folder, leakage_model, cols):
    """
     creates a numpy file from a folder containing csv files

     name_npy_file: name of the numpy file to be created
     folder: folder containing the csv files
     leakage_model: the leakage model to be used to create the traces (ID, HW, HD)
     cols: list of the columns/registers from the dataset to be used to create the traces
    """
    print("Creating simulation traces model....", leakage_model)
    trace_list = []
    count = 0
    for file in Path(folder).glob('*.csv'):
        print('Trace ', count)
        if leakage_model == 'ID':
            trace = create_ID_trace(file, cols)
        elif leakage_model == 'HW':
            trace = create_HW_trace(file, cols)
        elif leakage_model == 'HD':
            trace = create_HD_trace(file, cols)
        trace_list.append(trace)
        count += 1
    vectors_array = np.array(trace_list)
    np.save(name_npy_file, vectors_array)
    print("Finished creating the file")