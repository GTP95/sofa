from armchair.utils.enums import TargetResponse
from armchair.components.qiling_profile import QilingProfile
from armchair.components.sym_parser import SymParser
from armchair.utils.constants import RNG_BASE, RNG_SIZE, AES_BLOCK_SIZE
from armchair.utils.constants import PLATFORM, AES_BLOCK_SIZE
from armchair.utils.arm_helpers import arm_registers, return_instruction_type_arm

from qiling import Qiling
from qiling.extensions.mcu.stm32f4 import stm32f415
from qiling.extensions.hookswitch.hook_switch import hook_switch
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.os.memory import UC_PROT_ALL
from capstone import Cs
from argparse import Namespace, ArgumentParser
from colorama import Fore, Style

import re
import os
import json
import shutil

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
    parser = ArgumentParser(description="Welcome to ARMChair!")

    # Global argument for debugging
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug mode for verbose output."
    )

    parser.add_argument(
        "--input",
        choices=["user", "user-csv", "auto", "user-raw"],
        required=True,
        help="Choose between commmand line user-provided, user-provided file, auto-generated input or in code not validated input.",
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
        "--elf_path",
        type=str,
        help="Path to the .elf file (required if no SettingsLoader is implemented for user-csv and user-raw mode).",
    )

    parser.add_argument(
        "--input_format",
        type=str,
        choices=["hex", "plaintext"],
        default="hex",
        help="Format of the inputs such as key and plaintext, either as an hex string or plaintext, hex dy default",
    )

    # Positional argument to select the algorithm (AES, ASCON, KECCAK)
    subparsers = parser.add_subparsers(
        dest="target", required=True, help="Choose the cryptographic algorithm."
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

    # Parse the arguments
    args = parser.parse_args()

    # Debug mode
    if args.debug:
        print(f"{info_t} Verbose mode is enabled")

    print(f"{info_t} Expected input in {args.input_format} format")

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
            print(
                f"{warn_t} No --elf_path argument provided, in this case the SettingsLoader component needs to be created and used for the {args.target} session"
            )

    if args.input == "user-raw":
        if not args.elf_path:
            print(
                f"{warn_t} No --elf_path argument provided, in this case the SettingsLoader component needs to be created and used for the {args.target} session"
            )

    # Process based on the algorithm (determined by the invoked subparser)
    if args.target == "AES":
        if args.input == "user" and args.debug:
            print(f"{info_t} AES with user-provided input:")
            print(f"{info_t} Key: {args.key}")
            print(f"{info_t} Plaintext: {args.plaintext}")
            print(f"{info_t} IV: {args.iv}")
        elif args.input == "auto" and args.debug:
            count = args.count if args.count else 1
            print(
                f"{info_t} AES with auto-generated input. {count} inputs will be generated."
            )
        elif args.input == "user-csv" and args.debug:
            print(
                f"{info_t} AES with user provided file. All the inputs in the file will be processed."
            )

    elif args.target == "ASCON":
        if args.input == "user" and args.debug:
            print(f"{info_t} ASCON with user-provided input:")
            print(f"{info_t} Key: {args.key}")
            print(f"{info_t} Plaintext: {args.plaintext}")
            print(f"{info_t} Nonce: {args.nonce}")
            print(f"{info_t} Associated Data: {args.ad}")
        elif args.input == "auto" and args.debug:
            count = args.count if args.count else 1
            print(
                f"{info_t} ASCON with auto-generated input. Generating {count} inputs..."
            )
        elif args.input == "user-csv" and args.debug:
            print(
                f"{info_t} ASCON with user provided file. All the inputs in the file will be processed."
            )

    elif args.target == "KECCAK":
        if args.input == "user" and args.debug:
            print(f"{info_t} KECCAK with user-provided input:")
            print(f"{info_t} Plaintext: {args.plaintext}")
        elif args.input == "auto" and args.debug:
            count = args.count if args.count else 1
            print(
                f"{info_t} KECCAK with auto-generated input. Generating {count} inputs..."
            )
        elif args.input == "user-csv" and args.debug:
            print(
                f"{info_t} KECCAK with user provided file. All the inputs in the file will be processed."
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
    an hex string first.

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
    an hex string first.

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
    an hex string first.

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
    an hex string first.

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

# region: LOADERS


def load_target_config():
    """
    Loads the target configuration from a JSON file based on the platform.

    Returns:
        dict: The configuration settings loaded from the file.

    Raises:
        FileNotFoundError: If the configuration file is not found.
        JSONDecodeError: If there is an error parsing the JSON file.
    """
    file_path = ""

    # find the json file
    for file in os.listdir():
        if file.endswith(".json") and PLATFORM in file:
            file_path = file

    if file_path == "":
        raise FileNotFoundError(f"Error: The target configuration file does not exist.")

    try:
        with open(file_path, "r") as file:
            data = json.load(file)
            return data
    except json.JSONDecodeError as e:
        raise json.JSONDecodeError(
            f"Error: Failed to decode JSON from {file_path}. Error: {e}"
        )
    except Exception as e:
        raise Exception(
            f"An unexpected error occurred while parsing the json config file: {e}"
        )


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
    debug: bool = False,
) -> Qiling:
    """
    Initializes Qiling with the given profile, ELF file, and disassembler hooks.

    Args:
        profile (QilingProfile): The profile to use in the emulation.
        elf (str): The path to the ELF file.
        traces (list): A list to store disassembled traces.
        debug (bool): Enable verbose output if True.

    Returns:
        Qiling: The initialized Qiling instance.
    """
    ql = Qiling(
        argv=[elf],
        archtype=QL_ARCH.CORTEX_M,
        ostype=QL_OS.MCU,
        env=stm32f415,
        verbose=QL_VERBOSE.DEBUG if debug else QL_VERBOSE.DISABLED,
    )

    # Create peripherals as needed
    ql.hw.create("usart1")
    ql.hw.create("rcc")

    # Manually map the RNG memory region, otherwise it will crash.
    ql.mem.map(RNG_BASE, RNG_SIZE, UC_PROT_ALL, "[RNG]")

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

# region: PRETTIFIERS


err_t: str = f"{Fore.RED}{'[err]:'}{Style.RESET_ALL}"
"""
err_t (str): Red-colored error message prefix.
"""

warn_t: str = f"{Fore.YELLOW}{'[warn]:'}{Style.RESET_ALL}"
"""
warn_t (str): Yellow-colored warning message prefix.
"""

info_t: str = f"{Fore.BLUE}{'[info]:'}{Style.RESET_ALL}"
"""
info_t (str): Blue-colored informational message prefix.
"""


# endregion
