from sofa.utils.constants import RNG_BASE, RNG_SIZE
from sofa.components.sym_parser import SymParser
from sofa.utils.helpers import str_to_bytes, parse_usart_res, string_to_hex

from qiling import Qiling
from qiling.extensions.mcu.stm32f4 import stm32f415
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.os.memory import UC_PROT_ALL

from argparse import Namespace, ArgumentParser
import sys

# Help message for the command-line interface
help_message = "Welcome to ARMChair code tester!"


class EmulatorState:
    """
    A class to maintain the state of the emulator.

    Attributes:
        first_invocation (bool): Tracks if it's the first call to the command hook.
    """

    def __init__(self):
        self.first_invocation = True  # Tracks if it's the first call


def on_get_cmd_reached(ql: Qiling, user_data: tuple[EmulatorState, str]) -> None:
    """
    Callback function to handle the 'simpleserial_get' function in the emulated firmware.

    Args:
        ql (Qiling): The Qiling emulator instance.
        target_data (EmulatorState): The state of the emulator.
    """
    es, input_format = user_data
    # Skip processing USART1 data on the first call
    if not es.first_invocation:
        received_data = ql.hw.usart1.recv()  # Receive data from USART1
        parsed_data = parse_usart_res(
            res_bytes=received_data
        )  # Parse the received data

        if parsed_data == "OK":
            print("The code received the command correctly!")
        elif parsed_data == "ERR":
            print(
                "The code returned an error, make sure to check the length of your inputs and if they match the format that you specified!"
            )
        else:
            print(f"Received from the C code: {parsed_data}")

    # Mark the first invocation as processed
    es.first_invocation = False

    # Prompt the user for a command
    user_input = input(
        "Enter a command (e.g., kaabbcc..), or type 'quit' to exit: "
    ).strip()

    # Handle the 'quit' command
    if user_input.lower() == "quit":
        print("Quit command received. Stopping emulation.")
        ql.stop()  # Stop the emulator
        return

    data = (
        string_to_hex(input_string=user_input[1:])
        if input_format == "plaintext"
        else user_input[1:]
    )

    # Convert user input to bytes and send to USART1
    cmd_bytes = (
        bytes(user_input[0], encoding="ascii") + str_to_bytes(string=data) + b"\n"
    )

    print(f"Sending to C code: {cmd_bytes}")
    ql.hw.usart1.send(cmd_bytes)  # Send the bytes to USART1


def hook_cmds(
    ql: Qiling, sym_parser: SymParser, es: EmulatorState, input_format: str
) -> None:
    """
    Hooks the firmware function 'simpleserial_get' in the Qiling emulator.

    Args:
        ql (Qiling): The Qiling emulator instance.
        sym_parser (SymParser): The symbol parser for resolving ELF symbols.
        es (EmulatorState): The state of the emulator.
    """
    # Retrieve the symbol address for 'simpleserial_get' from the ELF file
    get_cmd = sym_parser.get_symbol_by_name(name="simpleserial_get")

    user_data = (es, input_format)

    # Hook the symbol address to the callback
    ql.hook_address(callback=on_get_cmd_reached, address=get_cmd, user_data=user_data)


def main():
    """
    The main function initializes the Qiling emulator, sets up peripherals, maps memory,
    hooks firmware functions, and starts emulation.
    """
    # Parse command-line arguments
    parser = ArgumentParser(description=help_message)

    parser.add_argument(
        "--elf_path",
        type=str,
        required=True,
        help="Path to the .elf file.",
    )

    parser.add_argument(
        "--input_format",
        type=str,
        choices=["hex", "plaintext"],
        default="hex",
        help="Format of the inputs such as key and plaintext, either as an hex string or plaintext, hex dy default",
    )

    args: Namespace = parser.parse_args()  # Parse arguments

    if not args.elf_path:
        parser.error("--elf_path, --elf_path is required for this program to work")

    elf_path = args.elf_path  # Extract the ELF path
    input_format = args.input_format

    print(f"Testing {elf_path} with {input_format} input format")

    # Initialize emulator state and symbol parser
    es = EmulatorState()

    try:
        sp = SymParser(elf_path=elf_path)
        # Initialize the Qiling emulator for Cortex-M
        ql = Qiling(
            argv=[elf_path],
            archtype=QL_ARCH.CORTEX_M,
            ostype=QL_OS.MCU,
            env=stm32f415,
            verbose=QL_VERBOSE.DEFAULT,
        )

        # Create required peripherals
        ql.hw.create("usart1")  # USART1 for serial communication
        ql.hw.create("rcc")  # Reset and Clock Control

        # Map the RNG memory region manually to avoid crashes
        ql.mem.map(RNG_BASE, RNG_SIZE, UC_PROT_ALL, "[RNG]")

        # Hook commands to the Qiling emulator
        hook_cmds(ql=ql, sym_parser=sp, es=es, input_format=input_format)

        # Start the emulation
        ql.run()

    except Exception as e:
        # Handle exceptions and cleanly exit
        print(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Entry point of the script
    main()
