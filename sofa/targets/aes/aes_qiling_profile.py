import logging

from sofa.components.qiling_profile import QilingProfile
from sofa.components.sym_parser import SymParser
from sofa.targets.aes.aes_uart_interface import AesUartHandler
from sofa.utils.enums import AesQilingStatus
from sofa.utils.helpers import log_data_received, get_command_received
from sofa.targets.aes.aes_settings_loader import AesSettingsLoader

from qiling import Qiling


class AesQilingProfile(QilingProfile):
    """
    A class that manages the AES-specific operations within the Qiling framework.
    This class extends the QilingProfile base class and handles key, IV, and plaintext
    transmission for AES encryption via UART.

    Attributes:
        _sym_parser (SymParser): An instance of the symbol parser to retrieve symbols from the target ELF file.
        __status (list[AesQilingStatus]): Tracks the current status of the AES command execution in Qiling.
    """

    def __init__(self, json_path) -> None:
        """
        Initializes the AesProfile with a symbol parser and sets the initial AES status to INIT.
        """
        super().__init__()
        self.__status: list[AesQilingStatus] = [AesQilingStatus.INIT]
        self.settings=AesSettingsLoader(json_path).get_target_settings()
        self.logger=logging.getLogger(__name__)
        self.logger.setLevel(logging.getLogger().level)

    def __hook_function_get_cmd_reached(self, ql: Qiling, user_data: dict) -> None:
        """
        Handles the hook when the 'get' command is reached in Qiling. Depending on the current
        status, it sends the AES key, IV, or plaintext over UART and tracks attempts.

        Args:
            ql (Qiling): The Qiling instance that controls the emulation.
            user_data (dict): Contains the AES key, IV, and plaintext to be transmitted.
        """
        match self.__status[0]:
            case AesQilingStatus.WAIT_CMD:
                self._uart.send_key(key=user_data["key"])
                self._track_attempts(ql=ql, data="key")  # Check retry limit
            case AesQilingStatus.KEY_SET:
                self._uart.get_response()
                self._retry_counter = 0  # Reset retry counter
                if not user_data["iv"]:
                    self._uart.send_pt(pt=user_data["plaintext"])
                    self._track_attempts(ql=ql, data="plaintext")
                else:
                    self._uart.send_iv(iv=user_data["iv"])
                    self._track_attempts(ql=ql, data="iv")
            case AesQilingStatus.IV_SET:
                self._uart.get_response()
                self._retry_counter = 0  # Reset retry counter
                self._uart.send_pt(pt=user_data["plaintext"])
                self._track_attempts(ql=ql, data="plaintext")
            case AesQilingStatus.ENC_DONE:
                res: str = self._uart.get_response()
                self._retry_counter = 0  # Reset retry counter
                ql.log.info("Encryption done!")
                ql.log.info(f"Ciphertext: {res}")
                ql.log.info("Quitting Qiling..")
                ql.stop()

    def __hook_function_add_cmd_reached(self, ql: Qiling) -> None:
        """
        Handles the hook when the 'add' command is reached in Qiling. It registers the command
        and updates the status based on the command received.

        Args:
            ql (Qiling): The Qiling instance that controls the emulation.
        """
        command, data_length = get_command_received(ql=ql)
        self._uart.register_command(command, data_length)
        if command == "q":
            self.__status[0] = AesQilingStatus.WAIT_CMD
            self.logger.info("All commands registered correctly!")
        else:
            self.logger.info(f"Command registered successfully ({command}, {data_length})")

    def __hook_function_add_key_reached(self, ql: Qiling) -> None:
        """
        Handles the hook when the 'add key' command is reached. It logs the key and updates
        the status to indicate that the key has been set.

        Args:
            ql (Qiling): The Qiling instance that controls the emulation.
        """
        log_data_received(ql=ql, description="key")
        self.__status[0] = AesQilingStatus.KEY_SET

    def __hook_function_add_iv_reached(self, ql: Qiling) -> None:
        """
        Handles the hook when the 'add IV' command is reached. It logs the IV and updates
        the status to indicate that the IV has been set.

        Args:
            ql (Qiling): The Qiling instance that controls the emulation.
        """
        log_data_received(ql=ql, description="iv")
        self.__status[0] = AesQilingStatus.IV_SET

    def __hook_function_enc_reached(self, ql: Qiling) -> None:
        """
        Handles the hook when the 'encrypt' command is reached. It logs the plaintext
        and updates the status to indicate that encryption is done.

        Args:
            ql (Qiling): The Qiling instance that controls the emulation.
        """
        log_data_received(ql=ql, description="plaintext")
        self.__status[0] = AesQilingStatus.ENC_DONE

    def hook_cmds(self, ql: Qiling, sym_parser: SymParser, target_data: list) -> None:  #TODO: what about the function to get the plaintext?
        """
        Hooks AES-related commands to their respective functions within Qiling.

        Args:
            ql (Qiling): The Qiling instance that controls the emulation.
            target_data (list): A list containing the AES key, plaintext, and IV (if applicable).
        """
        if self.settings["execution_mode"] == "direct":
            self.__prepare_direct_call(ql, sym_parser, target_data)
            return

        logger = logging.getLogger(__name__)
        logger.setLevel(logging.getLogger().level)
        # Determine if an IV is used
        use_iv: bool = (
                len([item for item in target_data if (item is not None and item != "")]) > 2
        )

        # Prepare the target data as a dictionary
        td: dict = {
            "key": target_data[0],
            "plaintext": target_data[1],
            "iv": target_data[2] if use_iv else None,
        }

        # Retrieve the symbol addresses from the ELF file, based on the JSON config file.
        # Takes into account the case when some aren't specified in the config file due to them not being applicable (and so shouldn't be hooked)
        add_cmd = sym_parser.get_symbol_by_name(name=self.settings['add_cmd']) if self.settings['add_cmd'] != '' else None
        get_cmd = sym_parser.get_symbol_by_name(name=self.settings['get_cmd']) if self.settings['get_cmd'] != '' else None
        key_cmd = sym_parser.get_symbol_by_name(name=self.settings['key_cmd']) if self.settings['key_cmd'] != '' else None
        enc_cmd = sym_parser.get_symbol_by_name(name=self.settings['enc_cmd']) if self.settings['enc_cmd'] != '' else None

        if use_iv:
            iv_cmd = sym_parser.get_symbol_by_name(name=self.settings['iv_cmd'])

        # Hook the respective functions to the Qiling addresses
        if add_cmd is not None:
            ql.hook_address(self.__hook_function_add_cmd_reached, address=add_cmd)
        if get_cmd is not None:
            ql.hook_address(self.__hook_function_get_cmd_reached, address=get_cmd, user_data=td)
        if key_cmd is not None:
            ql.hook_address(self.__hook_function_add_key_reached, address=key_cmd)
        else:
            logger.info(f"Key command (key_cmd) not specified in the configuration file, or not found in the ELF file. Skipping key command hooking.\n"
                  f"This is likely an error, how are you going to send the key to the target?")
        if enc_cmd is not None:
            ql.hook_address(self.__hook_function_enc_reached, address=enc_cmd)
        else:
            logger.info(f"Encryption command (enc_cmd) not specified in the configuration file, or not found in the ELF file. Skipping encryption command hooking.\n"
                  f"This is likely an error, how are you going to send the plaintext to the target/start the encryption?")

        if use_iv:
            ql.hook_address(self.__hook_function_add_iv_reached, address=iv_cmd)


    def get_profile_range(self, sym_parser: SymParser) -> tuple:
        """
        Returns a tuple representing the address range of the AES profile in Qiling.

        Returns:
            tuple: A tuple containing the start and end addresses of the AES commands.
        """
        begin = sym_parser.get_symbol_by_name(name=self.settings["trace_start"])
        end = sym_parser.get_symbol_by_name(name=self.settings["trace_end"])
        return (begin, end)

    def init_uart(self, ql, input_format) -> None:
        self.input_format = input_format
        if self.settings["execution_mode"] == "direct":
            return
        self._uart = AesUartHandler(ql=ql, input_format=input_format)

    def __prepare_direct_call(
        self, ql: Qiling, sym_parser: SymParser, target_data: list
    ) -> None:
        """Invoke an AES routine directly using its ARM calling convention.

        The RP2350 challenge uses USB stdio rather than the SimpleSerial UART
        protocol.  Direct invocation keeps the trace focused on ``decrypt`` and
        avoids requiring a full USB controller and Pico SDK runtime model.
        """

        convert = (
            (lambda value: value.encode("utf-8"))
            if self.input_format == "plaintext"
            else bytes.fromhex
        )
        key = convert(target_data[0])
        plaintext = convert(target_data[1])

        if len(key) > 128:
            raise ValueError("The RP2350 decrypt routine accepts at most 128 key bytes")
        if len(plaintext) > 32:
            raise ValueError("The RP2350 decrypt routine accepts at most 32 data bytes")

        workspace = self.settings["workspace_address"]
        key_address = workspace
        salt_address = workspace + 0x100
        iv_address = workspace + 0x120
        data_address = workspace + 0x140

        ql.mem.write(key_address, key.ljust(128, b"\0"))
        ql.mem.write(salt_address, bytes(32))
        ql.mem.write(iv_address, bytes(32))
        ql.mem.write(data_address, plaintext.ljust(32, b"\0"))

        stack_address = self.settings["stack_address"]
        ql.arch.regs.sp = stack_address
        ql.mem.write_ptr(stack_address, 1, 4)  # fifth argument: nblk
        ql.arch.regs.r0 = key_address
        ql.arch.regs.r1 = salt_address
        ql.arch.regs.r2 = iv_address
        ql.arch.regs.r3 = data_address

        entry = sym_parser.get_symbol_by_name(self.settings["enc_cmd"])
        stop_address = sym_parser.get_symbol_by_name("__flash_binary_end")
        ql.arch.regs.lr = stop_address | 1
        ql.arch.regs.pc = entry

        def stop_after_call(qiling: Qiling) -> None:
            result = bytes(qiling.mem.read(data_address, 16)).hex()
            self.logger.info("Encryption done!")
            self.logger.info("Ciphertext: %s", result)
            qiling.stop()

        ql.hook_address(stop_after_call, stop_address)

    def get_algorithm_name(self):
        return "AES"
