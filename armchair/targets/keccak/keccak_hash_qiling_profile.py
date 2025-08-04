from armchair.components.qiling_profile import QilingProfile
from armchair.components.sym_parser import SymParser
from armchair.targets.keccak.keccak_uart_interface import KeccakHashUartHandler
from armchair.utils.enums import KeccakQilingStatus
from armchair.utils.helpers import log_data_received, get_command_received

from qiling import Qiling


class KeccakHashQilingProfile(QilingProfile):
    def __init__(self) -> None:

        super().__init__()
        self.__status: list[KeccakQilingStatus] = [KeccakQilingStatus.INIT]

    def __hook_function_get_cmd_reached(self, ql: Qiling, user_data: dict) -> None:
        match self.__status[0]:
            case KeccakQilingStatus.WAIT_CMD:
                self._uart.send_pt(pt=user_data["plaintext"])
                self._track_attempts(ql=ql, data="plaintext")  # Check retry limit
            case KeccakQilingStatus.HASH_DONE:
                res: str = self._uart.get_response()
                self._retry_counter = 0  # Reset retry counter
                ql.log.info("Hashing done!")
                ql.log.info(f"Hash: {res}")
                ql.log.info("Quitting Qiling..")
                ql.stop()

    def __hook_function_add_cmd_reached(self, ql: Qiling) -> None:
        command, data_length = get_command_received(ql=ql)
        if command == "q":
            self.__status[0] = KeccakQilingStatus.WAIT_CMD
            ql.log.info("All commands registered correctly!")
        else:
            ql.log.info(f"Command registered successfully ({command}, {data_length})")

    def __hook_function_hash_reached(self, ql: Qiling) -> None:
        log_data_received(ql=ql, description="plaintext")
        self.__status[0] = KeccakQilingStatus.HASH_DONE

    def hook_cmds(self, ql: Qiling, sym_parser: SymParser, target_data: list) -> None:
        # Prepare the target data as a dictionary
        td: dict = {
            "plaintext": target_data[0],
        }

        # Retrieve the symbol addresses from the ELF file
        add_cmd = sym_parser.get_symbol_by_name(name="simpleserial_addcmd")
        get_cmd = sym_parser.get_symbol_by_name(name="simpleserial_get")
        hash_cmd = sym_parser.get_symbol_by_name(name="shake_hash")

        # Hook the respective functions to the Qiling addresses
        ql.hook_address(self.__hook_function_add_cmd_reached, address=add_cmd)
        ql.hook_address(
            self.__hook_function_get_cmd_reached, address=get_cmd, user_data=td
        )
        ql.hook_address(self.__hook_function_hash_reached, address=hash_cmd)

    def get_profile_range(self, sym_parser: SymParser) -> tuple:
        enc_cmd = sym_parser.get_symbol_by_name(name="shake_hash")
        get_cmd = sym_parser.get_symbol_by_name(name="simpleserial_put")
        return (enc_cmd, get_cmd)

    def init_uart(self, ql, input_format) -> None:
        self._uart = KeccakHashUartHandler(ql=ql, input_format=input_format)

    def get_algorithm_name(self):
        return "KECCAK"
