from armchair.components.qiling_profile import QilingProfile
from armchair.components.sym_parser import SymParser
from armchair.targets.ascon.ascon_uart_interface import AsconUartHandler
from armchair.utils.enums import AsconQilingStatus
from armchair.utils.helpers import log_data_received, get_command_received

from qiling import Qiling


class AsconQilingProfile(QilingProfile):
    def __init__(self) -> None:
        super().__init__()
        self.__status: list[AsconQilingStatus] = [AsconQilingStatus.INIT]

    def __hook_function_get_cmd_reached(self, ql: Qiling, user_data: dict) -> None:
        match self.__status[0]:
            case AsconQilingStatus.WAIT_CMD:
                self._uart.send_key(key=user_data["key"])
                self._track_attempts(ql=ql, data="key")  # Check retry limit
            case AsconQilingStatus.KEY_SET:
                self._uart.get_response()
                self._retry_counter = 0  # Reset retry counter
                self._uart.send_nonce(nonce=user_data["nonce"])
                self._track_attempts(ql=ql, data="nonce")  # Check retry limit
            case AsconQilingStatus.NONCE_SET:
                self._uart.get_response()
                self._retry_counter = 0  # Reset retry counter
                if not user_data["AD"]:
                    self._uart.send_pt(pt=user_data["plaintext"])
                    self._track_attempts(ql=ql, data="plaintext")
                else:
                    self._uart.send_ad(ad=user_data["AD"])
                    self._track_attempts(ql=ql, data="AD")
            case AsconQilingStatus.AD_SET:
                self._uart.get_response()
                self._retry_counter = 0  # Reset retry counter
                self._uart.send_pt(pt=user_data["plaintext"])
                self._track_attempts(ql=ql, data="plaintext")
            case AsconQilingStatus.ENC_DONE:
                res: str = self._uart.get_response()
                self._retry_counter = 0  # Reset retry counter
                ql.log.info("Encryption done!")

                ciphertext = res[:-32]  # All except the last 16 bytes (ciphertext)
                tag = res[-32:]  # The last 16 bytes (tag)

                ql.log.info(f"Ciphertext: {ciphertext}")
                ql.log.info(f"Tag: {tag}")
                ql.log.info("Quitting Qiling..")

                ql.stop()

    def __hook_function_add_cmd_reached(self, ql: Qiling) -> None:
        command, data_length = get_command_received(ql=ql)
        if command == "q":
            self.__status[0] = AsconQilingStatus.WAIT_CMD
            ql.log.info("All commands registered correctly!")
        else:
            ql.log.info(f"Command registered successfully ({command}, {data_length})")

    def __hook_function_add_key_reached(self, ql: Qiling) -> None:
        log_data_received(ql=ql, description="key")
        self.__status[0] = AsconQilingStatus.KEY_SET

    def __hook_function_add_ad_reached(self, ql: Qiling) -> None:
        log_data_received(ql=ql, description="ad")
        self.__status[0] = AsconQilingStatus.AD_SET

    def __hook_function_add_nonce_reached(self, ql: Qiling) -> None:
        log_data_received(ql=ql, description="nonce")
        self.__status[0] = AsconQilingStatus.NONCE_SET

    def __hook_function_enc_reached(self, ql: Qiling) -> None:
        log_data_received(ql=ql, description="plaintext")
        self.__status[0] = AsconQilingStatus.ENC_DONE

    def hook_cmds(self, ql: Qiling, sym_parser: SymParser, target_data: list) -> None:
        # Determine if AD is used
        use_ad: bool = (
            len([item for item in target_data if (item != None and item != "")]) > 3
        )

        # Prepare the target data as a dictionary
        td: dict = {
            "key": target_data[0],
            "plaintext": target_data[1],
            "nonce": target_data[2],
            "AD": target_data[3] if use_ad else None,
        }

        # Retrieve the symbol addresses from the ELF file
        add_cmd = sym_parser.get_symbol_by_name(name="simpleserial_addcmd")
        get_cmd = sym_parser.get_symbol_by_name(name="simpleserial_get")
        key_cmd = sym_parser.get_symbol_by_name(name="set_key")
        n_cmd = sym_parser.get_symbol_by_name(name="set_nonce")
        enc_cmd = sym_parser.get_symbol_by_name(name="encrypt_plaintext")

        if use_ad:
            ad_cmd = sym_parser.get_symbol_by_name(name="set_associated_data")

        # Hook the respective functions to the Qiling addresses
        ql.hook_address(self.__hook_function_add_cmd_reached, address=add_cmd)
        ql.hook_address(
            self.__hook_function_get_cmd_reached, address=get_cmd, user_data=td
        )
        ql.hook_address(self.__hook_function_add_key_reached, address=key_cmd)
        ql.hook_address(self.__hook_function_add_nonce_reached, address=n_cmd)
        ql.hook_address(self.__hook_function_enc_reached, address=enc_cmd)

        if use_ad:
            ql.hook_address(self.__hook_function_add_ad_reached, address=ad_cmd)

    def get_profile_range(self, sym_parser: SymParser) -> tuple:
        enc_cmd = sym_parser.get_symbol_by_name(name="crypto_aead_encrypt")
        get_cmd = sym_parser.get_symbol_by_name(name="return_value")
        return (enc_cmd, get_cmd)

    def init_uart(self, ql, input_format) -> None:
        self._uart = AsconUartHandler(ql=ql, input_format=input_format)

    def get_algorithm_name(self):
        return "ASCON"
