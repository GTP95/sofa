from armchair.utils.helpers import (
    get_iv_cmd,
    get_key_cmd,
    get_pt_cmd,
)

from qiling import Qiling
import logging

from armchair.components.uart_interface import UartHandler


class AesUartHandler(UartHandler):
    """
    Handles AES-specific UART commands, such as sending the key, IV, and plaintext.
    Inherits from UartHandler.
    """

    def __init__(self, ql: Qiling, input_format: str) -> None:
        super().__init__(ql=ql, input_format=input_format)

    def send_key(self, key: str) -> None:
        """
        Sends the AES key to the target device over UART.

        Args:
            key (str): The AES key to be sent.

        Raises:
            Exception: If there's an error while sending the key.
        """
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.getLogger().level)
        try:
            # Convert the key string into a command
            key_cmd: bytes = get_key_cmd(key=key, input_format=self.input_format)
            # Send the command using the inherited method
            self._send_cmd(cmd=key_cmd)
            logger.info(f"Sent the following key command over UART: {key_cmd}")
        except Exception as e:
            raise Exception(
                f"Error: something went wrong while sending the key: {e.args[0]}."
            )

    def send_iv(self, iv: str) -> None:
        """
        Sends the AES initialization vector (IV) to the target device over UART.

        Args:
            iv (str): The IV to be sent.

        Raises:
            Exception: If there's an error while sending the IV.
        """
        try:
            # Convert the IV string into a command
            iv_cmd: bytes = get_iv_cmd(iv=iv, input_format=self.input_format)
            # Send the command using the inherited method
            self._send_cmd(cmd=iv_cmd)
        except Exception as e:
            raise Exception(
                f"Error: something went wrong while sending the iv: {e.args[0]}."
            )

    def send_pt(self, pt: str) -> None:
        """
        Sends the AES plaintext to the target device over UART.

        Args:
            pt (str): The plaintext to be sent.

        Raises:
            Exception: If there's an error while sending the plaintext.
        """
        try:
            # Convert the plaintext string into a command
            pt_cmd: bytes = get_pt_cmd(pt=pt, input_format=self.input_format)
            # Send the command using the inherited method
            self._send_cmd(cmd=pt_cmd)
        except Exception as e:
            raise Exception(
                f"Error: something went wrong while sending the pt: {e.args[0]}."
            )
