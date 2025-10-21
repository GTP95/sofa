from sofa.utils.helpers import (
    get_key_cmd,
    get_pt_cmd,
    get_ad_cmd,
    get_nonce_cmd,
)

from qiling import Qiling

from sofa.components.uart_interface import UartHandler


class AsconUartHandler(UartHandler):
    def __init__(self, ql: Qiling, input_format: str) -> None:
        super().__init__(ql=ql, input_format=input_format)

    def send_key(self, key: str) -> None:
        try:
            # Convert the key string into a command
            key_cmd: bytes = get_key_cmd(key=key, input_format=self.input_format)
            # Send the command using the inherited method
            self._send_cmd(cmd=key_cmd)
        except Exception as e:
            raise Exception(
                f"Error: something went wrong while sending the key: {e.args[0]}."
            )

    def send_ad(self, ad: str) -> None:
        try:
            # Convert the IV string into a command
            ad_cmd: bytes = get_ad_cmd(ad=ad, input_format=self.input_format)
            # Send the command using the inherited method
            self._send_cmd(cmd=ad_cmd)
        except Exception as e:
            raise Exception(
                f"Error: something went wrong while sending the ad: {e.args[0]}."
            )

    def send_nonce(self, nonce: str) -> None:
        try:
            # Convert the IV string into a command
            n_cmd: bytes = get_nonce_cmd(nonce=nonce, input_format=self.input_format)
            # Send the command using the inherited method
            self._send_cmd(cmd=n_cmd)
        except Exception as e:
            raise Exception(
                f"Error: something went wrong while sending the nonce: {e.args[0]}."
            )

    def send_pt(self, pt: str) -> None:
        try:
            # Convert the plaintext string into a command
            pt_cmd: bytes = get_pt_cmd(pt=pt, input_format=self.input_format)
            # Send the command using the inherited method
            self._send_cmd(cmd=pt_cmd)
        except Exception as e:
            raise Exception(
                f"Error: something went wrong while sending the pt: {e.args[0]}."
            )
