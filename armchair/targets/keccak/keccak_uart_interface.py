from armchair.utils.helpers import get_pt_cmd

from qiling import Qiling

from armchair.components.uart_interface import UartHandler


class KeccakHashUartHandler(UartHandler):
    def __init__(self, ql: Qiling, input_format: str) -> None:
        super().__init__(ql=ql, input_format=input_format)

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
