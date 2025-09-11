from armchair.utils.helpers import (
    TargetResponse,
    parse_usart_res,
)

from qiling import Qiling
import logging


class UartHandler:
    """
    Base class for handling UART communication with the Qiling emulated hardware.

    Attributes:
        ql (Qiling): The Qiling instance controlling the emulation.
    """

    def __init__(self, ql: Qiling, input_format: str) -> None:
        """
        Initializes the UartHandler with the given Qiling instance.

        Args:
            ql (Qiling): The Qiling instance controlling the emulation.
        """
        self.ql: Qiling = ql
        self.input_format: str = input_format

    def get_response(self) -> str:
        """
        Receives and parses the UART response from the emulated hardware.

        Returns:
            str: The parsed response from the UART, it will always be a hex string

        Raises:
            Exception: If there's an error while receiving or parsing the response.
        """
        try:
            # Receive bytes from the USART1 interface
            res_bytes: bytes = self.ql.hw.usart1.recv(256)
            # Parse the received bytes into a string response
            response: str = parse_usart_res(res_bytes=res_bytes)

            # Check if the response indicates an error
            if response == TargetResponse.ERR.value:
                self.ql.log.error(
                    msg=f"The data has not been correctly received, the uart returned '{response}', stopping emulation"
                )
                self.ql.stop()  # Stop the emulation if an error occurred
                raise Exception("Simulation stopped due to UART error")
            return response
        except Exception as e:
            raise Exception(
                f"Error: something went wrong while getting or parsing the uart response: {e}."
            )

    def _send_cmd(self, cmd: bytes) -> Exception | None:
        """
        Sends a command over the UART interface to the target device.

        Args:
            cmd (bytes): The command to send over UART.

        Raises:
            Exception: If there is an error while sending the command.
        """
        try:
            # Log the command being sent, represented as the first byte's ASCII character
            self.ql.log.info(msg=f"Sending '{chr(cmd[0])}' command... Full command is: {cmd}")
            # Send the command over USART1
            self.ql.hw.usart1.send(cmd)
        except Exception as e:
            raise Exception(f"Sending '{chr(cmd[0])}' command resulted in: {e}.")
