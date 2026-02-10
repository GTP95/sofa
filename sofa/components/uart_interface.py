from sofa.utils.helpers import (
    TargetResponse,
    parse_usart_res,
)

from qiling import Qiling
import logging
import time


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
        self.logger: logging.Logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.getLogger().level)
        self._rx_buf: bytearray = bytearray()

    def get_response(self, *, timeout_s: float = 1.0, chunk_size: int = 256) -> str:
        """
        Receives and parses the UART response from the emulated hardware.

        Returns:
            str: The parsed response from the UART, it will always be a hex string

        Raises:
            UartError: If there's an error while receiving or parsing the response.
        """
        start = time.monotonic()
        raw_collected = bytearray()
        try:
            while (time.monotonic() - start) < timeout_s:
                # Receive bytes from the USART1 interface (may be partial/empty)
                chunk: bytes = self.ql.hw.usart1.recv(chunk_size)
                if chunk:
                    raw_collected.extend(chunk)

                    # Try parsing whatever we have so far.
                    # parse_usart_res should be robust to extra bytes / partial frames;
                    # if it isn't, we still gain visibility via raw logging below.
                    response: str = parse_usart_res(res_bytes=bytes(raw_collected))

                    if response == TargetResponse.ERR.value:
                        self.logger.error(
                            "UART returned ERR. raw=%s",
                            bytes(raw_collected).hex(),
                        )
                        self.ql.stop()
                        raise UartError(
                            "Simulation stopped due to UART error",
                            raw=bytes(raw_collected),
                            parsed=response,
                        )

                    # Heuristic: if parsing yields a non-empty non-ERR string, accept it.
                    if response:
                        return response

                # Avoid a tight busy loop if recv() returns b""
                time.sleep(0.001)

            # Timed out waiting for a valid response
            self.logger.error(
                "Timed out waiting for UART response after %.3fs. raw=%s",
                timeout_s,
                bytes(raw_collected).hex(),
            )
            self.ql.stop()
            raise UartError(
                f"Timed out waiting for UART response after {timeout_s:.3f}s",
                raw=bytes(raw_collected),
                parsed=None,
            )

        except UartError:
            raise
        except Exception as e:
            self.logger.exception(
                "Error while getting/parsing UART response. raw=%s",
                bytes(raw_collected).hex(),
            )
            raise UartError(
                "Error while getting or parsing the UART response",
                raw=bytes(raw_collected),
                parsed=None,
            ) from e

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
            self.logger.info(msg=f"Sending '{chr(cmd[0])}' command... Full command is: {cmd}")
            # Send the command over USART1
            self.ql.hw.usart1.send(cmd)
        except Exception as e:
            raise Exception(f"Sending '{chr(cmd[0])}' command resulted in: {e}.")


class UartError(RuntimeError):
    """Raised when UART communication/parsing fails in a way that should stop the emulation."""
    def __init__(self, message: str, *, raw: bytes = b"", parsed: str | None = None) -> None:
        super().__init__(message)
        self.raw = raw
        self.parsed = parsed