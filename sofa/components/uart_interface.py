from sofa.utils.helpers import (
    TargetResponse,
    parse_usart_res,
)

from qiling import Qiling
import logging
import time


class UartError(RuntimeError):
    """Raised when UART communication/parsing fails in a way that should stop the emulation."""
    def __init__(self, message: str, *, raw: bytes = b"", parsed: str | None = None) -> None:
        super().__init__(message)
        self.raw = raw
        self.parsed = parsed


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
        self._command_lengths: dict[str, int] = {}

    def register_command(self, command: str, data_length: int) -> None:
        """Remember the payload length advertised by the running firmware."""
        self._command_lengths[command] = data_length

    def _recv_chunk(self, chunk_size: int) -> bytes:
        """
        Receive a chunk from USART1, supporting both recv() and recv(size) APIs.
        """
        try:
            return self.ql.hw.usart1.recv(chunk_size)
        except TypeError:
            # Some Qiling USART implementations expose recv() with no args
            return self.ql.hw.usart1.recv()

    def get_response(self, *, timeout_s: float = 2.5, chunk_size: int = 256) -> str:
        """
        Receives and parses the UART response from the emulated hardware.

        This waits until a full SimpleSerial-like frame is observed (terminator 'z00'),
        then parses it via parse_usart_res().

        Returns:
            str: The parsed response from the UART.

        Raises:
            UartError: If there's an error while receiving or parsing the response.
        """
        start = time.monotonic()
        raw_collected = bytearray()

        try:
            while (time.monotonic() - start) < timeout_s:
                chunk = self._recv_chunk(chunk_size)
                if chunk:
                    raw_collected.extend(chunk)

                    # SimpleSerial framing heuristic: ACK/data frames end with 'z00'
                    # We look for it in ASCII to decide we likely have a complete frame.
                    ascii_view = raw_collected.decode("ascii", errors="ignore")
                    if "z00" not in ascii_view:
                        continue

                    response = parse_usart_res(res_bytes=raw_collected)

                    if response == TargetResponse.ERR.value:
                        self.logger.error(
                            "UART parsed as ERR. raw=%s ascii=%r",
                            bytes(raw_collected).hex(),
                            ascii_view[-200:],
                        )
                        self.ql.stop()
                        raise UartError(
                            "Simulation stopped due to UART error",
                            raw=bytes(raw_collected),
                            parsed=response,
                        )

                    if response:
                        return response

                time.sleep(0.001)

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
        """
        try:
            command = chr(cmd[0])
            expected = self._command_lengths.get(command)
            if expected is not None:
                # SimpleSerial v1 sends two ASCII hex characters per byte.
                payload_length = len(cmd[1:].rstrip(b"\r\n"))
                if payload_length != expected * 2:
                    raise UartError(
                        f"UART command {command!r}: firmware expects {expected} bytes "
                        f"({expected * 2} hex characters), got {payload_length} hex "
                        "characters. Match the input/configuration to the firmware "
                        "build (PTLEN for plaintext)."
                    )
            self.logger.info(msg=f"Sending '{chr(cmd[0])}' command... Full command is: {cmd!r}")
            self.ql.hw.usart1.send(cmd)
        except Exception as e:
            raise Exception(f"Sending '{chr(cmd[0])}' command resulted in: {e}.") from e
