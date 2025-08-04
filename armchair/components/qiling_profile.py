from armchair.utils.constants import MAX_ATTEMPTS


class QilingProfile:
    """
    A base class for managing a profile in the Qiling framework, handling retries and
    allowing specific commands to be hooked to the Qiling emulator.

    Attributes:
        _sym_parser: A symbol parser instance for retrieving addresses and symbols.
        _retry_counter (int): Counter for tracking the number of retry attempts.
        _uart (UartHandler): Instance of the uart interface used to communicate.
        __max_attempts (int): Maximum allowed attempts before raising an error.
    """

    def __init__(self) -> None:
        """
        Initializes the QilingProfile with a symbol parser and sets the retry counter to 0.

        """
        self._retry_counter = 0  # Counter for tracking attempts
        self._uart = None
        self.__max_attempts = (
            MAX_ATTEMPTS  # Maximum allowed attempts before raising an error
        )

    def _track_attempts(self, ql, data: str) -> None:
        """
        Increments the retry counter and checks if the retry limit is exceeded.

        Args:
            ql: The Qiling instance that manages the emulation.
            data (str): A description of the data being sent or processed (used for error reporting).
        """
        self._retry_counter += 1  # Increment counter for retries
        self.__check_retry_limit(ql=ql, data=data)  # Check if retry limit is exceeded

    def __check_retry_limit(self, ql, data: str) -> None:
        """
        Checks if the retry limit is exceeded and raises an error if necessary.

        Args:
            ql: The Qiling instance that manages the emulation.
            data (str): A description of the data being sent or processed (used for error reporting).

        Raises:
            Exception: If the retry limit is exceeded.
        """
        if self._retry_counter >= self.__max_attempts:
            ql.log.error(
                f"Maximum retry limit of {self.__max_attempts} while sending the {data}!"
            )
            raise Exception(
                f"Maximum retry limit of {self.__max_attempts} while sending the {data}!"
            )

    def hook_cmds(self, ql, sym_parser, target_data: list) -> None:
        """
        Placeholder method for hooking specific commands to addresses in Qiling.
        Intended to be overridden in subclasses for specific command handling.

        Args:
            ql: The Qiling instance that manages the emulation.
            target_data (list): The target-specific data needed for hooking commands.
        """
        pass

    def get_profile_range(self, sym_parser):
        """
        Placeholder method for getting the profile range.
        Intended to be overridden in subclasses for returning address ranges for the profile.

        Returns:
            None
        """
        pass

    def init_uart(self, ql, input_format):
        """
        Initialises the uart interface for communication.

        Returns:
            None
        """
        pass

    def init_symbols_parser(self, elf_path):
        """
        Initialises the uart interface for communication.

        Returns:
            None
        """
        pass

    def get_algorithm_name(self) -> None:
        pass
