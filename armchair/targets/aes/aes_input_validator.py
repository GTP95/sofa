from armchair.utils.helpers import (
    get_hex_str_bytes_nr,
    warn_t,
)

from armchair.utils.constants import AES_BLOCK_SIZE
from armchair.components.input_validator import InputValidator


class AesInputValidator(InputValidator):
    """
    This class validates inputs specific to AES encryption, including optional PKCS7 padding.

    Attributes:
        __use_iv (bool): Specifies whether an initialization vector (IV) is required.
        __pt_len (int): Length of the plaintext in bytes.
        __k_len (int): Length of the key in bytes.
        __iv_len (int): Length of the IV, which is fixed at the AES block size.
        __key (str): The provided encryption key.
        __iv (str): The provided initialization vector.
        __plaintext (str): The provided plaintext.
    """

    def __init__(self) -> None:
        """
        Initializes the AES input validator with the target settings, data, and padding option.

        Args:
            target_settings (dict): AES-specific settings such as plaintext and key lengths.
            target_data (dict): Input data including key, plaintext, and IV.
        """
        super().__init__()
        self.__iv_len: int = AES_BLOCK_SIZE  # this is always the same

    def validate_inputs(self, target_data, target_settings) -> None:
        """
        Validates the sizes of the plaintext, key, and IV against the expected values specified in the configuration.

        For plaintext:
            - Checks if the length of the plaintext matches the expected length.
            - If padding is enabled and the plaintext size is not a multiple of the AES block size, it pads the plaintext and validates again.
            - If the size is incorrect and padding is not applicable, raises a ValueError.

        For the key:
            - Verifies that the key size matches the expected length.
            - Raises a ValueError if the key size is incorrect.

        For the IV (Initialization Vector):
            - If an IV is expected, checks the IV size and compares it to the expected length.
            - If the mode is ECB and the user provided the IV a warning is issued.
            - Raises a ValueError if the IV size is incorrect.

        Raises:
            ValueError: If any of the input sizes (plaintext, key, or IV) do not match the expected sizes, and padding does not resolve the issue.
        """
        s_use_iv: bool = target_settings["use_iv"]
        s_pt_len: int = target_settings["plaintext_length"]
        s_k_len: int = target_settings["key_length"]

        key: str = target_data[0]
        plaintext: str = target_data[1]
        iv: str = target_data[2] if s_use_iv else None

        # Validate plaintext length
        pt_len: int = get_hex_str_bytes_nr(string=plaintext)
        if pt_len != s_pt_len:
            raise ValueError(
                f"Plaintext byte size mismatch: expected {s_pt_len} bytes, but got {pt_len} bytes."
            )

        # Validate key length
        k_len: int = get_hex_str_bytes_nr(string=key)
        if k_len != s_k_len:
            raise ValueError(
                f"Key byte size mismatch: expected {s_k_len} bytes, but got {k_len} bytes."
            )

        # Validate IV length, if IV is expected
        if s_use_iv:
            iv_len: int = get_hex_str_bytes_nr(string=iv)
            if iv_len != self.__iv_len:
                raise ValueError(
                    f"IV byte size mismatch: expected {self.__iv_len} bytes, but got {iv_len} bytes."
                )

        # Validate if IV were not expected
        if not s_use_iv and iv != None:
            f"{warn_t} IVs were provided even if not needed therefore that input will be ignored"
