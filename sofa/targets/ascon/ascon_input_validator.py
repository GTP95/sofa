from sofa.utils.helpers import get_hex_str_bytes_nr
from sofa.utils.constants import (
    ASCON_KEY_SIZE,
    ASCON_NONCE_SIZE,
)

from sofa.components.input_validator import InputValidator


class AsconInputValidator(InputValidator):
    def __init__(self):
        super().__init__()
        self.__k_len: int = ASCON_KEY_SIZE
        self.__n_len: int = ASCON_NONCE_SIZE

    def validate_inputs(self, target_data, target_settings) -> None:
        s_pt_len: int = target_settings["plaintext_length"]
        s_ad_len: int = target_settings["ad_length"]
        s_use_ad: bool = s_ad_len != 0

        key: str = target_data[0]
        ad: str = target_data[1]
        nonce: str = target_data[2]
        plaintext: str = target_data[3]

        # Validate plaintext length
        pt_len: int = get_hex_str_bytes_nr(string=plaintext)
        if pt_len != s_pt_len:
            raise ValueError(
                f"Plaintext byte size mismatch: expected {s_pt_len} bytes, but got {pt_len} bytes."
            )

        # Validate key length
        k_len: int = get_hex_str_bytes_nr(string=key)
        if k_len != self.__k_len:
            raise ValueError(
                f"Key byte size mismatch: expected {self.__k_len} bytes, but got {k_len} bytes."
            )

        # Validate nonce length
        n_len: int = get_hex_str_bytes_nr(string=nonce)
        if n_len != self.__n_len:
            raise ValueError(
                f"Nonce byte size mismatch: expected {self.__n_len} bytes, but got {n_len} bytes."
            )

        if k_len != n_len:
            raise ValueError(
                f"Nonce/Key byte size mismatch: Nonce and key should be both 16 bytes, got {n_len} and {k_len} respectively."
            )

        # Validate ad length, if ad is expected
        if s_use_ad:
            ad_len: int = get_hex_str_bytes_nr(string=ad)
            if ad_len != s_ad_len:
                raise ValueError(
                    f"AD byte size mismatch: expected {s_ad_len} bytes, but got {ad_len} bytes."
                )
