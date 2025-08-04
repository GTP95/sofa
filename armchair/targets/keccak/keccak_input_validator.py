from armchair.utils.helpers import get_hex_str_bytes_nr
from armchair.components.input_validator import InputValidator


class KeccakHashInputValidator(InputValidator):
    def __init__(self) -> None:
        super().__init__()

    def validate_inputs(self, target_data, target_settings) -> None:
        s_pt_len: int = target_settings["plaintext_length"]
        plaintext: str = target_data[0]
        # Validate plaintext length
        pt_len: int = get_hex_str_bytes_nr(string=plaintext)
        if pt_len != s_pt_len:
            raise ValueError(
                f"Plaintext byte size mismatch: expected {s_pt_len} bytes, but got {pt_len} bytes."
            )
