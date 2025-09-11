import csv, logging

from armchair.utils.constants import (
    ASCON_KEY_SIZE,
    ASCON_NONCE_SIZE,
    DEFAULT_INPUT_CSV_PATH,
    DEFAULT_NR_OF_INPUTS,
)

from armchair.components.input_generator import InputsGenerator


class AsconInputsGenerator(InputsGenerator):
    def __init__(self) -> None:
        super().__init__()
        self.__k_len: int = ASCON_KEY_SIZE
        self.__n_len: int = ASCON_NONCE_SIZE
        self.logger=logging.getLogger(__name__)

    def generate_inputs_csv(
        self,
        target_settings: dict,
        nr_of_inputs: int = DEFAULT_NR_OF_INPUTS,
        input_path: str = DEFAULT_INPUT_CSV_PATH,
    ) -> None:
        s_ad_len: int = target_settings["ad_length"]
        s_pt_len: int = target_settings["plaintext_length"]
        use_ad: bool = s_ad_len != 0

        with open(file=input_path, mode="w", newline="") as file:
            writer = csv.writer(file)
            # Write header
            writer.writerow(["Key", "Plaintext", "Nonce", "AD"])
            for _ in range(nr_of_inputs):
                key: str = self._generate_random_hex_string(num_bytes=self.__k_len)
                plaintext: str = self._generate_random_hex_string(num_bytes=s_pt_len)
                nonce: str = self._generate_random_hex_string(num_bytes=self.__n_len)
                if use_ad:
                    ad: str = self._generate_random_hex_string(num_bytes=s_ad_len)
                    writer.writerow([key, plaintext, nonce, ad])
                else:
                    writer.writerow([key, plaintext, nonce])
        self.logger.info(
            f"ASCON CSV file '{input_path}' created with {nr_of_inputs} entries."
        )
