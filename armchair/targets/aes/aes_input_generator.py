import logging

from armchair.utils.constants import (
    AES_BLOCK_SIZE,
    DEFAULT_INPUT_CSV_PATH,
    DEFAULT_NR_OF_INPUTS,
)
from armchair.components.input_generator import InputsGenerator

import csv


class AesInputsGenerator(InputsGenerator):
    """
    Generates inputs specific to the AES encryption system.

    Attributes:
        __use_iv (bool): Specifies whether to use an initialization vector (IV).
        __pt_len (int): Length of the plaintext in bytes.
        __k_len (int): Length of the key in bytes.
        __iv_len (int): Length of the IV, which is fixed at the AES block size.
    """

    def __init__(self) -> None:
        super().__init__()
        self.__iv_len: int = AES_BLOCK_SIZE  # this is always the same
        self.logger=logging.getLogger(__name__)
        self.logger.setLevel(logging.getLogger().level)

    def generate_inputs_csv(
        self,
        target_settings: dict,
        nr_of_inputs: int = DEFAULT_NR_OF_INPUTS,
        input_path: str = DEFAULT_INPUT_CSV_PATH,
    ) -> None:
        """
        Generates a CSV file with random IVs, keys, and plaintexts.
        """
        use_iv: bool = target_settings["use_iv"]
        pt_len: int = target_settings["plaintext_length"]
        k_len: int = target_settings["key_length"]

        with open(file=input_path, mode="w", newline="") as file:
            writer = csv.writer(file)
            # Write header
            writer.writerow(["Key", "Plaintext", "IV"])
            for _ in range(nr_of_inputs):
                key: str = self._generate_random_hex_string(num_bytes=k_len)
                plaintext: str = self._generate_random_hex_string(num_bytes=pt_len)
                if use_iv:
                    iv: str = self._generate_random_hex_string(num_bytes=self.__iv_len)
                    writer.writerow([key, plaintext, iv])
                else:
                    writer.writerow([key, plaintext])
        self.logger.info(
            f"AES CSV file '{input_path}' created with {nr_of_inputs} entries."
        )
