import csv

from armchair.utils.helpers import info_t
from armchair.utils.constants import (
    DEFAULT_INPUT_CSV_PATH,
    DEFAULT_NR_OF_INPUTS,
)

from armchair.components.input_generator import InputsGenerator


class KeccakHashInputsGenerator(InputsGenerator):
    def __init__(self) -> None:
        super().__init__()

    def generate_inputs_csv(
        self,
        target_settings: dict,
        nr_of_inputs: int = DEFAULT_NR_OF_INPUTS,
        input_path: str = DEFAULT_INPUT_CSV_PATH,
    ) -> None:
        s_pt_len: int = target_settings["plaintext_length"]
        with open(file=input_path, mode="w", newline="") as file:
            writer = csv.writer(file)
            # Write header
            writer.writerow(["Plaintext"])
            for _ in range(nr_of_inputs):
                plaintext: str = self._generate_random_hex_string(num_bytes=s_pt_len)
                writer.writerow([plaintext])
        print(
            f"{info_t} {target_settings['function']} CSV file '{input_path}' created with {nr_of_inputs} entries."
        )
