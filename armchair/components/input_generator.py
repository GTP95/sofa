import random


class InputsGenerator:
    """
    Base class for generating input data.

    Attributes:
        _target_settings (dict): Stores configuration settings for the target.
    """

    def __init__(self) -> None:
        pass

    def _generate_random_hex_string(self, num_bytes) -> str:
        """
        Generates a random hexadecimal string of the specified byte length.

        Args:
            num_bytes (int): The length in bytes of the string to generate.

        Returns:
            str: A random hex string of twice the specified byte length.
        """
        return "".join(random.choices("0123456789abcdef", k=num_bytes * 2))

    def generate_inputs_csv(
        self,
        target_settings: dict,
        nr_of_inputs: int = 10,
        input_path: str = "input-csv.csv",
    ) -> None:
        """
        Placeholder method to be implemented in subclasses for generating CSV files with inputs.

        Args:
            target_settings (dict): The settings containing the specifics of the inputs to be generated.
        """
        pass
