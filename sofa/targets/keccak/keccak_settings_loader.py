from sofa.components.settings_loader import SettingsLoader


class KeccakHashSettingsLoader(SettingsLoader):
    def __init__(self, json_path=None) -> None:
        super().__init__(target="KECCAK", json_path=json_path)
        self._parse_target_config()

    def _parse_target_config(self) -> None:
        try:
            # Extract and convert relevant fields from the raw settings
            plaintext_length: int = int(self._settings["plaintext_length"])

            # Store the parsed settings in the _parsed_settings dictionary
            self._parsed_settings = {
                "platform": self._settings["platform"],
                "target": self._settings["target"],
                "function": self._settings["function"],
                "plaintext_length": plaintext_length,
            }
        except Exception as e:
            raise Exception(
                f"An unexpected error occurred while parsing the JSON config file: {e}"
            )

    def get_pt_len(self) -> int:
        """
        Returns the length of the plaintext for AES encryption.

        Returns:
            int: The plaintext length in bytes.
        """
        return self._parsed_settings["plaintext_length"]
