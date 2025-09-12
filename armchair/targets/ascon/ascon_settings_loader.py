from armchair.components.settings_loader import SettingsLoader


class AsconSettingsLoader(SettingsLoader):
    def __init__(self, json_path=None) -> None:
        super().__init__(target="ASCON", json_path=json_path)
        self._parse_target_config()

    def _parse_target_config(self) -> None:
        try:
            # Extract and convert relevant fields from the raw settings
            ad_length: int = int(self._settings["ad_length"])
            plaintext_length: int = int(self._settings["plaintext_length"])

            # Store the parsed settings in the _parsed_settings dictionary
            self._parsed_settings = {
                "platform": self._settings["platform"],
                "target": self._settings["target"],
                "ad_length": ad_length,
                "plaintext_length": plaintext_length,
            }
        except Exception as e:
            raise Exception(
                f"An unexpected error occurred while parsing the JSON config file: {e}"
            )

    def get_ad_len(self) -> int:
        return self._parsed_settings["ad_length"]

    def get_pt_len(self) -> int:
        """
        Returns the length of the plaintext for AES encryption.

        Returns:
            int: The plaintext length in bytes.
        """
        return self._parsed_settings["plaintext_length"]
