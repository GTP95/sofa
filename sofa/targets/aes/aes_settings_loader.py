import logging

from sofa.components.settings_loader import SettingsLoader


class AesSettingsLoader(SettingsLoader):
    """
    A subclass of SettingsLoader responsible for parsing AES-specific settings from the loaded JSON file.

    Methods:
        _parse_target_config: Parses AES-specific fields such as key length, plaintext length, IV usage, and masking.
        get_k_len: Returns the key length.
        get_use_iv: Returns whether the AES mode uses an initialization vector (IV).
        get_masked: Returns whether the AES encryption is masked.
        get_pt_len: Returns the plaintext length.
    """

    def __init__(self, json_path) -> None:
        """
        Initializes the AesSettingsLoader by calling the parent class's __init__ method and then parsing the configuration.
        """
        super().__init__(json_path)
        self._parse_target_config()
        self._logger=logging.getLogger(__name__)
        self._logger.setLevel(logging.getLogger().level)

    def _parse_target_config(self) -> None:
        """
        Parses AES-specific settings from the loaded JSON configuration.

        Extracts the key length, plaintext length, whether an IV is used, and whether masking is enabled.
        Populates the `_parsed_settings` dictionary with these values.

        Raises:
            Exception: If there is an issue parsing the settings.
        """
        try:
            # Extract and convert relevant fields from the raw settings
            key_length: int = int(self._settings["key_length"]) // 8  # Convert to bytes
            plaintext_length: int = int(self._settings["plaintext_length"])
            use_iv: bool = self._settings["use_iv"].lower() == "true"
            masked: bool = self._settings["masked"].lower() == "true"
            add_cmd: str = self._settings["add_cmd"]
            get_cmd: str = self._settings["get_cmd"]
            key_cmd: str = self._settings["key_cmd"]
            enc_cmd: str = self._settings["enc_cmd"]
            memory_mappings = self._settings["memory_mappings"]

            # Store the parsed settings in the _parsed_settings dictionary
            self._parsed_settings = {
                "platform": self._settings["platform"],
                "target": self._settings["target"],
                "key_length": key_length,
                "plaintext_length": plaintext_length,
                "use_iv": use_iv,
                "masked": masked,
                "add_cmd": add_cmd,
                "get_cmd": get_cmd,
                "key_cmd": key_cmd,
                "enc_cmd": enc_cmd,
                "memory_mappings": memory_mappings
            }
        except Exception as e:
            self._logger.error(f"An unexpected error occurred while parsing the JSON config file: {e}")
            raise e

    def get_k_len(self) -> int:
        """
        Returns the key length for AES encryption.

        Returns:
            int: The key length in bytes.
        """
        return self._parsed_settings["key_length"]

    def get_use_iv(self) -> bool:
        """
        Returns whether the AES mode uses an initialization vector (IV).

        Returns:
            bool: True if IV is used, False otherwise.
        """
        return self._parsed_settings["use_iv"]

    def get_masked(self) -> bool:
        """
        Returns whether AES masking is enabled.

        Returns:
            bool: True if masking is enabled, False otherwise.
        """
        return self._parsed_settings["masked"]

    def get_pt_len(self) -> int:
        """
        Returns the length of the plaintext for AES encryption.

        Returns:
            int: The plaintext length in bytes.
        """
        return self._parsed_settings["plaintext_length"]
