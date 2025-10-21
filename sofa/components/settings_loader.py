import os
import json

import logging


class SettingsLoader:
    """
    A base class responsible for loading and managing target-specific configuration settings from a JSON file.

    Attributes:
        _settings (dict or None): Stores the raw settings loaded from the JSON file.
        _parsed_settings (dict): A dictionary that holds parsed target-specific settings.
    """

    def __init__(self, json_path) -> None:
        """
        Initializes the SettingsLoader by loading the target configuration via __load_target_config.
        """
        self._settings = None
        self._parsed_settings: dict = {}
        self._logger = logging.getLogger(__name__)
        self._logger.setLevel(logging.getLogger().level)

        self.__load_target_config(json_path)



    def __load_target_config(self, json_path) -> None:
        """
        Loads the target configuration from a JSON file that matches the platform name found in `PLATFORM`.
        The JSON file should be located in the same directory as the program.

        Raises:
            FileNotFoundError: If the configuration file is missing.
            JSONDecodeError: If there is an error parsing the JSON.
            Exception: For any other issues during the file loading process.
        """



        # Try loading the JSON file, handle possible errors
        try:
            with open(json_path, "r") as file:
                self._settings = json.load(file)
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(
                msg=f"Error: Failed to decode JSON from {json_path}. Error: {e}",
                doc=json_path,
                pos=e.lineno,
            )
        except Exception as e:
            raise Exception(
                f"An unexpected error occurred while loading the JSON config file: {e}"
            )

    def _parse_target_config(self) -> None:
        """
        Placeholder method for parsing configuration data, meant to be overridden by subclasses.

        The subclass should parse `_settings` and populate `_parsed_settings` with relevant fields.
        """
        pass

    def get_plat(self) -> str:
        """
        Returns the platform name from the parsed settings.

        Returns:
            str: The platform name.
        """
        return self._parsed_settings["platform"]

    def get_target(self) -> str:
        """
        Returns the target name from the parsed settings.

        Returns:
            str: The target name.
        """
        return self._parsed_settings["target"]

    def get_target_file_name(self) -> str:
        """
        Constructs and returns the ELF file name for the target based on the platform and target names.

        Returns:
            str: The name of the target ELF file.
        """
        return f"{self.get_target()}-{self.get_plat()}.elf"

    def get_target_settings(self) -> dict:
        """
        Returns the parsed settings as a dictionary.

        Returns:
            dict: The parsed configuration settings.
        """
        return self._parsed_settings
