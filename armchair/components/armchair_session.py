from armchair.components.armchair_session_runner import ARMChairSessionRunner
from armchair.components.input_generator import InputsGenerator
from armchair.components.settings_loader import SettingsLoader
from armchair.components.input_validator import InputValidator
from armchair.components.input_parser import InputParser
from armchair.components.qiling_profile import QilingProfile

from armchair.utils.enums import ARMChairSessionMode

from argparse import Namespace

import csv
import logging


class ARMChairSession:
    def __init__(
        self,
        args: Namespace,
        raw_target_data: list = [],
        input_generator: InputsGenerator = None,
        input_validator: InputValidator = None,
        input_parser: InputParser = None,
        settings_loader: SettingsLoader = None,
    ) -> None:
        self.args: Namespace = args
        self.mode = ARMChairSessionMode(value=args.input)
        self.input_csv_path: str = args.path
        self.input_format: str = args.input_format
        # Use global logging configuration; avoid storing a debug boolean
        self.debug: bool = args.debug
        self.elf_path: str = args.elf_path
        self.target_data: list = []
        self.raw_target_data: list = raw_target_data
        self.input_generator: InputsGenerator = input_generator
        self.input_parser: InputParser = input_parser
        self.input_validator: InputValidator = input_validator
        self.settings_loader: SettingsLoader = settings_loader
        self.logger=logging.getLogger(__name__)
        # Set logger level after instantiation to follow global configuration
        self.logger.setLevel(logging.getLogger().level)

    def init_session(self) -> None:
        # Initialize (or not) the classes
        ig: InputsGenerator = self.input_generator
        iv: InputValidator = self.input_validator
        ip: InputParser = self.input_parser
        sl: SettingsLoader = self.settings_loader


        if self.mode == ARMChairSessionMode.USER:
            # Check that the required components have been passed
            if sl == None or iv == None:
                raise ValueError(
                    f"To use this mode all the  classes need to be implemented: ${type(sl)}, ${type(iv)}"
                )

            # Retrieve target settings from the settings loader
            target_settings: dict = sl.get_target_settings()

            # Get the user provided data
            self.target_data.append(
                ip.parse_user_args(u_args=self.args, target_settings=target_settings)
            )

            # Validate the user-provided data against the expected settings
            if not self.args.no_validation:
                iv.validate_inputs(
                    target_data=self.target_data[0], target_settings=target_settings
                )

        elif self.mode == ARMChairSessionMode.AUTO:
            # Check that the required components have been passed
            if sl == None or ig == None:
                raise ValueError(
                    f"To use this mode all the  classes need to be implemented: ${type(sl)}, ${type(ig)}"
                )

            # Retrieve target settings from the settings loader
            target_settings: dict = sl.get_target_settings()

            # Create the input filename based on the target and platform
            input_path: str = f"{sl.get_target()}-{sl.get_plat()}-Inputs.csv"

            # Generate the inputs and write them to a CSV file
            if self.args.count <1:
                raise ValueError(
                    f"Invalid number of inputs provided: {self.args.count}, must be at least 1"
                )
            ig.generate_inputs_csv(
                target_settings=target_settings,
                nr_of_inputs=self.args.count,
                input_path=input_path,
            )

            # Open and read the generated CSV file
            with open(file=input_path, mode="r") as file:
                csv_reader: csv._reader = csv.reader(file)
                next(csv_reader)  # Skip the header row
                rows = list(csv_reader)  # Read all rows into memory
                self.target_data.extend(rows)

        elif self.mode == ARMChairSessionMode.USER_CSV:
            self.logger.warning(
                f"Beware, {self.mode.value} mode has no validation of any kind, use the debug flag if the run fails and make sure that the csv you provided matches what the C code expects"
            )

            csv_path: str = self.input_csv_path

            if csv_path == None:
                raise ValueError(
                    f"No path to the .csv file was provided either by the user, cannot continue."
                )

            # Open and read the generated CSV file
            with open(file=csv_path, mode="r") as file:
                csv_reader: csv._reader = csv.reader(file)
                next(csv_reader)  # Skip the header row
                rows = list(csv_reader)  # Read all rows into memory
                self.target_data.extend(rows)

        elif self.mode == ARMChairSessionMode.USER_RAW:
            self.logger.warning(
                f'Beware, {self.mode.value} mode has no validation of any kind, use the debug flag if the run fails and make sure that the inputs that you provided matches what the C code expects and is structured this way ["value1", "value2", etc] where the values match the order that the QilingProfile expects'
            )

            self.target_data.append(self.raw_target_data)

        else:
            raise Exception(
                f"Mode {self.mode} has not been implemented yet, use the help function for available user input modes"
            )

    def run_session(self, target_profile: QilingProfile) -> None:
        session = ARMChairSessionRunner(
            elf_path=self.elf_path,
            input_format=self.input_format,
            target_data=self.target_data,
            target_profile=target_profile,
            json_path=self.args.config
        )
        session.run_session()