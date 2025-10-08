import csv
import logging
import os

from qiling import Qiling
from tqdm.contrib.concurrent import process_map

from armchair.components.sym_parser import SymParser
from armchair.targets.aes.aes_qiling_profile import QilingProfile
from armchair.utils.arm_helpers import headerList
from armchair.utils.constants import TRACESPATH
from armchair.utils.helpers import initialize_qiling
from armchair.utils.progress_bar import ProgressBar


class ARMChairSessionRunner:
    def __init__(
        self,
        elf_path: str,
        input_format,
        target_profile: QilingProfile,
        target_data: list,
        json_path: str
    ) -> None:
        self.elf_path: str = elf_path
        self.input_format: str = input_format
        self.target_profile: QilingProfile = target_profile
        self.target_data: list = target_data
        self.sym_parser = SymParser(elf_path=elf_path)
        self.logger=logging.getLogger(__name__)
        self.json_path=json_path

    def process_row(self, row, index) -> None:
        """
        Processes a single row of input data, initializing Qiling, running the emulation, and capturing traces.

        Args:
            row (dict): Input data to be processed.
            index (int): Used to map the input lines to the traces so that input line 1 corresponds to trace 1

        Functionality:
            - Initializes the Qiling emulator using the target ELF file and configuration.
            - Hooks commands specific to the profile.
            - Runs the Qiling emulator and collects trace information.
            - Saves traces to a CSV file for further analysis.
        """
        logger = logging.getLogger(__name__)
        try:
            # init traces object in memory (of the instructions are too many the hook for recording instructions could be used to write directly to csv instead)
            traces: list = []
            cache: dict = {}

            # initialize Qiling object
            ql: Qiling = initialize_qiling(
                elf=self.elf_path,
                sym_parser=self.sym_parser,
                profile=self.target_profile,
                traces=traces,
                cache=cache,
                json_path=self.json_path
            )

            self.target_profile.init_uart(ql=ql, input_format=self.input_format)

            output_path = f"{TRACESPATH}-{self.target_profile.get_algorithm_name()}"

            os.makedirs(output_path, 511, True)

            output_path: str = os.path.join(
                output_path,
                f"traces_{index[0] + 1}.csv",
            )

            self.target_profile.hook_cmds(
                ql=ql, sym_parser=self.sym_parser, target_data=row
            )

            ql.log.info("Starting Qiling..")
            ql.run()

            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logger.debug("Writing traces to CSV...")

            # Write traces using csv module
            with open(output_path, mode="w", newline="") as file:
                csv_writer = csv.writer(file)
                csv_writer.writerow(headerList)  # Write the headers
                csv_writer.writerows(traces)  # Write the rows of data
        except Exception as e:
            logger.error(f"\nError processing data {row}: {e}")
            raise e

    def run_session(self) -> None:
        # check that the data is there
        if self.target_data == None or len(self.target_data) == 0:
            raise ValueError(
                f"No or empty taget data has been provided, cannot process."
            )

        # Notify the user that the session has started
        self.logger.info(f"Session started")

        # run the session with the data provided
        if len(self.target_data) == 1:
            # Process the single row of data
            self.process_row(row=self.target_data[0], index=[0])
        else:
            # Process the rows in parallel using the available CPU workers
            process_map(
                self.process_row,
                self.target_data,
                enumerate(iterable=self.target_data),
                max_workers=4,
                chunksize=1,
                tqdm_class=ProgressBar,  # Use a custom progress bar class for tracking progress
            )

        # Notify the user that the session has completed
        self.logger.info("Session completed")
