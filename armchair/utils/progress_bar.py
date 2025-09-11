import logging

from tqdm import tqdm
from colorama import Fore, Style


# Define a custom tqdm class by subclassing tqdm
class ProgressBar(tqdm):
    """
    A custom progress bar class that extends tqdm to provide a more informative and styled progress bar.

    The progress bar is designed to display information such as:
    - Total progress.
    - Elapsed time.
    - Estimated remaining time.
    - Custom color formatting using colorama to enhance readability.

    Attributes:
        bar_format (str): The custom format of the progress bar, including colors and layout.
        ncols (int): The width of the progress bar, set to 100 characters.
        smoothing (float): The smoothing factor for the progress bar speed calculation.
    """

    def __init__(self, *args, **kwargs):
        """
        Initializes the custom ProgressBar with the desired formatting and layout.

        Args:
            *args: Variable-length argument list passed to the tqdm superclass.
            **kwargs: Arbitrary keyword arguments passed to the tqdm superclass.
        """
        logger = logging.getLogger(__name__)
        super().__init__(
            *args,
            **kwargs,
            bar_format=(
                f"Creating traces.."
                f"{Fore.WHITE}{{l_bar}}{Style.RESET_ALL}"  # Left part of the progress bar (white)
                f"{Fore.GREEN}{{bar}}{Style.RESET_ALL}"  # The progress bar itself (green)
                f" {Fore.WHITE}{{n_fmt}}/{Fore.WHITE}{{total_fmt}}{Style.RESET_ALL}"  # Progress numbers
                f" {Fore.WHITE}Elapsed: {Fore.WHITE}{{elapsed}}{Style.RESET_ALL}"  # Elapsed time
                f" {Fore.WHITE}Remaining: {Fore.WHITE}{{remaining}}{Style.RESET_ALL}"  # Remaining time
            ),
            ncols=100,  # Set the width of the progress bar
            smoothing=0.5,  # Smoothing factor for progress bar updates
        )
