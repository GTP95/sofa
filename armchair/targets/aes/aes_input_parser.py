from argparse import Namespace

from armchair.components.input_parser import InputParser


class AesInputParser(InputParser):
    def __init__(
        self,
    ) -> None:
        super().__init__()

    """
    Parses user input arguments for AES encryption.

    This class extends the InputParser base class and provides a specific implementation
    for the AES encryption algorithm. The `parse_user_args` method returns the key,
    plaintext, and initialization vector (IV) in the correct order.

    Methods:
    --------
    parse_user_args(args):
        Parses the arguments for AES encryption, returning a list containing:
        - Key: The encryption key (args.key)
        - Plaintext: The message to be encrypted (args.plaintext)
        - IV: The initialization vector (args.iv)

    Returns:
    --------
    list:
        A list of the key, plaintext, and IV in the order required for AES encryption.
    """

    def parse_user_args(self, u_args: Namespace, target_settings: dict):
        return [
            u_args.key,
            u_args.plaintext,
            u_args.iv if target_settings["use_iv"] else None,
        ]
