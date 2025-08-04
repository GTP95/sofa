from argparse import Namespace
from typing import Any

from armchair.components.input_parser import InputParser


class AsconInputParser(InputParser):
    def __init__(self) -> None:
        super().__init__()

    def parse_user_args(self, u_args: Namespace, target_settings: dict = {}) -> list:
        return [u_args.key, u_args.plaintext, u_args.nonce, u_args.ad]
