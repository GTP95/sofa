#!/usr/bin/env python3

from argparse import Namespace

from term_image.image import from_file

from armchair.components.armchair_session import ARMChairSession
from armchair.components.power_trace_generator import generate_power_traces, show_power_traces
from armchair.targets.aes.aes_input_generator import AesInputsGenerator
from armchair.targets.aes.aes_input_parser import AesInputParser
from armchair.targets.aes.aes_input_validator import AesInputValidator
from armchair.targets.aes.aes_qiling_profile import AesQilingProfile
from armchair.targets.aes.aes_settings_loader import AesSettingsLoader
from armchair.targets.ascon.ascon_input_generator import AsconInputsGenerator
from armchair.targets.ascon.ascon_input_parser import AsconInputParser
from armchair.targets.ascon.ascon_input_validator import AsconInputValidator
from armchair.targets.ascon.ascon_qiling_profile import AsconQilingProfile
from armchair.targets.ascon.ascon_settings_loader import AsconSettingsLoader
from armchair.targets.keccak.keccak_hash_qiling_profile import KeccakHashQilingProfile
from armchair.targets.keccak.keccak_input_generator import KeccakHashInputsGenerator
from armchair.targets.keccak.keccak_input_parser import KeccakHashInputParser
from armchair.targets.keccak.keccak_input_validator import KeccakHashInputValidator
from armchair.targets.keccak.keccak_settings_loader import KeccakHashSettingsLoader
from armchair.utils.helpers import parse_args, err_t, init

if __name__ == "__main__":
    init()
    image=from_file('art/CPU1.jpeg')
    image.draw()

    # Parse command-line arguments
    args: Namespace = parse_args()

    ig = None
    iv = None
    sl = None
    ip = None
    tp = None  # this is the only one that needs to be implemented, the rest can be skipped in user-csv or user-raw mode.

    if args.target == "AES":
        ig = AesInputsGenerator()
        iv = AesInputValidator()
        sl = AesSettingsLoader()
        ip = AesInputParser()
        tp = AesQilingProfile()

    elif args.target == "ASCON":
        ig = AsconInputsGenerator()
        iv = AsconInputValidator()
        sl = AsconSettingsLoader()
        ip = AsconInputParser()
        tp = AsconQilingProfile()

    elif args.target == "KECCAK":
        ig = KeccakHashInputsGenerator()
        iv = KeccakHashInputValidator()
        sl = KeccakHashSettingsLoader()
        ip = KeccakHashInputParser()
        tp = KeccakHashQilingProfile()

    else:
        # If the target is not implemented, raise an error
        raise Exception(
            f"{err_t} This target has not been implemented yet, use the help function for available targets"
        )

    session = ARMChairSession(
        args=args,
        raw_target_data=[
            "9db09adc6ec1d3b367e5ddf6d2cadfd1",
            "afc17270ea15da418e588ef63c0d98e2",
        ],  # usable in user-raw mode if we want some quick custom data to pass, this is just an example [key, plaintext].
        input_generator=ig,
        input_validator=iv,
        input_parser=ip,
        settings_loader=sl,
    )

    session.init_session()
    session.run_session(target_profile=tp)

    #TODO: do not hardcode paths
    generate_power_traces('Traces-AES', 'Traces-AES/power_traces.npz', args.leakage_model)
    show_power_traces('Traces-AES/power_traces.npz')


