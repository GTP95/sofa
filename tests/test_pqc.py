"""Exercise finalized PQC profiles, host cryptography and external ELF integration."""

from __future__ import annotations

import csv
from dataclasses import replace
import json
from pathlib import Path
from random import Random
import sys
import tempfile
from typing import Any
import unittest
from unittest.mock import patch

import numpy as np

from sofa.components.pqc import (DSA_SIZES, FAMILIES, HASHES, KEM_SIZES, SLH_SIGNATURES,
                                 PQCInputParser, PQCSpec, generate_pqc_inputs, read_pqc_csv, write_pqc_csv)
from sofa.components.pqc_backend import BackendUnavailable, OpenSSLBackend
from sofa.components.tvla import analyze_tvla_archive, generate_tvla_inputs, write_tvla_manifest
from sofa.components.baremetal import BaremetalProfile, initialize_baremetal
from sofa.components.sym_parser import SymParser
from sofa.utils.helpers import create_npz_file, get_profile_algorithm, parse_args
from test_baremetal import config_fixture, elf_fixture, routine

VECTORS = Path(__file__).parent / 'vectors'
PARAMETERS = {'ML-KEM': list(KEM_SIZES), 'ML-DSA': list(DSA_SIZES),
              'SLH-DSA': [f'{hash_name}-{variant}' for hash_name in ('SHA2', 'SHAKE') for variant in SLH_SIGNATURES]}


def settings(family: str = 'ML-DSA', parameter: str = '44', operation: str = 'verify', **extras: Any) -> dict[str, Any]:
    """Build a minimal PQC configuration for a selected FIPS operation."""
    return dict(platform='baremetal', execution_mode='baremetal-direct', target=family,
                parameter_set=parameter, operation=operation, **extras)


def decoded(row: dict[str, str]) -> dict[str, bytes]:
    """Decode the named bytes in a validated vector for host checks."""
    return {key: bytes.fromhex(value) for key, value in row.items()}


class PQCInputTests(unittest.TestCase):
    """Check every profile and encoding without requiring the optional backend."""

    def test_all_parameter_sets_operations_parsing_and_csv(self) -> None:
        """Check exact FIPS lengths, required fields and named CSV round trips."""
        with tempfile.TemporaryDirectory() as directory:
            for family, parameters in PARAMETERS.items():
                for parameter in parameters:
                    operations = ('keygen', 'encapsulate', 'decapsulate') if family == 'ML-KEM' else ('keygen', 'sign', 'verify')
                    for operation in operations:
                        with self.subTest(family=family, parameter=parameter, operation=operation):
                            config = settings(family, parameter, operation)
                            spec = PQCSpec.from_settings(config)
                            values = {key: bytes(length).hex() for key, length in spec.sizes.items()}
                            values.update(message='', context='ff'*255)
                            row = spec.parse(values)
                            path = Path(directory) / 'profile.json'
                            path.write_text(json.dumps(config))
                            self.assertEqual(get_profile_algorithm(str(path)), family)
                            write_pqc_csv(Path(directory) / 'inputs.csv', [{**spec.metadata(), **row}])
                            self.assertEqual(read_pqc_csv(Path(directory) / 'inputs.csv', spec), [row])
                            for field in spec.sizes:
                                with self.assertRaisesRegex(ValueError, field):
                                    spec.parse({**values, field: '00'})
                            with self.assertRaisesRegex(ValueError, 'Missing'):
                                spec.parse({})

    def test_profile_and_malformed_input_errors(self) -> None:
        """Reject invalid profiles, encodings and contexts without repairing vectors."""
        for extras in ({'platform': 'stm32f4'}, {'execution_mode': 'uart'}, {'parameter_set': '999'},
                       {'operation': 'encapsulate'}, {'randomized': 'false'}, {'message_length': -1},
                       {'signature_mode': 'wrong'}, {'prehash_algorithm': 'SHA-512'},
                       {'signature_mode': 'prehash', 'prehash_algorithm': 'MD5'}):
            with self.subTest(extras=extras), self.assertRaises(ValueError):
                PQCSpec.from_settings({**settings(), **extras})
        spec = PQCSpec.from_settings(settings(operation='keygen'))
        for values in ({'seed': '00'}, {'seed': '0'*63}, {'seed': 'gg'*32}, {'seed': '00 '*32},
                       {'seed': 123}, {'seed': '00'*32, 'context': '00'*256}, {'unknown': ''}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                spec.parse(values)
        sign = PQCSpec.from_settings(settings(operation='sign', randomized=False))
        values = dict(secret_key='00'*2560, message='')
        self.assertEqual(sign.parse(values)['randomness'], '00'*32)
        with self.assertRaisesRegex(ValueError, 'deterministic'):
            sign.parse({**values, 'randomness': 'ff'*32})
        # A same-size malformed signature stays available for rejection testing.
        verify = PQCSpec.from_settings(settings())
        self.assertEqual(verify.parse(dict(public_key='00'*1312, message='', signature='ff'*2420))['signature'], 'ff'*2420)

    def test_prehash_encoding_and_strength(self) -> None:
        """Match FIPS domain separation, DER OIDs and XOF lengths for every hash."""
        import hashlib
        for hash_name, (digest_name, oid, length, strength) in HASHES.items():
            for family, parameter, needed in [('ML-DSA', '44', 128), ('ML-DSA', '65', 192),
                                               ('ML-DSA', '87', 256), ('SLH-DSA', 'SHAKE-128s', 128),
                                               ('SLH-DSA', 'SHA2-192f', 192), ('SLH-DSA', 'SHA2-256s', 256)]:
                config = settings(family, parameter, 'sign', signature_mode='prehash', prehash_algorithm=hash_name)
                if strength < needed:
                    with self.assertRaises(ValueError):
                        PQCSpec.from_settings(config)
                    continue
                spec = PQCSpec.from_settings(config)
                digest = hashlib.new(digest_name, b'abc')
                expected = digest.digest(length) if digest_name.startswith('shake_') else digest.digest()
                self.assertEqual(spec.encode_message(b'abc', b'ctx'),
                                 b'\x01\x03ctx'+bytes.fromhex('06096086480165030402')+bytes([oid])+expected)
        spec = PQCSpec.from_settings(settings())
        self.assertEqual(spec.encode_message(b'', bytes(255)), b'\x00\xff'+bytes(255))
        with self.assertRaises(ValueError):
            spec.encode_message(b'', bytes(256))

    def test_cli_defaults_user_json_and_backend_optional(self) -> None:
        """Select PQC defaults and load supplied inputs without importing libcrypto."""
        from argparse import Namespace
        with tempfile.TemporaryDirectory() as directory:
            profile, inputs = Path(directory)/'profile.json', Path(directory)/'inputs.json'
            profile.write_text(json.dumps(settings('ML-KEM', '512', 'keygen')))
            inputs.write_text(json.dumps({'seed': '00'*64}))
            with patch.object(sys, 'argv', ['sofa', 'binary.elf', str(profile), '--tvla', '--count', '4']):
                self.assertEqual(parse_args().tvla_variable, 'seed')
            with patch.object(sys, 'argv', ['sofa', 'binary.elf', str(profile), '--tvla', '--count', '4', '--tvla_variable', 'key']), patch('sys.stderr'):
                with self.assertRaises(SystemExit):
                    parse_args()
            with patch('ctypes.CDLL', side_effect=OSError('unavailable')):
                values = PQCInputParser().parse_user_args(Namespace(pqc_inputs=str(inputs)), settings('ML-KEM', '512', 'keygen'))
                self.assertEqual(values['seed'], '00'*64)
                with self.assertRaisesRegex(BackendUnavailable, 'SOFA_LIBCRYPTO'):
                    OpenSSLBackend()


class PQCBackendTests(unittest.TestCase):
    """Verify the optional provider against NIST vectors and host relationships."""

    @classmethod
    def setUpClass(cls) -> None:
        """Skip host cryptographic tests only when the optional backend is absent."""
        try:
            cls.backend = OpenSSLBackend()
        except BackendUnavailable as error:
            raise unittest.SkipTest(str(error)) from error

    def test_nist_keygen_known_answers(self) -> None:
        """Match pinned NIST ACVP raw public and expanded private keys in all sets."""
        for vector in json.loads((VECTORS/'pqc_keygen.json').read_text()):
            with self.subTest(name=vector['algorithm']+'-'+vector['parameter_set']):
                spec = PQCSpec.from_settings(settings(vector['algorithm'], vector['parameter_set'], 'keygen'))
                result = self.backend.keygen(spec, bytes.fromhex(vector['seed']))
                self.assertEqual(result['public_key'].hex(), vector['public_key'])
                self.assertEqual(result['secret_key'].hex(), vector['secret_key'])

    def test_nist_encapsulation_and_signature_known_answers(self) -> None:
        """Match pinned ACVP ciphertexts, shared secrets and pure/prehash signatures."""
        for vector in json.loads((VECTORS/'pqc_kem.json').read_text()):
            spec = PQCSpec.from_settings(settings('ML-KEM', vector['parameter_set'], 'decapsulate'))
            values = decoded(vector['values'])
            ciphertext, secret = self.backend.encapsulate(spec, values)
            self.assertEqual(ciphertext, values['ciphertext'])
            self.assertEqual(secret.hex(), vector['shared_secret'])
            self.assertEqual(secret, self.backend.decapsulate(spec, values))
        for vector in json.loads((VECTORS/'pqc_signatures.json').read_text()):
            spec = PQCSpec.from_settings(settings(vector['algorithm'], vector['parameter_set'], 'sign',
                                                signature_mode=vector['signature_mode'],
                                                prehash_algorithm=vector['prehash_algorithm'], randomized=False))
            values = decoded(spec.parse(vector['values']))
            self.assertEqual(self.backend.signature(spec, values), values['signature'])
            self.assertTrue(self.backend.signature(spec, values, True))

    def test_every_generated_operation_and_reproduction(self) -> None:
        """Check every operation's generated lengths and cryptographic correctness."""
        for family, parameters in PARAMETERS.items():
            for parameter in parameters:
                spec = PQCSpec.from_settings(settings(family, parameter, 'keygen'))
                keys = self.backend.keygen(spec, bytes(range(spec.sizes['seed'])))
                self.assertEqual(keys, self.backend.keygen(spec, keys['seed']))
                for operation in (('keygen', 'encapsulate', 'decapsulate') if family == 'ML-KEM' else ('keygen', 'sign', 'verify')):
                    with self.subTest(family=family, parameter=parameter, operation=operation):
                        current = replace(spec, operation=operation)
                        # Share keys across operations to keep slow SLH keygen tests bounded.
                        baseline = {key: value.hex() for key, value in keys.items()}
                        if operation in {'sign', 'verify'}:
                            baseline.update(randomness=bytes(current.sizes['randomness']).hex())
                        row = self.backend.vector(current, Random(42), baseline if operation != 'keygen' else None)
                        current.parse(row)
                        values = decoded(row)
                        if operation in {'encapsulate', 'decapsulate'}:
                            ciphertext, secret = self.backend.encapsulate(current, values)
                            self.assertEqual(ciphertext, values['ciphertext'])
                            self.assertEqual(secret, self.backend.decapsulate(current, values))
                        elif operation in {'sign', 'verify'}:
                            self.assertTrue(self.backend.signature(current, values, True))
                            self.assertEqual(self.backend.signature(current, values), values['signature'])

    def test_context_prehash_and_deterministic_signing(self) -> None:
        """Verify pure/prehash separation, context bounds and deterministic entropy."""
        for family, parameter in [('ML-DSA', '44'), ('SLH-DSA', 'SHAKE-128f')]:
            pure = PQCSpec.from_settings(settings(family, parameter, 'sign', randomized=False))
            for mode in ('pure', 'prehash'):
                spec = replace(pure, signature_mode=mode, prehash_algorithm='SHA-512' if mode == 'prehash' else '')
                rows, manifest, _ = generate_pqc_inputs(spec, 1, 42)
                self.assertEqual((rows, manifest, 42), generate_pqc_inputs(spec, 1, 42))
                values = decoded(rows[0])
                if family == 'SLH-DSA':
                    n = spec.sizes['randomness']
                    self.assertEqual(values['randomness'], values['secret_key'][2*n:3*n])
                for context in (b'', b'abc', bytes(range(255))):
                    values['context'] = context
                    values['signature'] = self.backend.signature(spec, values)
                    self.assertTrue(self.backend.signature(spec, values, True))
                    self.assertFalse(self.backend.signature(replace(spec, signature_mode='prehash' if mode == 'pure' else 'pure', prehash_algorithm='SHA-512'), values, True))
                    self.assertFalse(self.backend.signature(spec, {**values, 'message': b'changed'}, True))

    def test_tvla_valid_dependencies_balance_and_replay(self) -> None:
        """Keep fixed keys, regenerate valid dependencies and replay every manifest byte."""
        for family, parameter in [('ML-KEM', '512'), ('ML-DSA', '44'), ('SLH-DSA', 'SHA2-128f')]:
            for operation in (('keygen', 'encapsulate', 'decapsulate') if family == 'ML-KEM' else ('keygen', 'sign', 'verify')):
                config = settings(family, parameter, operation)
                spec = PQCSpec.from_settings(config)
                rows, manifest, seed = generate_tvla_inputs(family, config, 4, seed=42)
                self.assertEqual((rows, manifest, seed), generate_tvla_inputs(family, config, 4, seed=42))
                self.assertEqual([row['group'] for row in manifest], ['fixed', 'random', 'fixed', 'random'])
                self.assertEqual(rows[0], rows[2])
                self.assertNotEqual(rows[0][spec.tvla_variable], rows[1][spec.tvla_variable])
                self.assertEqual(set(manifest[1]['changed_fields'].split(',')), {k for k in rows[1] if rows[1][k] != rows[0].get(k)})
                if operation != 'keygen':
                    self.assertEqual(rows[0]['secret_key'], rows[1]['secret_key'])
                if operation in {'sign', 'verify'}:
                    self.assertEqual(rows[0]['randomness'], rows[1]['randomness'])
                    self.assertTrue(all(self.backend.signature(spec, decoded(row), True) for row in rows))
                if operation == 'decapsulate':
                    for row in rows:
                        _, secret = self.backend.encapsulate(spec, decoded(row))
                        self.assertEqual(secret, self.backend.decapsulate(spec, decoded(row)))
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory)/'manifest.csv'
                    write_pqc_csv(path, manifest)
                    self.assertEqual(read_pqc_csv(path, spec), rows)
                with self.assertRaises(ValueError):
                    generate_tvla_inputs(family, config, 4, variable='key')


class PQCIntegrationTests(unittest.TestCase):
    """Execute named PQC input buffers using real static ELF fixtures."""

    def test_session_input_modes_and_manifest(self) -> None:
        """Initialize user/CSV/auto/TVLA sessions and persist complete run manifests."""
        from argparse import Namespace
        from sofa.components.armchair_session import ARMChairSession
        from sofa.components.pqc import PQCSettingsLoader
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = settings('ML-KEM', '512', 'keygen')
            profile, inputs = root/'profile.json', root/'inputs.json'
            profile.write_text(json.dumps(config))
            inputs.write_text(json.dumps({'seed': '00'*64}))
            csv_path = root/'input.csv'
            write_pqc_csv(csv_path, [{'seed': '00'*64}])
            for mode, tvla in [('user', False), ('user-csv', False), ('auto', False), ('auto', True)]:
                args = Namespace(algorithm='ML-KEM', input=mode, path=str(csv_path), input_format='hex',
                                 debug=False, elf_path='unused.elf', config=str(profile), count=4,
                                 tvla=tvla, tvla_seed=42, tvla_variable='seed', pqc_inputs=str(inputs),
                                 no_validation=True)
                session = ARMChairSession(args, input_parser=PQCInputParser(), settings_loader=PQCSettingsLoader(str(profile)))
                with patch('sofa.components.armchair_session.write_pqc_csv'):
                    session.init_session()
                self.assertEqual(len(session.target_data), 4 if mode == 'auto' else 1)
                with patch('sofa.components.armchair_session.ARMChairSessionRunner') as runner:
                    runner.return_value.run_session.return_value = str(root)
                    self.assertEqual(session.run_session(BaremetalProfile(config)), str(root))
                self.assertEqual(read_pqc_csv(root/'pqc_inputs.csv', PQCSpec.from_settings(config)), session.target_data)
                if tvla:
                    self.assertTrue((root/'tvla_inputs.csv').exists())
            csv_path.write_text('seed\n00\n')
            session = ARMChairSession(Namespace(**{**vars(args), 'input': 'user-csv'}),
                                     settings_loader=PQCSettingsLoader(str(profile)))
            with self.assertRaisesRegex(ValueError, 'exactly 64'):
                session.init_session()

    def test_direct_buffers_and_capture_on_all_architectures(self) -> None:
        """Place raw/encoded bytes, run a wrapper and retain manifest result metadata."""
        for arch in ('arm64', 'riscv32', 'riscv64'):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config = config_fixture(arch)
                config.update(settings('ML-DSA', '44', 'verify'))
                config['direct_call']['buffers'] = {
                    'key': {'address': 0x300000, 'size': 1312, 'input': 'public_key'},
                    'output': {'address': 0x300600, 'size': 16},
                    'encoded': {'address': 0x300700, 'size': 128, 'input': 'encoded_message'},
                }
                config['direct_call']['arguments'][8] = {'length': 'encoded_message'}
                elf = root/'test.elf'
                elf_fixture(elf, arch, routine(arch))
                profile, symbols = BaremetalProfile(config), SymParser(str(elf))
                traces: list[list[Any]] = []
                ql = initialize_baremetal(str(elf), config, profile, symbols, traces, 'accessed')
                spec = PQCSpec.from_settings(config)
                values = spec.parse(dict(public_key='00'*1312, message='616263', context='7879', signature='ff'*2420))
                profile.hook_cmds(ql, symbols, values)
                self.assertEqual(bytes(ql.mem.read(0x300700, 7)), b'\x00\x02xyabc')
                ql.run(begin=ql.sofa_entry, end=0x100104, count=100)
                ql.sofa_access_recorder.validate_complete()
                self.assertEqual(ql.mem.read_ptr(0x300600), 7)
                manifest = []
                for index in range(4):
                    with (root/f'traces_{index+1}.csv').open('w', newline='') as destination:
                        writer = csv.writer(destination)
                        writer.writerow(ql.sofa_trace_header)
                        writer.writerows(traces)
                    manifest.append({**spec.metadata(), 'trace_filename': f'traces_{index+1}.csv',
                                     'group': 'fixed' if index % 2 == 0 else 'random', **values})
                write_tvla_manifest(root/'tvla_inputs.csv', manifest)
                write_pqc_csv(root/'pqc_inputs.csv', manifest)
                create_npz_file(root/'power.npz', root, 'HW')
                result = analyze_tvla_archive(root/'power.npz')
                with np.load(result, allow_pickle=False) as archive:
                    self.assertEqual(json.loads(str(archive['pqc_inputs'])), manifest)
