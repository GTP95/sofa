"""FIPS 203/204/205 profiles, named inputs, encodings and valid vector generation."""

from __future__ import annotations

import csv
import hashlib
import json
import secrets
from argparse import Namespace
from dataclasses import dataclass
from pathlib import Path
from random import Random
from typing import Any, Mapping

from sofa.components.settings_loader import SettingsLoader

FAMILIES = frozenset({'ML-KEM', 'ML-DSA', 'SLH-DSA'})
KEM_SIZES = {'512': (800, 1632, 768), '768': (1184, 2400, 1088), '1024': (1568, 3168, 1568)}
DSA_SIZES = {'44': (1312, 2560, 2420), '65': (1952, 4032, 3309), '87': (2592, 4896, 4627)}
SLH_SIGNATURES = {'128s': 7856, '128f': 17088, '192s': 16224, '192f': 35664,
                  '256s': 29792, '256f': 49856}
# FIPS 180/202 hashes: hashlib name, DER OID final byte, output bytes, collision strength.
HASHES = {
    'SHA-224': ('sha224', 4, 28, 112), 'SHA-256': ('sha256', 1, 32, 128),
    'SHA-384': ('sha384', 2, 48, 192), 'SHA-512': ('sha512', 3, 64, 256),
    'SHA-512/224': ('sha512_224', 5, 28, 112), 'SHA-512/256': ('sha512_256', 6, 32, 128),
    'SHA3-224': ('sha3_224', 7, 28, 112), 'SHA3-256': ('sha3_256', 8, 32, 128),
    'SHA3-384': ('sha3_384', 9, 48, 192), 'SHA3-512': ('sha3_512', 10, 64, 256),
    'SHAKE128': ('shake_128', 11, 32, 128), 'SHAKE256': ('shake_256', 12, 64, 256),
}
INPUT_FIELDS = ('seed', 'public_key', 'secret_key', 'message', 'context', 'randomness',
                'ciphertext', 'signature')
METADATA_FIELDS = ('algorithm', 'parameter_set', 'operation', 'signature_mode', 'prehash_algorithm',
                   'randomized', 'effective_seed', 'trace_filename', 'group', 'tested_variable', 'changed_fields')


@dataclass(frozen=True)
class PQCSpec:
    """Describe one external FIPS operation and its raw byte lengths."""

    algorithm: str
    parameter_set: str
    operation: str
    sizes: dict[str, int]
    signature_mode: str = 'pure'
    prehash_algorithm: str = ''
    randomized: bool = True
    message_length: int = 64

    @classmethod
    def from_settings(cls, settings: Mapping[str, Any]) -> PQCSpec:
        """Validate a PQC profile before any host generation or emulation."""
        if settings.get('platform') != 'baremetal' or settings.get('execution_mode') != 'baremetal-direct':
            raise ValueError("PQC requires platform 'baremetal' and execution_mode 'baremetal-direct'")
        family = settings.get('target')
        parameter = str(settings.get('parameter_set', ''))
        operation = settings.get('operation')
        if family == 'ML-KEM' and parameter in KEM_SIZES:
            public, private, ciphertext = KEM_SIZES[parameter]
            sizes = dict(public_key=public, secret_key=private, ciphertext=ciphertext, seed=64, randomness=32)
            operations = {'keygen', 'encapsulate', 'decapsulate'}
        elif family == 'ML-DSA' and parameter in DSA_SIZES:
            public, private, signature = DSA_SIZES[parameter]
            sizes = dict(public_key=public, secret_key=private, signature=signature, seed=32, randomness=32)
            operations = {'keygen', 'sign', 'verify'}
        elif family == 'SLH-DSA' and parameter in {
            f'{hash_name}-{variant}' for hash_name in ('SHA2', 'SHAKE') for variant in SLH_SIGNATURES
        }:
            variant = parameter.split('-')[1]
            n = int(variant[:3]) // 8
            sizes = dict(public_key=2*n, secret_key=4*n, signature=SLH_SIGNATURES[variant], seed=3*n, randomness=n)
            operations = {'keygen', 'sign', 'verify'}
        else:
            raise ValueError(f'Unsupported PQC family/parameter_set: {family!r}/{parameter!r}')
        if operation not in operations:
            raise ValueError(f'{family} operation must be one of {sorted(operations)}')
        mode = settings.get('signature_mode', 'pure')
        prehash = settings.get('prehash_algorithm', '')
        randomized = settings.get('randomized', True)
        length = settings.get('message_length', 64)
        if type(randomized) is not bool or type(length) is not int or length < 0:
            raise ValueError('randomized must be a JSON boolean; message_length must be a nonnegative integer')
        if mode not in {'pure', 'prehash'}:
            raise ValueError("signature_mode must be 'pure' or 'prehash'")
        if family == 'ML-KEM' and any(name in settings for name in ('signature_mode', 'prehash_algorithm', 'randomized')):
            raise ValueError('Signature settings are not applicable to ML-KEM')
        if mode == 'prehash':
            strength = {'44': 128, '65': 192, '87': 256}.get(parameter, 0)
            if family == 'SLH-DSA':
                strength = int(parameter.split('-')[1][:3])
            if prehash not in HASHES or HASHES[prehash][3] < strength:
                raise ValueError(f'prehash_algorithm must provide at least {strength} bits of collision strength')
        elif prehash:
            raise ValueError('prehash_algorithm requires signature_mode prehash')
        return cls(family, parameter, operation, sizes, mode, prehash, randomized, length)

    @property
    def name(self) -> str:
        """Return the OpenSSL provider algorithm name."""
        return f'{self.algorithm}-{self.parameter_set}'

    @property
    def tvla_variable(self) -> str:
        """Return the supported independent TVLA variable for this operation."""
        return {'keygen': 'seed', 'encapsulate': 'randomness', 'decapsulate': 'ciphertext',
                'sign': 'message', 'verify': 'message'}[self.operation]

    def metadata(self) -> dict[str, str]:
        """Return profile choices needed to interpret and replay input bytes."""
        return dict(algorithm=self.algorithm, parameter_set=self.parameter_set, operation=self.operation,
                    signature_mode=self.signature_mode if self.algorithm != 'ML-KEM' else '',
                    prehash_algorithm=self.prehash_algorithm, randomized=str(self.randomized).lower())

    def encode_message(self, message: bytes, context: bytes = b'') -> bytes:
        """Encode a pure or prehash message with the FIPS domain and DER hash OID."""
        if len(context) > 255:
            raise ValueError('context must be at most 255 bytes')
        if self.signature_mode == 'pure':
            return bytes((0, len(context))) + context + message
        hash_name, oid, length, _ = HASHES[self.prehash_algorithm]
        digest = hashlib.new(hash_name, message)
        hashed = digest.digest(length) if hash_name.startswith('shake_') else digest.digest()
        return bytes((1, len(context))) + context + bytes.fromhex('06096086480165030402') + bytes((oid,)) + hashed

    def parse(self, values: Mapping[str, str], *, metadata: bool = False) -> dict[str, str]:
        """Validate lengths while preserving supplied rejection vectors byte for byte."""
        if not isinstance(values, Mapping):
            raise ValueError('PQC inputs must be a JSON object or named CSV row')
        allowed = set(INPUT_FIELDS) | {'encoded_message'}
        if metadata:
            allowed.update(METADATA_FIELDS)
            for key, expected in self.metadata().items():
                if key in values and values[key] != expected:
                    raise ValueError(f'PQC CSV {key} does not match profile')
        unknown = set(values) - allowed
        if unknown:
            raise ValueError(f'Unknown PQC input fields: {sorted(unknown, key=str)}')
        decoded = {}
        for field in INPUT_FIELDS:
            if field not in values or values[field] == '' and field not in {'message', 'context'}:
                continue
            value = values[field]
            if not isinstance(value, str) or len(value) % 2 or any(c not in '0123456789abcdefABCDEF' for c in value):
                raise ValueError(f'{field} must be an even-length hexadecimal string')
            decoded[field] = bytes.fromhex(value)
            if field in self.sizes and len(decoded[field]) != self.sizes[field]:
                raise ValueError(f'{field} must be exactly {self.sizes[field]} bytes; got {len(decoded[field])}')
        decoded.setdefault('context', b'')
        if len(decoded['context']) > 255:
            raise ValueError('context must be at most 255 bytes')
        required = {'keygen': {'seed'}, 'encapsulate': {'public_key', 'randomness'},
                    'decapsulate': {'secret_key', 'ciphertext'}, 'sign': {'secret_key', 'message'},
                    'verify': {'public_key', 'message', 'signature'}}[self.operation].copy()
        if self.operation == 'sign':
            if self.randomized:
                required.add('randomness')
            elif 'secret_key' in decoded:
                deterministic = (bytes(32) if self.algorithm == 'ML-DSA' else
                                 decoded['secret_key'][2*self.sizes['randomness']:3*self.sizes['randomness']])
                if 'randomness' in decoded and decoded['randomness'] != deterministic:
                    raise ValueError('randomness does not match deterministic signing')
                decoded['randomness'] = deterministic
        missing = required - decoded.keys()
        if missing:
            raise ValueError(f'Missing PQC input fields: {sorted(missing)}')
        if self.algorithm != 'ML-KEM' and 'message' in decoded:
            encoded = self.encode_message(decoded['message'], decoded['context'])
            if 'encoded_message' in values and values['encoded_message'] != encoded.hex():
                raise ValueError('encoded_message does not match message/context/profile')
            decoded['encoded_message'] = encoded
        return {field: value.hex() for field, value in decoded.items()}


class PQCSettingsLoader(SettingsLoader):
    """Load PQC settings without UART or legacy symmetric cipher requirements."""

    def __init__(self, json_path: str) -> None:
        """Read and validate all PQC-specific profile settings."""
        super().__init__(json_path)
        PQCSpec.from_settings(self._settings)
        self._parsed_settings = self._settings.copy()


class PQCInputParser:
    """Read named hexadecimal JSON inputs without loading a crypto backend."""

    def parse_user_args(self, u_args: Namespace, target_settings: dict[str, Any]) -> dict[str, str]:
        """Read and validate one user-supplied JSON object."""
        with Path(u_args.pqc_inputs).open(encoding='utf-8') as source:
            return PQCSpec.from_settings(target_settings).parse(json.load(source))


class PQCInputValidator:
    """Validate raw input encodings independently of cryptographic validity."""

    def validate_inputs(self, target_data: Mapping[str, str], target_settings: dict[str, Any]) -> None:
        """Require operation inputs and parameter-dependent field lengths."""
        PQCSpec.from_settings(target_settings).parse(target_data)


def read_pqc_csv(path: str | Path, spec: PQCSpec) -> list[dict[str, str]]:
    """Load named input columns or replay an entire Sofa PQC manifest."""
    with Path(path).open(encoding='utf-8', newline='') as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames):
            raise ValueError('PQC CSV requires unique named columns')
        rows = [spec.parse(row, metadata=True) for row in reader]
    if not rows:
        raise ValueError('PQC CSV contains no inputs')
    return rows


def write_pqc_csv(path: str | Path, rows: list[dict[str, str]]) -> None:
    """Write named inputs with the union of all present fields."""
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with Path(path).open('w', encoding='utf-8', newline='') as destination:
        writer = csv.DictWriter(destination, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


class PQCInputsGenerator:
    """Create reproducible, valid vectors through the optional host backend."""

    def generate_inputs_csv(self, target_settings: dict[str, Any], nr_of_inputs: int = 10,
                            input_path: str = 'input-csv.csv') -> None:
        """Generate valid named CSV rows and record their effective seed."""
        rows, manifest, _ = generate_pqc_inputs(PQCSpec.from_settings(target_settings), nr_of_inputs)
        write_pqc_csv(input_path, manifest)


def generate_pqc_inputs(spec: PQCSpec, count: int, seed: int | None = None,
                        tvla: bool = False) -> tuple[list[dict[str, str]], list[dict[str, str]], int]:
    """Generate valid operations, preserving dependent inputs in balanced TVLA groups."""
    from sofa.components.pqc_backend import OpenSSLBackend
    if count < 1 or tvla and (count < 4 or count % 2):
        raise ValueError('PQC count must be positive; TVLA requires an even count of at least 4')
    if tvla and spec.tvla_variable == 'message' and spec.message_length == 0:
        raise ValueError('PQC TVLA requires message_length > 0')
    seed = secrets.randbits(64) if seed is None else seed
    if not 0 <= seed < 2**64:
        raise ValueError('PQC generation seed must be between 0 and 2^64 - 1')
    rng = Random(seed)
    backend = OpenSSLBackend()
    baseline = spec.parse(backend.vector(spec, rng))
    rows, manifest = [], []
    for index in range(count):
        group = 'fixed' if index % 2 == 0 else 'random'
        if tvla:
            values = baseline.copy()
            if group == 'random':
                while values == baseline:
                    values = backend.vector(spec, rng, baseline)
        else:
            values = baseline if index == 0 else backend.vector(spec, rng)
        values = spec.parse(values)
        rows.append(values)
        changed = ','.join(key for key in values if values[key] != baseline.get(key)) if tvla else ''
        manifest.append({**spec.metadata(), 'effective_seed': str(seed),
                         'trace_filename': f'traces_{index+1}.csv', 'group': group if tvla else '',
                         'tested_variable': spec.tvla_variable if tvla else '', 'changed_fields': changed, **values})
    return rows, manifest, seed
