"""Optional OpenSSL 3.5+ host vector backend; never imported for supplied inputs."""

from __future__ import annotations

import ctypes as C
from ctypes.util import find_library
from contextlib import contextmanager
import os
from random import Random
from typing import Any, Iterator

from sofa.components.pqc import PQCSpec


class BackendUnavailable(RuntimeError):
    """Indicate that the optional PQC vector provider cannot be used."""


class OSSLParam(C.Structure):
    """Match the public OpenSSL OSSL_PARAM ABI."""

    _fields_ = [('key', C.c_char_p), ('data_type', C.c_uint), ('data', C.c_void_p),
                ('data_size', C.c_size_t), ('return_size', C.c_size_t)]


class Parameters:
    """Keep OSSL_PARAM backing storage alive for each synchronous EVP call."""

    def __init__(self, values: dict[str, bytes | int]) -> None:
        """Build typed integer and octet parameters and their terminating entry."""
        self.storage: list[Any] = []
        self.array = (OSSLParam * (len(values) + 1))()
        for index, (name, value) in enumerate(values.items()):
            key = name.encode('ascii')
            storage = C.c_int(value) if isinstance(value, int) else C.create_string_buffer(value)
            self.storage.extend((key, storage))
            self.array[index] = OSSLParam(key, 1 if isinstance(value, int) else 5,
                                          C.cast(C.pointer(storage), C.c_void_p),
                                          C.sizeof(storage) if isinstance(value, int) else len(value), 0)


class OpenSSLBackend:
    """Bind EVP with explicit entropy, checked results and deterministic cleanup."""

    def __init__(self) -> None:
        """Lazily load a provider-capable libcrypto, with actionable errors."""
        path = os.environ.get('SOFA_LIBCRYPTO') or find_library('crypto')
        try:
            if not path:
                raise OSError('libcrypto was not found')
            self.lib = C.CDLL(path)
            self._bind('OpenSSL_version_num', C.c_ulong, [])
            if self.lib.OpenSSL_version_num() < 0x30500000:
                raise OSError('libcrypto is older than OpenSSL 3.5')
            p, n, i, s = C.c_void_p, C.c_size_t, C.c_int, C.c_char_p
            pn = C.POINTER(n)
            pp = C.POINTER(p)
            signatures = {
                'EVP_PKEY_CTX_new_from_name': (p, [p, s, s]),
                'EVP_PKEY_CTX_new_from_pkey': (p, [p, p, s]),
                'EVP_PKEY_CTX_free': (None, [p]), 'EVP_PKEY_free': (None, [p]),
                'EVP_PKEY_keygen_init': (i, [p]), 'EVP_PKEY_CTX_set_params': (i, [p, p]),
                'EVP_PKEY_generate': (i, [p, pp]),
                'EVP_PKEY_get_octet_string_param': (i, [p, s, p, n, pn]),
                'EVP_PKEY_fromdata_init': (i, [p]), 'EVP_PKEY_fromdata': (i, [p, pp, i, p]),
                'EVP_PKEY_encapsulate_init': (i, [p, p]),
                'EVP_PKEY_encapsulate': (i, [p, p, pn, p, pn]),
                'EVP_PKEY_decapsulate_init': (i, [p, p]),
                'EVP_PKEY_decapsulate': (i, [p, p, pn, p, n]),
                'EVP_SIGNATURE_fetch': (p, [p, s, s]), 'EVP_SIGNATURE_free': (None, [p]),
                'EVP_PKEY_sign_message_init': (i, [p, p, p]),
                'EVP_PKEY_verify_message_init': (i, [p, p, p]),
                'EVP_PKEY_sign': (i, [p, p, pn, p, n]),
                'EVP_PKEY_verify': (i, [p, p, n, p, n]),
                'ERR_get_error': (C.c_ulong, []), 'ERR_error_string_n': (None, [C.c_ulong, p, n]),
            }
            for name, (result, args) in signatures.items():
                self._bind(name, result, args)
        except (OSError, AttributeError) as error:
            raise BackendUnavailable(
                'PQC generation and TVLA require OpenSSL 3.5+ libcrypto with ML-KEM, ML-DSA and SLH-DSA '
                'enabled. Install it or set SOFA_LIBCRYPTO to its shared-library path. '
                f'Supplied JSON/CSV vectors do not need this backend. Details: {error}'
            ) from error

    def _bind(self, name: str, result: Any, arguments: list[Any]) -> None:
        """Declare every foreign function's argument and return types."""
        function = getattr(self.lib, name)
        function.restype, function.argtypes = result, arguments

    def _check(self, result: Any, operation: str) -> Any:
        """Raise a diagnostic with the OpenSSL error queue on EVP failure."""
        if result is not None and result > 0:
            return result
        errors = []
        while code := self.lib.ERR_get_error():
            buffer = C.create_string_buffer(256)
            self.lib.ERR_error_string_n(code, buffer, len(buffer))
            errors.append(buffer.value.decode('utf-8', errors='replace'))
        raise RuntimeError(f'OpenSSL PQC {operation} failed: {"; ".join(errors) or "provider rejected operation"}. '
                           'Ensure the default provider enables the requested PQC algorithm and testing parameters.')

    @contextmanager
    def _resource(self, pointer: Any, free: str, description: str) -> Iterator[Any]:
        """Release an EVP allocation even when a later provider call fails."""
        pointer = self._check(pointer, description)
        try:
            yield pointer
        finally:
            getattr(self.lib, free)(pointer)

    @contextmanager
    def _context(self, spec: PQCSpec, key: Any = None) -> Iterator[Any]:
        """Allocate a named key context or a context bound to a loaded key."""
        pointer = (self.lib.EVP_PKEY_CTX_new_from_pkey(None, key, None) if key else
                   self.lib.EVP_PKEY_CTX_new_from_name(None, spec.name.encode(), None))
        with self._resource(pointer, 'EVP_PKEY_CTX_free', f'fetch {spec.name}') as context:
            yield context

    def _export(self, key: Any, name: str, size: int) -> bytes:
        """Export a raw expanded FIPS key component with an exact length check."""
        buffer, length = C.create_string_buffer(size), C.c_size_t(size)
        self._check(self.lib.EVP_PKEY_get_octet_string_param(key, name.encode(), buffer, size, C.byref(length)), 'key export')
        if length.value != size:
            raise RuntimeError(f'Unexpected OpenSSL {name} size: {length.value}, expected {size}')
        return buffer.raw[:length.value]

    def keygen(self, spec: PQCSpec, seed: bytes) -> dict[str, bytes]:
        """Generate FIPS expanded keys from an explicit key-generation seed."""
        if len(seed) != spec.sizes['seed']:
            raise ValueError('Incorrect PQC keygen seed length')
        with self._context(spec) as context:
            self._check(self.lib.EVP_PKEY_keygen_init(context), 'keygen init')
            params = Parameters({'seed': seed})
            self._check(self.lib.EVP_PKEY_CTX_set_params(context, params.array), 'keygen seed')
            key = C.c_void_p()
            try:
                self._check(self.lib.EVP_PKEY_generate(context, C.byref(key)), 'keygen')
                return dict(seed=seed, public_key=self._export(key, 'pub', spec.sizes['public_key']),
                            secret_key=self._export(key, 'priv', spec.sizes['secret_key']))
            finally:
                self.lib.EVP_PKEY_free(key)

    @contextmanager
    def _key(self, spec: PQCSpec, values: dict[str, bytes], private: bool) -> Iterator[Any]:
        """Import raw expanded keys without a seed overriding their encoding."""
        params = Parameters({'priv' if private else 'pub': values['secret_key' if private else 'public_key']})
        with self._context(spec) as context:
            self._check(self.lib.EVP_PKEY_fromdata_init(context), 'key import init')
            key = C.c_void_p()
            try:
                self._check(self.lib.EVP_PKEY_fromdata(context, C.byref(key), 0x87 if private else 0x86, params.array), 'key import')
                yield key
            finally:
                self.lib.EVP_PKEY_free(key)

    def encapsulate(self, spec: PQCSpec, values: dict[str, bytes]) -> tuple[bytes, bytes]:
        """Encapsulate with the FIPS 203 explicit 32-byte m randomness."""
        if len(values['randomness']) != 32:
            raise ValueError('ML-KEM randomness must be 32 bytes')
        with self._key(spec, values, False) as key, self._context(spec, key) as context:
            params = Parameters({'ikme': values['randomness']})
            self._check(self.lib.EVP_PKEY_encapsulate_init(context, params.array), 'encapsulation init')
            ciphertext, secret = C.create_string_buffer(spec.sizes['ciphertext']), C.create_string_buffer(32)
            clen, slen = C.c_size_t(len(ciphertext)), C.c_size_t(32)
            self._check(self.lib.EVP_PKEY_encapsulate(context, ciphertext, C.byref(clen), secret, C.byref(slen)), 'encapsulation')
            return ciphertext.raw[:clen.value], secret.raw[:slen.value]

    def decapsulate(self, spec: PQCSpec, values: dict[str, bytes]) -> bytes:
        """Decapsulate a raw ciphertext for host-side vector verification."""
        with self._key(spec, values, True) as key, self._context(spec, key) as context:
            self._check(self.lib.EVP_PKEY_decapsulate_init(context, None), 'decapsulation init')
            secret, length = C.create_string_buffer(32), C.c_size_t(32)
            ciphertext = values['ciphertext']
            self._check(self.lib.EVP_PKEY_decapsulate(context, secret, C.byref(length), ciphertext, len(ciphertext)), 'decapsulation')
            return secret.raw[:length.value]

    def signature(self, spec: PQCSpec, values: dict[str, bytes], verify: bool = False) -> bytes | bool:
        """Sign or verify a FIPS-encoded message without a second encoding layer."""
        with self._key(spec, values, not verify) as key, self._context(spec, key) as context:
            pointer = self.lib.EVP_SIGNATURE_fetch(None, spec.name.encode(), None)
            with self._resource(pointer, 'EVP_SIGNATURE_free', 'signature fetch') as algorithm:
                parameters: dict[str, bytes | int] = {'message-encoding': 0}
                if not verify:
                    parameters['test-entropy'] = values['randomness']
                params = Parameters(parameters)
                init = self.lib.EVP_PKEY_verify_message_init if verify else self.lib.EVP_PKEY_sign_message_init
                self._check(init(context, algorithm, params.array), 'signature init')
                message = spec.encode_message(values['message'], values.get('context', b''))
                if verify:
                    signature = values['signature']
                    result = self.lib.EVP_PKEY_verify(context, signature, len(signature), message, len(message))
                    if result == 0:
                        # Invalid signatures are expected, and must not pollute later diagnostics.
                        while self.lib.ERR_get_error():
                            pass
                        return False
                    self._check(result, 'verification')
                    return True
                buffer, length = C.create_string_buffer(spec.sizes['signature']), C.c_size_t(spec.sizes['signature'])
                self._check(self.lib.EVP_PKEY_sign(context, buffer, C.byref(length), message, len(message)), 'signing')
                return buffer.raw[:length.value]

    def vector(self, spec: PQCSpec, rng: Random, baseline: dict[str, str] | None = None) -> dict[str, str]:
        """Generate a valid operation, optionally varying only its TVLA dependencies."""
        values = ({name: bytes.fromhex(value) for name, value in baseline.items() if name != 'encoded_message'}
                  if baseline else self.keygen(spec, rng.randbytes(spec.sizes['seed'])))
        if spec.operation == 'keygen':
            if baseline:
                values = self.keygen(spec, rng.randbytes(spec.sizes['seed']))
        elif spec.algorithm == 'ML-KEM':
            values['randomness'] = rng.randbytes(32)
            values['ciphertext'], _ = self.encapsulate(spec, values)
        else:
            values['message'] = rng.randbytes(spec.message_length)
            values.setdefault('context', b'')
            if not baseline:
                values['randomness'] = (rng.randbytes(spec.sizes['randomness']) if spec.randomized else
                                        bytes(32) if spec.algorithm == 'ML-DSA' else
                                        values['secret_key'][2*spec.sizes['randomness']:3*spec.sizes['randomness']])
            values['signature'] = self.signature(spec, values)
        return {name: value.hex() for name, value in values.items()}
