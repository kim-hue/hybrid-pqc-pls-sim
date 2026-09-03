"""Cryptographic primitives used by the hybrid PQC-PLS protocol.

Everything here is a real implementation:

* ``KEM``  -> ML-KEM-768   (FIPS 203, ``kyber-py``)
* ``Sig``  -> ML-DSA-65    (FIPS 204, ``dilithium-py``)
* ``AEAD`` -> AES-256-GCM  (``cryptography``)
* ``H``    -> SHA3-256, ``MAC`` -> HMAC-SHA-256, ``HKDF`` -> RFC 5869

Canonical encoding
------------------
The protocol figures write hashes over concatenations such as
``H(m1 || sigma_U || m2)``.  Raw concatenation of variable-length fields is
not injective, so every hash/MAC input here goes through :func:`enc`, a
type-tagged, length-prefixed (TLV) encoder.  This makes the transcript hash
collision-free with respect to field boundaries, which is exactly what the
transcript-binding argument needs.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dilithium_py.ml_dsa import ML_DSA_65
from kyber_py.ml_kem import ML_KEM_768

# --------------------------------------------------------------------------
# canonical TLV encoding
# --------------------------------------------------------------------------

_T_BYTES = 0x01
_T_INT = 0x02
_T_STR = 0x03
_T_BOOL = 0x04
_T_NONE = 0x05
_T_SEQ = 0x06
_T_FLOAT = 0x07


def _enc_one(x: Any) -> bytes:
    if x is None:
        return bytes([_T_NONE]) + (0).to_bytes(4, "big")
    if isinstance(x, bool):
        return bytes([_T_BOOL]) + (1).to_bytes(4, "big") + bytes([1 if x else 0])
    if isinstance(x, int):
        body = x.to_bytes(8, "big", signed=True)
        return bytes([_T_INT]) + len(body).to_bytes(4, "big") + body
    if isinstance(x, float):
        body = struct.pack(">d", x)          # IEEE-754 big-endian: canonical
        return bytes([_T_FLOAT]) + len(body).to_bytes(4, "big") + body
    if isinstance(x, (bytes, bytearray, memoryview)):
        body = bytes(x)
        return bytes([_T_BYTES]) + len(body).to_bytes(4, "big") + body
    if isinstance(x, str):
        body = x.encode("utf-8")
        return bytes([_T_STR]) + len(body).to_bytes(4, "big") + body
    if isinstance(x, (tuple, list)):
        body = b"".join(_enc_one(i) for i in x)
        return bytes([_T_SEQ]) + len(body).to_bytes(4, "big") + body
    if hasattr(x, "to_bytes_msg"):
        return _enc_one(x.to_bytes_msg())
    raise TypeError(f"cannot canonically encode {type(x)!r}")


def enc(*parts: Any) -> bytes:
    """Injective encoding of an ordered tuple of fields."""
    return b"".join(_enc_one(p) for p in parts)


# --------------------------------------------------------------------------
# hash / KDF / MAC
# --------------------------------------------------------------------------

HASH_LEN = 32


def H(*parts: Any) -> bytes:
    """SHA3-256 over the canonical encoding of ``parts``."""
    return hashlib.sha3_256(enc(*parts)).digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 HKDF-Extract with HMAC-SHA-256."""
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-Expand with HMAC-SHA-256."""
    if length > 255 * 32:
        raise ValueError("HKDF-Expand output too long")
    out, t, counter = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def mac(key: bytes, label: str, *parts: Any) -> bytes:
    """HMAC-SHA-256 with an explicit domain-separation label."""
    return hmac.new(key, enc(label, *parts), hashlib.sha256).digest()


def verify_mac(key: bytes, tag: bytes, label: str, *parts: Any) -> bool:
    return hmac.compare_digest(mac(key, label, *parts), tag)


# --------------------------------------------------------------------------
# AEAD
# --------------------------------------------------------------------------

NONCE_LEN = 12


def nonce_xor(base: bytes, counter: int) -> bytes:
    """``nonce_i = n^0 XOR i`` as written in the protocol figure."""
    if len(base) != NONCE_LEN:
        raise ValueError("nonce base must be 12 bytes")
    ctr = counter.to_bytes(NONCE_LEN, "big")
    return bytes(a ^ b for a, b in zip(base, ctr))


class AEAD:
    """AES-256-GCM Seal/Open with canonically-encoded associated data."""

    @staticmethod
    def seal(key: bytes, nonce: bytes, ad: Iterable[Any], plaintext: bytes) -> bytes:
        return AESGCM(key).encrypt(nonce, plaintext, enc(*tuple(ad)))

    @staticmethod
    def open(key: bytes, nonce: bytes, ad: Iterable[Any], ct: bytes) -> Optional[bytes]:
        try:
            return AESGCM(key).decrypt(nonce, ct, enc(*tuple(ad)))
        except Exception:
            return None  # bottom


# --------------------------------------------------------------------------
# operation accounting (used by the performance experiments)
# --------------------------------------------------------------------------


class OpStats:
    """Wall-clock and call-count accounting per named operation."""

    def __init__(self) -> None:
        self.time_s: Dict[str, float] = defaultdict(float)
        self.calls: Dict[str, int] = defaultdict(int)

    def add(self, name: str, dt: float) -> None:
        self.time_s[name] += dt
        self.calls[name] += 1

    def reset(self) -> None:
        self.time_s.clear()
        self.calls.clear()

    def snapshot(self) -> Dict[str, Dict[str, float]]:
        return {
            k: {"total_ms": self.time_s[k] * 1e3, "calls": self.calls[k],
                "mean_ms": self.time_s[k] * 1e3 / max(self.calls[k], 1)}
            for k in sorted(self.time_s)
        }


STATS = OpStats()


class timed:
    """Context manager / decorator recording elapsed time into ``STATS``."""

    def __init__(self, name: str, stats: OpStats | None = None) -> None:
        self.name = name
        self.stats = stats or STATS

    def __enter__(self) -> "timed":
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, *exc) -> None:
        self.stats.add(self.name, time.perf_counter() - self.t0)
        return None


# --------------------------------------------------------------------------
# post-quantum KEM and signature
# --------------------------------------------------------------------------


class KEM:
    """ML-KEM-768 (FIPS 203)."""

    name = "ML-KEM-768"
    pk_len, sk_len, ct_len, ss_len = 1184, 2400, 1088, 32

    @staticmethod
    def keygen() -> Tuple[bytes, bytes]:
        with timed("KEM.KeyGen"):
            ek, dk = ML_KEM_768.keygen()
        return ek, dk

    @staticmethod
    def encaps(pk: bytes) -> Tuple[bytes, bytes]:
        """Returns ``(ciphertext, shared_secret)`` (figure order)."""
        with timed("KEM.Encaps"):
            ss, ct = ML_KEM_768.encaps(pk)
        return ct, ss

    @staticmethod
    def decaps(sk: bytes, ct: bytes) -> bytes:
        with timed("KEM.Decaps"):
            return ML_KEM_768.decaps(sk, ct)


class Sig:
    """ML-DSA-65 (FIPS 204)."""

    name = "ML-DSA-65"
    pk_len, sk_len, sig_len = 1952, 4032, 3309

    @staticmethod
    def keygen() -> Tuple[bytes, bytes]:
        with timed("Sig.KeyGen"):
            return ML_DSA_65.keygen()

    @staticmethod
    def sign(sk: bytes, msg: bytes) -> bytes:
        with timed("Sig.Sign"):
            return ML_DSA_65.sign(sk, msg)

    @staticmethod
    def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
        with timed("Sig.Verify"):
            try:
                return bool(ML_DSA_65.verify(pk, msg, sig))
            except Exception:
                return False


# --------------------------------------------------------------------------
# certificates (a minimal PQC PKI: one offline CA)
# --------------------------------------------------------------------------


@dataclass
class Certificate:
    subject: str
    pk_sig: bytes
    not_before: int
    not_after: int
    issuer: str
    issuer_sig: bytes = b""

    def tbs(self) -> bytes:
        return enc("TBSCertificate", self.subject, self.pk_sig,
                   self.not_before, self.not_after, self.issuer)

    def to_bytes_msg(self) -> bytes:
        return enc("Certificate", self.tbs(), self.issuer_sig)

    def size(self) -> int:
        return len(self.to_bytes_msg())


class CA:
    """Offline certification authority holding an ML-DSA-65 key pair."""

    def __init__(self, name: str = "5G-Home-Network-CA") -> None:
        self.name = name
        self.pk, self._sk = Sig.keygen()

    def issue(self, subject: str, pk_sig: bytes,
              validity_s: int = 365 * 24 * 3600) -> Certificate:
        now = int(time.time())
        cert = Certificate(subject, pk_sig, now - 60, now + validity_s, self.name)
        cert.issuer_sig = Sig.sign(self._sk, cert.tbs())
        return cert

    def verify(self, cert: Certificate, now: Optional[int] = None) -> bool:
        now = int(time.time()) if now is None else now
        if cert.issuer != self.name:
            return False
        if not (cert.not_before <= now <= cert.not_after):
            return False
        return Sig.verify(self.pk, cert.tbs(), cert.issuer_sig)


# --------------------------------------------------------------------------
# replay protection
# --------------------------------------------------------------------------


class ReplayCache:
    """``ReplayCheck(sid, N_U)`` of Step 1: reject any repeated pair."""

    def __init__(self) -> None:
        self._seen: set[bytes] = set()

    def check_and_insert(self, sid: bytes, nonce: bytes) -> bool:
        key = H("REPLAY", sid, nonce)
        if key in self._seen:
            return False
        self._seen.add(key)
        return True


class SlidingWindow:
    """Data-plane ``ReplayCheck(i)`` with an RFC-4303-style sliding window."""

    def __init__(self, size: int = 64) -> None:
        self.size = size
        self.highest = -1
        self.bitmap = 0

    def check_and_insert(self, i: int) -> bool:
        if i < 0:
            return False
        if i > self.highest:
            shift = i - self.highest
            self.bitmap = ((self.bitmap << shift) | 1) & ((1 << self.size) - 1)
            self.highest = i
            return True
        offset = self.highest - i
        if offset >= self.size:
            return False
        if (self.bitmap >> offset) & 1:
            return False
        self.bitmap |= 1 << offset
        return True


def rand_bytes(n: int) -> bytes:
    return os.urandom(n)
