"""Wire messages of the hybrid PQC-PLS protocol.

Every message has a canonical, injective byte encoding (``to_bytes_msg``) so
that transcript hashes are unambiguous, and a ``size()`` used by the
performance evaluation to report real on-the-wire overhead.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Tuple

from .primitives import Certificate, enc
from .reconcile import HelperData


class _Msg:
    def size(self) -> int:
        return len(self.to_bytes_msg())      # type: ignore[attr-defined]


@dataclass
class M1(_Msg):
    """``m1 = (sid, N_U, pk_E, alg_list, SN_id)``"""

    sid: bytes
    n_u: bytes
    pk_e: bytes
    alg_list: Tuple[str, ...]
    sn_id: str

    def to_bytes_msg(self) -> bytes:
        return enc("m1", self.sid, self.n_u, self.pk_e,
                   tuple(self.alg_list), self.sn_id)


@dataclass
class M2(_Msg):
    """``m2 = (sid, N_U, N_B, C_KEM, W, alg_sel, SN_id, h_probe)``"""

    sid: bytes
    n_u: bytes
    n_b: bytes
    c_kem: bytes
    w: HelperData
    alg_sel: str
    sn_id: str
    h_probe: bytes

    def to_bytes_msg(self) -> bytes:
        return enc("m2", self.sid, self.n_u, self.n_b, self.c_kem,
                   self.w.to_bytes_msg(), self.alg_sel, self.sn_id, self.h_probe)


@dataclass
class MConf(_Msg):
    """Reconciliation verification ``(r, v_B)`` of Step 4."""

    sid: bytes
    r: bytes
    v_b: bytes

    def to_bytes_msg(self) -> bytes:
        return enc("mconf", self.sid, self.r, self.v_b)


@dataclass
class M3(_Msg):
    """``m3 = (sid, d_U)`` with MAC ``tau_3``."""

    sid: bytes
    d_u: bool

    def to_bytes_msg(self) -> bytes:
        return enc("m3", self.sid, self.d_u)


@dataclass
class M4(_Msg):
    """``m4 = (sid, d_U, d_B, G_PHY)`` with MAC ``tau_4``."""

    sid: bytes
    d_u: bool
    d_b: bool
    g_phy: bool

    def to_bytes_msg(self) -> bytes:
        return enc("m4", self.sid, self.d_u, self.d_b, self.g_phy)


@dataclass
class Flight1(_Msg):
    m1: M1
    sig_u: bytes
    cert_u: Certificate

    def to_bytes_msg(self) -> bytes:
        return enc("flight1", self.m1.to_bytes_msg(), self.sig_u,
                   self.cert_u.to_bytes_msg())


@dataclass
class Flight2(_Msg):
    m2: M2
    sig_b: bytes
    cert_b: Certificate

    def to_bytes_msg(self) -> bytes:
        return enc("flight2", self.m2.to_bytes_msg(), self.sig_b,
                   self.cert_b.to_bytes_msg())


@dataclass
class Flight3(_Msg):
    m3: M3
    tau3: bytes

    def to_bytes_msg(self) -> bytes:
        return enc("flight3", self.m3.to_bytes_msg(), self.tau3)


@dataclass
class Flight4(_Msg):
    m4: M4
    tau4: bytes

    def to_bytes_msg(self) -> bytes:
        return enc("flight4", self.m4.to_bytes_msg(), self.tau4)


@dataclass
class Finished(_Msg):
    sid: bytes
    ct: bytes

    def to_bytes_msg(self) -> bytes:
        return enc("finished", self.sid, self.ct)


@dataclass
class Record(_Msg):
    sid: bytes
    i: int
    ct: bytes

    def to_bytes_msg(self) -> bytes:
        return enc("record", self.sid, self.i, self.ct)


def with_field(msg, **kw):
    """Adversary helper: shallow-copy a dataclass message with fields replaced."""
    return replace(msg, **kw)
