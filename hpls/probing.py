"""Step 2: session-bound physical-layer probing.

``probe_ctx`` is *derived* rather than negotiated: both parties compute it
deterministically from the authenticated pair ``(sid, N_U)``.  It fixes the
pilot subcarrier set, the per-round sounding instants (with pseudorandom
jitter) and the sounding sequence seed.  Consequences:

* the probing schedule is unpredictable to an off-path adversary, so Eve
  cannot pre-position or pre-compute her soundings;
* ``h_probe = H(probe_ctx)`` is signed inside ``m2`` in Step 3, which binds
  the radio measurement campaign to the authenticated session and prevents
  replaying helper data from a different session or a different channel.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

import numpy as np

from .channel import RadioWorld
from .config import PhyConfig
from .primitives import H, enc, hkdf_expand


@dataclass(frozen=True)
class ProbeContext:
    sid: bytes
    n_u: bytes
    scs_hz: float
    subcarriers: Tuple[int, ...]
    round_times_us: Tuple[float, ...]
    tdd_gap_us: float
    n_avg_symbols: int
    pilot_seed: bytes

    def to_bytes_msg(self) -> bytes:
        return enc("probe_ctx", self.sid, self.n_u, int(self.scs_hz),
                   tuple(int(s) for s in self.subcarriers),
                   tuple(round(float(t), 3) for t in self.round_times_us),
                   round(float(self.tdd_gap_us), 3), int(self.n_avg_symbols),
                   self.pilot_seed)

    def h_probe(self) -> bytes:
        return H("h_probe", self.to_bytes_msg())

    @property
    def n_rounds(self) -> int:
        return len(self.round_times_us)

    @property
    def n_pilots(self) -> int:
        return len(self.subcarriers)

    def freqs_hz(self) -> np.ndarray:
        return np.asarray(self.subcarriers, dtype=float) * self.scs_hz

    def times_s(self, role: str) -> np.ndarray:
        """Sounding instants; the UE sounds ``tdd_gap`` after the gNB."""
        t = np.asarray(self.round_times_us, dtype=float) * 1e-6
        return t + (self.tdd_gap_us * 1e-6 if role == "U" else 0.0)

    @staticmethod
    def derive(sid: bytes, n_u: bytes, cfg: PhyConfig) -> "ProbeContext":
        """Deterministic, session-bound probing schedule."""
        prk = H("PROBE-CTX", sid, n_u)
        spacing = cfg.effective_pilot_spacing()
        n_pilots = cfg.n_subcarriers // spacing
        interval_us = cfg.effective_probe_interval_us()
        need = 2 * n_pilots + 2 * cfg.n_probe_rounds + 32
        stream = hkdf_expand(prk, enc("PROBE-SCHEDULE"), need)
        pos = 0

        def u16() -> int:
            nonlocal pos
            v = int.from_bytes(stream[pos:pos + 2], "big")
            pos += 2
            return v

        # pilot comb: one pseudorandom subcarrier inside each coherence bin
        subcarriers = []
        for b in range(n_pilots):
            off = u16() % spacing
            sc = b * spacing + off
            if sc < cfg.n_subcarriers:
                subcarriers.append(sc)
        # sounding instants: nominal grid + up to +-10 % jitter
        times = []
        for r in range(cfg.n_probe_rounds):
            jit = (u16() / 65535.0 - 0.5) * 0.2 * interval_us
            times.append(r * interval_us + jit)
        return ProbeContext(sid, n_u, cfg.scs_hz, tuple(subcarriers),
                            tuple(times), cfg.tdd_gap_us,
                            int(cfg.n_avg_symbols), stream[-32:])


@dataclass
class Observation:
    """One node's raw channel observation ``Y`` (Step 2)."""

    csi: np.ndarray          # complex, shape (n_rounds, n_pilots)
    feat: np.ndarray         # real feature vector fed to the quantiser
    snr_db_est: float

    @property
    def n(self) -> int:
        return int(self.feat.size)


def estimate(world: RadioWorld, role: str, ctx: ProbeContext) -> Observation:
    """``Estimate_role(probe_ctx)`` -> ``Y_role``.

    The feature used for key generation is the per-subcarrier CFR magnitude in
    dB (an envelope feature: robust to the residual carrier-phase and
    timing offsets that would destroy raw-phase reciprocity).
    """
    t = ctx.times_s(role)
    f = ctx.freqs_hz()
    m_avg = max(int(ctx.n_avg_symbols), 1)
    t_sym = 1.07 / ctx.scs_hz             # OFDM symbol duration incl. CP
    acc = np.zeros((len(t), len(f)), dtype=complex)
    for m in range(m_avg):
        acc += world.observe(role, t + m * t_sym, f)
    csi = acc / m_avg                     # coherent pilot averaging
    mag = np.abs(csi)
    feat = 20.0 * np.log10(np.maximum(mag, 1e-12)).ravel()
    p_rx = float(np.mean(mag ** 2))
    sigma2 = world.noise_floor(role, ctx.n_pilots) / m_avg
    snr_est = 10.0 * np.log10(max(p_rx / sigma2 - 1.0, 1e-3))
    return Observation(csi=csi, feat=feat, snr_db_est=snr_est)
