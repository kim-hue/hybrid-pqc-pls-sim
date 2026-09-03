"""``PHYGate`` and privacy amplification ``PA``.

PHYGate is the *local* admission test each node runs on its own observation
before it is willing to let the channel contribute key material.  It is a
conjunction of four checks:

1.  **link quality** -- estimated SNR above ``snr_min_db``;
2.  **campaign validity** -- enough probe rounds actually completed;
3.  **quantiser reliability** -- enough samples sit far from a quantisation
    threshold (a local proxy for the reciprocity/cross-over error rate; it
    needs no exchange, hence leaks nothing);
4.  **entropy budget** -- the leftover-hash-lemma inequality

        L  <=  H_inf(Z) - leak(W) - 2*log2(1/eps)

    must hold for the target length ``L = target_phy_bits``, where
    ``H_inf(Z)`` is the conservative NIST SP 800-90B estimate and ``leak(W)``
    is the exact syndrome length of the helper data.

Privacy amplification uses a Toeplitz-matrix universal hash -- a genuine
strong extractor, so the LHL bound above is the right one -- seeded from the
public transcript hash ``T_2``.  Seeding from ``T_2`` binds the extractor
instance to the authenticated session, so helper data / extractor seeds from
another session cannot be spliced in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from math import ceil
from typing import Dict, Optional

import numpy as np

from .config import GateConfig, QuantConfig
from .entropy import EntropyReport, analyse
from .primitives import enc, hkdf_expand, hkdf_extract
from .quantize import QuantResult, bits_to_bytes
from .reconcile import HelperData


@dataclass
class GateDecision:
    accept: bool
    snr_ok: bool
    rounds_ok: bool
    reliability_ok: bool
    entropy_ok: bool
    snr_db: float
    n_rounds: int
    reliable_fraction: float
    retained_fraction: float
    h_min_bits: float
    leak_bits: int
    budget_bits: float
    entropy: Optional[EntropyReport] = None

    def reasons(self) -> Dict[str, bool]:
        return {"snr": self.snr_ok, "rounds": self.rounds_ok,
                "reliability": self.reliability_ok, "entropy": self.entropy_ok}


def phy_gate(q: QuantResult, W: HelperData, snr_db_est: float, n_rounds: int,
             qcfg: QuantConfig, gcfg: GateConfig) -> GateDecision:
    """``g <- PHYGate(Y, W)``.

    Note that the entropy budget is evaluated on the *retained* symbol
    sequence (the samples the mask in ``W`` keeps), because that is exactly
    the string privacy amplification will be applied to.
    """
    snr_ok = bool(snr_db_est >= gcfg.snr_min_db)
    rounds_ok = bool(n_rounds >= gcfg.min_probe_rounds)

    # local, non-exchanged channel-quality statistic
    frac = float(np.mean(q.reliability >= gcfg.reliability_margin))
    rel_ok = bool(frac >= gcfg.min_reliable_fraction)

    try:
        _, levels = W.select(q)
    except ValueError:
        levels = np.zeros(0, dtype=np.int64)
    retained = float(levels.size / max(q.levels.size, 1))
    rep = analyse(levels, 1 << qcfg.bits_per_sample)
    leak = W.leak_bits
    budget = rep.h_min_total - leak - 2 * gcfg.pa_epsilon_log2
    ent_ok = bool(budget >= gcfg.target_phy_bits)

    accept = bool(snr_ok and rounds_ok and rel_ok and ent_ok)
    return GateDecision(accept, snr_ok, rounds_ok, rel_ok, ent_ok,
                        float(snr_db_est), int(n_rounds), frac, retained,
                        rep.h_min_total, leak, budget, rep)


# --------------------------------------------------------------------------
# privacy amplification
# --------------------------------------------------------------------------


def _toeplitz_seed(t2: bytes, n_in: int, n_out: int) -> np.ndarray:
    need_bits = n_in + n_out - 1
    raw = hkdf_expand(hkdf_extract(t2, b"PA-EXTRACTOR"), enc("PA-SEED", n_in, n_out),
                      ceil(need_bits / 8))
    return np.unpackbits(np.frombuffer(raw, dtype=np.uint8))[:need_bits]


def privacy_amplify(bits: np.ndarray, t2: bytes, n_out_bits: int) -> bytes:
    """``PA(Z, T_2)``: Toeplitz universal hash, seed derived from ``T_2``."""
    z = np.asarray(bits, dtype=np.uint8).ravel()
    n_in = int(z.size)
    if n_in == 0:
        raise ValueError("empty input to privacy amplification")
    seed = _toeplitz_seed(t2, n_in, n_out_bits)
    out = np.empty(n_out_bits, dtype=np.uint8)
    for i in range(n_out_bits):
        row = seed[i:i + n_in]                 # Toeplitz: row i is a shift
        out[i] = np.bitwise_xor.reduce(row & z) & 1
    return bits_to_bytes(out)
