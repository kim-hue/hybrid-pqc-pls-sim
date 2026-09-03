"""Information reconciliation: ``ReconcileHelper`` and ``Reconcile``.

``W = ReconcileHelper(Y_B)`` produces two public objects:

1.  a **retained-sample mask**.  The gNB drops the samples whose quantiser
    input falls inside a guard band around a decision threshold; those are
    precisely the samples that would cross over at the UE.  Only the *indices*
    are published, never the values.  Under the symmetry of the (block
    z-scored) fading feature the mask carries no information about the sign /
    level of the retained samples, but it does condition their distribution,
    which is why the entropy budget in :mod:`hpls.gate` is always evaluated on
    the **retained** sequence rather than on the raw one.
2.  a **BCH syndrome** of the retained bit string -- a syndrome-based secure
    sketch (Dodis-Ostrovsky-Reyzin-Smith) whose entropy loss is exactly the
    published syndrome length ``n_blocks*(n-k)`` bits.

Both are carried inside ``m2`` and therefore covered by ``sigma_B``, so an
attacker cannot substitute helper data from another session or another
channel: the signature also covers ``h_probe``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

import numpy as np

from .bch import BCH, get_bch
from .config import CodeConfig, QuantConfig
from .primitives import H, enc
from .quantize import QuantResult, bits_to_bytes, bytes_to_bits


@dataclass
class HelperData:
    """``W`` -- public reconciliation helper data."""

    m: int
    t: int
    bits_per_sample: int
    n_samples: int           # length of the full probing campaign
    mask: bytes              # packed retained-sample indicator, n_samples bits
    n_bits: int              # length of the retained bit string Z
    n_blocks: int
    syndrome: bytes

    @property
    def leak_bits(self) -> int:
        """Bits of entropy the published syndrome removes from Z."""
        return self.n_blocks * get_bch(self.m, self.t).n_k

    def mask_bits(self) -> np.ndarray:
        return bytes_to_bits(self.mask, self.n_samples).astype(bool)

    def select(self, q: QuantResult) -> Tuple[np.ndarray, np.ndarray]:
        """Apply the retained-sample mask: returns ``(bits, levels)``."""
        keep = self.mask_bits()
        if q.levels.size != keep.size:
            raise ValueError("helper data does not match this campaign")
        b = self.bits_per_sample
        bits = q.bits.reshape(-1, b)[keep].ravel()
        return bits, q.levels[keep]

    def to_bytes_msg(self) -> bytes:
        return enc("W", self.m, self.t, self.bits_per_sample, self.n_samples,
                   self.mask, self.n_bits, self.n_blocks, self.syndrome)

    def size(self) -> int:
        return len(self.to_bytes_msg())

    def with_syndrome_flips(self, n_flips: int = 1,
                            rng: Optional[np.random.Generator] = None
                            ) -> "HelperData":
        """Adversarial helper-data corruption (syndrome bits flipped)."""
        rng = rng or np.random.default_rng(0)
        bits = np.unpackbits(np.frombuffer(self.syndrome, dtype=np.uint8))
        idx = rng.choice(bits.size, size=min(n_flips, bits.size), replace=False)
        bits[idx] ^= 1
        return HelperData(self.m, self.t, self.bits_per_sample, self.n_samples,
                          self.mask, self.n_bits, self.n_blocks,
                          np.packbits(bits).tobytes())


def _blocks(bits: np.ndarray, n: int) -> Tuple[np.ndarray, int]:
    """Zero-pad to a multiple of ``n`` and reshape into code blocks."""
    pad = (-bits.size) % n
    if pad:
        bits = np.concatenate([bits, np.zeros(pad, dtype=np.uint8)])
    return bits.reshape(-1, n), pad


def reconcile_helper(q_b: QuantResult, code: CodeConfig,
                     quant: QuantConfig) -> HelperData:
    """``W <- ReconcileHelper(Y_B)`` (gNB side, Step 3)."""
    keep = q_b.reliability >= quant.guard_band
    if not keep.any():                      # degenerate link: keep everything
        keep = np.ones_like(keep, dtype=bool)
    b = quant.bits_per_sample
    z_b = q_b.bits.reshape(-1, b)[keep].ravel()
    c: BCH = get_bch(code.m, code.t)
    blocks, _ = _blocks(z_b, c.n)
    syn = np.concatenate([c.sketch(blk) for blk in blocks])
    return HelperData(code.m, code.t, b, int(q_b.levels.size),
                      bits_to_bytes(keep.astype(np.uint8)), int(z_b.size),
                      int(blocks.shape[0]), bits_to_bytes(syn))


@dataclass
class ReconcileResult:
    bits: np.ndarray
    levels: np.ndarray
    ok: bool
    corrected: int
    failed_blocks: int


def reconcile(q_u: QuantResult, W: HelperData) -> ReconcileResult:
    """``Z_U <- Reconcile(Quantize(Y_U), W)`` (UE side, Step 4)."""
    c: BCH = get_bch(W.m, W.t)
    try:
        bits_u, levels_u = W.select(q_u)
    except ValueError:
        return ReconcileResult(np.zeros(0, dtype=np.uint8),
                               np.zeros(0, dtype=np.int64), False, 0, W.n_blocks)
    if bits_u.size != W.n_bits:
        return ReconcileResult(bits_u, levels_u, False, 0, W.n_blocks)
    blocks, pad = _blocks(bits_u, c.n)
    syn_b = bytes_to_bits(W.syndrome, W.n_blocks * c.n_k).reshape(-1, c.n_k)
    out, corrected, failed = [], 0, 0
    for i, blk in enumerate(blocks):
        diff = c.sketch(blk) ^ syn_b[i]
        err = c.decode_syndrome(diff)
        if err is None:
            failed += 1
            out.append(blk)                 # leave raw; the gate will reject
        else:
            corrected += int(err.sum())
            out.append(blk ^ err)
    fixed = np.concatenate(out)
    if pad:
        fixed = fixed[:-pad]
    return ReconcileResult(fixed, levels_u, failed == 0, corrected, failed)


def confirm_tag(r: bytes, bits: np.ndarray) -> bytes:
    """``v = H_conf(r || Z)`` -- reconciliation verification value (Step 4).

    ``r`` is a fresh gNB-chosen challenge, so ``v_B`` is not replayable and
    is unlinkable across sessions.
    """
    return H("H_conf", r, bits_to_bytes(np.asarray(bits, dtype=np.uint8)),
             int(bits.size))
