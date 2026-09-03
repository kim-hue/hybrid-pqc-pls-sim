"""Channel quantiser ``Quantize(Y)``.

Multi-bit CQG quantiser:

1.  block-wise z-score normalisation -- removes the large-scale fading and,
    crucially, the *static* transceiver gain mismatch between the two nodes,
    which is what makes the two sides' quantiser inputs comparable without
    exchanging any calibration data;
2.  equiprobable thresholds taken from the standard normal quantile function
    (fixed constants, identical on both sides, nothing to exchange);
3.  Gray coding, so a single-level slip costs one bit instead of ``b`` bits.

The per-sample distance to the nearest threshold is kept locally as a
*reliability* value.  It is never transmitted (transmitting it is the classic
guard-band leak); it is used only inside ``PHYGate`` as a local channel-quality
statistic.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import erf, sqrt
from typing import List

import numpy as np

from .config import QuantConfig


def _ppf(p: float) -> float:
    """Inverse standard normal CDF (Acklam's rational approximation)."""
    a = [-3.969683028665376e+01, 2.209460984245205e+02, -2.759285104469687e+02,
         1.383577518672690e+02, -3.066479806614716e+01, 2.506628277459239e+00]
    b = [-5.447609879822406e+01, 1.615858368580409e+02, -1.556989798598866e+02,
         6.680131188771972e+01, -1.328068155288572e+01]
    c = [-7.784894002430293e-03, -3.223964580411365e-01, -2.400758277161838e+00,
         -2.549732539343734e+00, 4.374664141464968e+00, 2.938163982698783e+00]
    d = [7.784695709041462e-03, 3.224671290700398e-01, 2.445134137142996e+00,
         3.754408661907416e+00]
    plow, phigh = 0.02425, 1 - 0.02425
    if p < plow:
        q = sqrt(-2 * np.log(p))
        return (((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / \
               ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)
    if p > phigh:
        q = sqrt(-2 * np.log(1 - p))
        return -(((((c[0]*q+c[1])*q+c[2])*q+c[3])*q+c[4])*q+c[5]) / \
                ((((d[0]*q+d[1])*q+d[2])*q+d[3])*q+1)
    q = p - 0.5
    r = q * q
    return (((((a[0]*r+a[1])*r+a[2])*r+a[3])*r+a[4])*r+a[5])*q / \
           (((((b[0]*r+b[1])*r+b[2])*r+b[3])*r+b[4])*r+1)


def thresholds(bits_per_sample: int) -> np.ndarray:
    """Equiprobable thresholds for ``2^b`` levels of a standard normal."""
    n_lev = 1 << bits_per_sample
    return np.array([_ppf(i / n_lev) for i in range(1, n_lev)])


def gray_encode(level: np.ndarray) -> np.ndarray:
    return level ^ (level >> 1)


@dataclass
class QuantResult:
    bits: np.ndarray          # uint8, length n_samples * bits_per_sample
    levels: np.ndarray        # int, length n_samples
    reliability: np.ndarray   # float, distance to nearest threshold (std units)
    normalised: np.ndarray

    @property
    def n_bits(self) -> int:
        return int(self.bits.size)


def quantize(feat: np.ndarray, cfg: QuantConfig) -> QuantResult:
    y = np.asarray(feat, dtype=float).ravel()
    bs = cfg.block_size if cfg.block_size and cfg.block_size > 1 else y.size
    z = np.empty_like(y)
    for s in range(0, y.size, bs):
        blk = y[s:s + bs]
        mu = blk.mean()
        sd = blk.std()
        z[s:s + bs] = (blk - mu) / (sd if sd > 1e-12 else 1.0)

    th = thresholds(cfg.bits_per_sample)
    levels = np.searchsorted(th, z).astype(np.int64)
    rel = np.min(np.abs(z[:, None] - th[None, :]), axis=1)

    gray = gray_encode(levels)
    b = cfg.bits_per_sample
    bits = ((gray[:, None] >> np.arange(b - 1, -1, -1)[None, :]) & 1).astype(np.uint8)
    return QuantResult(bits=bits.ravel(), levels=levels, reliability=rel,
                       normalised=z)


def bit_disagreement(a: np.ndarray, b: np.ndarray) -> float:
    n = min(a.size, b.size)
    if n == 0:
        return float("nan")
    return float(np.mean(a[:n] != b[:n]))


def bits_to_bytes(bits: np.ndarray) -> bytes:
    return np.packbits(np.asarray(bits, dtype=np.uint8)).tobytes()


def bytes_to_bits(data: bytes, n_bits: int) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))[:n_bits]
