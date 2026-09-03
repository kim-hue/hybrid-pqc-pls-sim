"""Min-entropy estimation for the physical-layer source.

Two NIST SP 800-90B style estimators are implemented and the *minimum* of
the two is used, which is the conservative choice mandated by 90B:

* **MCV** (most-common-value) with a one-sided 99 % upper confidence bound on
  ``p_max`` -- an i.i.d. estimator;
* **Markov** (first order) -- upper-bounds the probability of the most likely
  length-``L`` path through the estimated transition matrix.  This is the
  estimator that actually matters here, because neighbouring channel samples
  are correlated whenever the pilot spacing is below the coherence bandwidth
  or the probe interval is below the coherence time.

Shannon entropy and collision (Renyi-2) entropy are reported as diagnostics
only; they are *not* used in the key-length budget.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from math import log2, sqrt
from typing import Dict

import numpy as np

Z_99 = 2.5758293035489004        # one-sided 99 % normal quantile


@dataclass
class EntropyReport:
    n_symbols: int
    alphabet: int
    h_mcv: float                 # bits / symbol
    h_markov: float              # bits / symbol
    h_shannon: float             # bits / symbol (diagnostic)
    h_collision: float           # bits / symbol (diagnostic)
    h_min_per_symbol: float      # min(h_mcv, h_markov)
    h_min_total: float           # bits over the whole string
    lag1_corr: float

    def as_dict(self) -> Dict[str, float]:
        return asdict(self)


def _hist(sym: np.ndarray, alphabet: int) -> np.ndarray:
    counts = np.bincount(sym, minlength=alphabet).astype(float)
    return counts / max(counts.sum(), 1.0)


def min_entropy_mcv(sym: np.ndarray, alphabet: int) -> float:
    n = sym.size
    if n == 0:
        return 0.0
    p_hat = float(_hist(sym, alphabet).max())
    p_u = min(1.0, p_hat + Z_99 * sqrt(max(p_hat * (1 - p_hat), 0.0) / max(n - 1, 1)))
    p_u = max(p_u, 1.0 / alphabet)
    return -log2(p_u)


def min_entropy_markov(sym: np.ndarray, alphabet: int, path_len: int = 128) -> float:
    """90B first-order Markov estimate, generalised to a k-ary alphabet."""
    n = sym.size
    if n < 2:
        return 0.0
    p0 = _hist(sym, alphabet)
    trans = np.zeros((alphabet, alphabet))
    np.add.at(trans, (sym[:-1], sym[1:]), 1.0)
    row = trans.sum(axis=1, keepdims=True)
    # 90B uses the biased-high estimate; empty rows fall back to uniform
    with np.errstate(invalid="ignore", divide="ignore"):
        P = np.where(row > 0, trans / np.maximum(row, 1.0), 1.0 / alphabet)
    # most likely path of length `path_len` (Viterbi on log-probabilities)
    eps = 1e-300
    logp = np.log2(np.maximum(P, eps))
    v = np.log2(np.maximum(p0, eps))
    for _ in range(path_len - 1):
        v = (v[:, None] + logp).max(axis=0)
    p_max_log = float(v.max())
    h = -p_max_log / path_len
    return max(0.0, min(h, log2(alphabet)))


def shannon_entropy(sym: np.ndarray, alphabet: int) -> float:
    p = _hist(sym, alphabet)
    p = p[p > 0]
    return float(-(p * np.log2(p)).sum())


def collision_entropy(sym: np.ndarray, alphabet: int) -> float:
    p = _hist(sym, alphabet)
    return float(-log2(max((p ** 2).sum(), 1e-300)))


def analyse(sym: np.ndarray, alphabet: int) -> EntropyReport:
    """Full entropy report for a symbol sequence (e.g. quantiser levels)."""
    sym = np.asarray(sym, dtype=np.int64).ravel()
    h_mcv = min_entropy_mcv(sym, alphabet)
    h_mk = min_entropy_markov(sym, alphabet)
    h_min = min(h_mcv, h_mk)
    if sym.size > 2 and sym.std() > 0:
        lag1 = float(np.corrcoef(sym[:-1], sym[1:])[0, 1])
    else:
        lag1 = 0.0
    return EntropyReport(
        n_symbols=int(sym.size), alphabet=int(alphabet),
        h_mcv=h_mcv, h_markov=h_mk,
        h_shannon=shannon_entropy(sym, alphabet),
        h_collision=collision_entropy(sym, alphabet),
        h_min_per_symbol=h_min, h_min_total=h_min * sym.size,
        lag1_corr=lag1,
    )
