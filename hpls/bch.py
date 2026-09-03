"""Binary BCH codes over GF(2^m) -- the engine of the secure sketch.

Only the *syndrome* side of the code is needed:

    sketch(z)          = z(x) mod g(x)                (n-k bits, public)
    recover(z', W)     = z' XOR decode(z'(x) mod g(x) XOR W)

Because ``e = z XOR z'`` satisfies ``e(alpha^j) = (z'(x) mod g XOR W)(alpha^j)``
for every root ``alpha^j`` of ``g``, the remainder difference is a valid BCH
syndrome for the error pattern, which is then decoded with Berlekamp-Massey
plus a Chien search.  This is the standard code-offset/syndrome secure sketch
of Dodis-Ostrovsky-Reyzin-Smith; its entropy loss is exactly ``n-k`` bits.
"""

from __future__ import annotations

from functools import lru_cache
from typing import List, Optional, Tuple

import numpy as np

# primitive polynomials for GF(2^m), m = 3..10
PRIM_POLY = {
    3: 0b1011,
    4: 0b10011,
    5: 0b100101,
    6: 0b1000011,
    7: 0b10001001,
    8: 0b100011101,
    9: 0b1000010001,
    10: 0b10000001001,
}


class GF2m:
    """Exponential/logarithm tables for GF(2^m)."""

    def __init__(self, m: int) -> None:
        if m not in PRIM_POLY:
            raise ValueError(f"unsupported m={m}")
        self.m = m
        self.n = (1 << m) - 1
        poly = PRIM_POLY[m]
        exp = [0] * (2 * self.n + 1)
        log = [0] * (self.n + 1)
        x = 1
        for i in range(self.n):
            exp[i] = x
            log[x] = i
            x <<= 1
            if x & (1 << m):
                x ^= poly
        for i in range(self.n, 2 * self.n + 1):
            exp[i] = exp[i - self.n]
        self.exp, self.log = exp, log

    def mul(self, a: int, b: int) -> int:
        if a == 0 or b == 0:
            return 0
        return self.exp[(self.log[a] + self.log[b]) % self.n]

    def div(self, a: int, b: int) -> int:
        if b == 0:
            raise ZeroDivisionError
        if a == 0:
            return 0
        return self.exp[(self.log[a] - self.log[b]) % self.n]

    def inv(self, a: int) -> int:
        return self.exp[(-self.log[a]) % self.n]

    def alpha(self, i: int) -> int:
        return self.exp[i % self.n]


def _gf2_polymul(a: int, b: int) -> int:
    """Multiply two GF(2) polynomials given as bit masks."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        b >>= 1
    return r


def _gf2_polymod(a: int, g: int) -> int:
    dg = g.bit_length() - 1
    while a.bit_length() - 1 >= dg and a:
        a ^= g << (a.bit_length() - 1 - dg)
    return a


class BCH:
    """A binary BCH code of length ``n = 2^m - 1`` designed for ``t`` errors."""

    def __init__(self, m: int, t: int) -> None:
        self.gf = GF2m(m)
        self.m, self.t = m, t
        self.n = self.gf.n
        self.g = self._generator()
        self.n_k = self.g.bit_length() - 1     # deg g == number of parity bits
        self.k = self.n - self.n_k
        if self.k <= 0:
            raise ValueError(f"BCH(m={m}, t={t}) has no information bits")

    # -- construction ------------------------------------------------------

    def _minimal_poly(self, i: int) -> int:
        """Minimal polynomial of ``alpha^i`` as a GF(2) bit mask."""
        gf = self.gf
        coset, j = [], i % gf.n
        while True:
            coset.append(j)
            j = (2 * j) % gf.n
            if j == i % gf.n:
                break
        # prod (x + alpha^j) evaluated in GF(2^m); coefficients land in GF(2)
        poly = [1]
        for j in coset:
            aj = gf.alpha(j)
            new = [0] * (len(poly) + 1)
            for d, c in enumerate(poly):
                new[d] ^= gf.mul(c, aj)      # c * alpha^j
                new[d + 1] ^= c              # c * x
            poly = new
        mask = 0
        for d, c in enumerate(poly):
            if c not in (0, 1):
                raise AssertionError("minimal polynomial not over GF(2)")
            if c:
                mask |= 1 << d
        return mask

    def _generator(self) -> int:
        g, seen = 1, set()
        for i in range(1, 2 * self.t + 1, 2):
            j, coset = i % self.gf.n, set()
            while j not in coset:
                coset.add(j)
                j = (2 * j) % self.gf.n
            key = min(coset)
            if key in seen:
                continue
            seen.add(key)
            g = _gf2_polymul(g, self._minimal_poly(i))
        return g

    # -- sketch / decode ---------------------------------------------------

    @staticmethod
    def _bits_to_int(bits: np.ndarray) -> int:
        v = 0
        for i, b in enumerate(np.asarray(bits, dtype=np.uint8)):
            if b:
                v |= 1 << i          # bit i is the coefficient of x^i
        return v

    @staticmethod
    def _int_to_bits(v: int, length: int) -> np.ndarray:
        return np.array([(v >> i) & 1 for i in range(length)], dtype=np.uint8)

    def sketch(self, bits: np.ndarray) -> np.ndarray:
        """``n-k``-bit syndrome (remainder) of one length-``n`` block."""
        if len(bits) != self.n:
            raise ValueError(f"block must be {self.n} bits, got {len(bits)}")
        r = _gf2_polymod(self._bits_to_int(bits), self.g)
        return self._int_to_bits(r, self.n_k)

    def _syndromes(self, rem: int) -> List[int]:
        gf = self.gf
        out = []
        for j in range(1, 2 * self.t + 1):
            aj, acc, v = gf.alpha(j), 0, rem
            # Horner over the remainder polynomial
            deg = rem.bit_length() - 1
            for d in range(deg, -1, -1):
                acc = gf.mul(acc, aj) ^ ((v >> d) & 1)
            out.append(acc)
        return out

    def _berlekamp_massey(self, S: List[int]) -> List[int]:
        gf = self.gf
        C, B = [1], [1]
        L, mm, b = 0, 1, 1
        for r in range(len(S)):
            d = S[r]
            for i in range(1, L + 1):
                if i < len(C):
                    d ^= gf.mul(C[i], S[r - i])
            if d == 0:
                mm += 1
                continue
            coef = gf.div(d, b)
            T = list(C)
            if len(C) < len(B) + mm:
                C += [0] * (len(B) + mm - len(C))
            for i, bi in enumerate(B):
                C[i + mm] ^= gf.mul(coef, bi)
            if 2 * L <= r:
                L, B, b, mm = r + 1 - L, T, d, 1
            else:
                mm += 1
        return C[:L + 1] if L + 1 <= len(C) else C

    def decode_syndrome(self, syn_bits: np.ndarray) -> Optional[np.ndarray]:
        """Recover the error pattern from a remainder-syndrome difference.

        Returns the length-``n`` error vector, or ``None`` on decoding failure
        (more than ``t`` errors).
        """
        rem = self._bits_to_int(syn_bits)
        if rem == 0:
            return np.zeros(self.n, dtype=np.uint8)
        S = self._syndromes(rem)
        if all(s == 0 for s in S):
            return None                      # non-zero remainder, zero syndrome
        sigma = self._berlekamp_massey(S)
        deg = len(sigma) - 1
        if deg == 0 or deg > self.t:
            return None
        gf = self.gf
        err = np.zeros(self.n, dtype=np.uint8)
        found = 0
        for p in range(self.n):
            # evaluate sigma(alpha^-p)
            x, acc = gf.alpha(-p), 0
            for c in reversed(sigma):
                acc = gf.mul(acc, x) ^ c
            if acc == 0:
                err[p] = 1
                found += 1
        if found != deg:
            return None
        # verify: the recovered pattern must reproduce the syndrome
        if self._bits_to_int(self.sketch(err)) != rem:
            return None
        return err


@lru_cache(maxsize=32)
def get_bch(m: int, t: int) -> BCH:
    return BCH(m, t)


def code_rate_table(m: int, t_values: Tuple[int, ...]) -> List[dict]:
    out = []
    for t in t_values:
        try:
            c = get_bch(m, t)
        except ValueError:
            continue
        out.append({"n": c.n, "k": c.k, "t": t, "leak_bits": c.n_k,
                    "rate": c.k / c.n,
                    "correctable_ber": t / c.n})
    return out
