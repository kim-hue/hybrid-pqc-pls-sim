"""Unit tests for the hybrid PQC-PLS simulator.

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import pathlib
import sys
import unittest

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from hpls.bch import get_bch
from hpls.channel import RadioWorld
from hpls.config import DEFAULT
from hpls.entropy import analyse, min_entropy_markov, min_entropy_mcv
from hpls.gate import privacy_amplify
from hpls.messages import M1
from hpls.metrics import phy_trial
from hpls.primitives import (AEAD, CA, H, KEM, ReplayCache, Sig, SlidingWindow,
                             enc, hkdf_expand, hkdf_extract, mac, nonce_xor,
                             rand_bytes, verify_mac)
from hpls.probing import ProbeContext, estimate
from hpls.protocol import PKI, SessionKeys, run_session
from hpls.quantize import bit_disagreement, quantize, thresholds
from hpls.reconcile import confirm_tag, reconcile, reconcile_helper

PKI_SINGLETON = None


def pki():
    global PKI_SINGLETON
    if PKI_SINGLETON is None:
        PKI_SINGLETON = PKI.build()
    return PKI_SINGLETON


class TestEncoding(unittest.TestCase):
    def test_injective_across_field_boundaries(self):
        # raw concatenation would collide; the TLV encoding must not
        self.assertNotEqual(enc(b"ab", b"c"), enc(b"a", b"bc"))
        self.assertNotEqual(H(b"ab", b"c"), H(b"a", b"bc"))

    def test_type_separation(self):
        self.assertNotEqual(enc(1), enc("1"))
        self.assertNotEqual(enc(None), enc(b""))
        self.assertNotEqual(enc(True), enc(1))

    def test_deterministic(self):
        m = M1(b"s" * 16, b"n" * 32, b"p" * 1184, ("a", "b"), "sn")
        self.assertEqual(m.to_bytes_msg(), m.to_bytes_msg())


class TestPrimitives(unittest.TestCase):
    def test_kem_roundtrip(self):
        pk, sk = KEM.keygen()
        ct, ss = KEM.encaps(pk)
        self.assertEqual(KEM.decaps(sk, ct), ss)
        self.assertEqual(len(ss), 32)

    def test_sig_roundtrip_and_rejection(self):
        pk, sk = Sig.keygen()
        s = Sig.sign(sk, b"msg")
        self.assertTrue(Sig.verify(pk, b"msg", s))
        self.assertFalse(Sig.verify(pk, b"msg!", s))

    def test_hkdf_rfc5869_vector(self):
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        prk = hkdf_extract(salt, ikm)
        self.assertEqual(prk.hex(),
                         "077709362c2e32df0ddc3f0dc47bba63"
                         "90b6c73bb50f9c3122ec844ad7c2b3e5")
        okm = hkdf_expand(prk, info, 42)
        self.assertEqual(okm.hex(),
                         "3cb25f25faacd57a90434f64d0362f2a"
                         "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")

    def test_mac_and_aead(self):
        k = rand_bytes(32)
        t = mac(k, "UE-GATE", b"x")
        self.assertTrue(verify_mac(k, t, "UE-GATE", b"x"))
        self.assertFalse(verify_mac(k, t, "GNB-GATE", b"x"))
        n = rand_bytes(12)
        ct = AEAD.seal(k, n, (b"sid", 0), b"data")
        self.assertEqual(AEAD.open(k, n, (b"sid", 0), ct), b"data")
        self.assertIsNone(AEAD.open(k, n, (b"sid", 1), ct))

    def test_nonce_xor(self):
        base = bytes(range(12))
        self.assertEqual(nonce_xor(base, 0), base)
        self.assertNotEqual(nonce_xor(base, 1), base)

    def test_certificate_chain(self):
        ca, rogue = CA("Real"), CA("Rogue")
        pk, _ = Sig.keygen()
        cert = ca.issue("ue", pk)
        self.assertTrue(ca.verify(cert))
        self.assertFalse(rogue.verify(cert))
        cert.pk_sig = b"\x00" * len(cert.pk_sig)
        self.assertFalse(ca.verify(cert))

    def test_replay_cache_and_window(self):
        rc = ReplayCache()
        self.assertTrue(rc.check_and_insert(b"sid", b"n"))
        self.assertFalse(rc.check_and_insert(b"sid", b"n"))
        w = SlidingWindow(8)
        self.assertTrue(w.check_and_insert(0))
        self.assertFalse(w.check_and_insert(0))
        self.assertTrue(w.check_and_insert(5))
        self.assertTrue(w.check_and_insert(3))
        self.assertTrue(w.check_and_insert(100))
        self.assertFalse(w.check_and_insert(5))       # outside the window now


class TestBCH(unittest.TestCase):
    def test_known_parameters(self):
        for m, t, k in [(8, 4, 223), (8, 8, 191), (8, 12, 163), (8, 16, 131),
                        (7, 4, 99), (6, 3, 45)]:
            c = get_bch(m, t)
            self.assertEqual(c.k, k, f"BCH(m={m}, t={t})")

    def test_sketch_corrects_up_to_t(self):
        c = get_bch(8, 8)
        rng = np.random.default_rng(7)
        for _ in range(20):
            z = rng.integers(0, 2, c.n).astype(np.uint8)
            W = c.sketch(z)
            for n_err in (0, 1, 4, 8):
                e = np.zeros(c.n, dtype=np.uint8)
                if n_err:
                    e[rng.choice(c.n, n_err, replace=False)] = 1
                zp = z ^ e
                err = c.decode_syndrome(c.sketch(zp) ^ W)
                self.assertIsNotNone(err)
                np.testing.assert_array_equal(zp ^ err, z)

    def test_decoder_fails_loudly_beyond_t(self):
        c = get_bch(8, 4)
        rng = np.random.default_rng(11)
        failures = 0
        for _ in range(20):
            z = rng.integers(0, 2, c.n).astype(np.uint8)
            e = np.zeros(c.n, dtype=np.uint8)
            e[rng.choice(c.n, 30, replace=False)] = 1
            err = c.decode_syndrome(c.sketch(z ^ e) ^ c.sketch(z))
            if err is None or not np.array_equal((z ^ e) ^ err, z):
                failures += 1
        self.assertEqual(failures, 20)     # never silently "corrects"


class TestQuantiser(unittest.TestCase):
    def test_thresholds_equiprobable(self):
        th = thresholds(2)
        self.assertEqual(len(th), 3)
        self.assertAlmostEqual(th[1], 0.0, places=6)

    def test_identical_input_gives_identical_bits(self):
        rng = np.random.default_rng(3)
        y = rng.normal(size=500)
        a = quantize(y, DEFAULT.quant)
        b = quantize(y, DEFAULT.quant)
        np.testing.assert_array_equal(a.bits, b.bits)
        self.assertEqual(a.bits.size, 500 * DEFAULT.quant.bits_per_sample)

    def test_gain_offset_is_removed_by_normalisation(self):
        rng = np.random.default_rng(4)
        y = rng.normal(size=400)
        a = quantize(y, DEFAULT.quant)
        b = quantize(3.0 * y + 12.0, DEFAULT.quant)   # gain + offset
        np.testing.assert_array_equal(a.bits, b.bits)

    def test_gray_coding_limits_bit_errors(self):
        cfg2 = DEFAULT.with_quant(bits_per_sample=2).quant
        y = np.linspace(-3, 3, 4096)
        q = quantize(y, cfg2)
        b = q.bits.reshape(-1, 2)
        # adjacent levels differ in exactly one bit under Gray coding
        changes = np.where(np.diff(q.levels) != 0)[0]
        for i in changes:
            self.assertEqual(int(np.sum(b[i] != b[i + 1])), 1)


class TestReconciliation(unittest.TestCase):
    def test_helper_data_recovers_gnb_string(self):
        cfg = DEFAULT
        world = RadioWorld(cfg.phy, seed=99)
        ctx = ProbeContext.derive(b"s" * 16, b"n" * 32, cfg.phy)
        q_u = quantize(estimate(world, "U", ctx).feat, cfg.quant)
        q_b = quantize(estimate(world, "B", ctx).feat, cfg.quant)
        W = reconcile_helper(q_b, cfg.code, cfg.quant)
        z_b, _ = W.select(q_b)
        rec = reconcile(q_u, W)
        self.assertTrue(rec.ok)
        np.testing.assert_array_equal(rec.bits, z_b)
        self.assertEqual(W.leak_bits, W.n_blocks * get_bch(8, cfg.code.t).n_k)

    def test_corrupt_helper_data_never_steers_the_ue_silently(self):
        """A corrupted syndrome must fail loudly, not redirect the UE.

        Syndrome decoding can only apply an XOR correction, so a corrupted
        ``W`` either fails to decode (the block is left untouched) or is
        caught by the reconciliation verification ``r_U``.  What must never
        happen is a silent agreement on a string other than ``Z_B``.
        """
        cfg = DEFAULT
        world = RadioWorld(cfg.phy, seed=100)
        ctx = ProbeContext.derive(b"s" * 16, b"n" * 32, cfg.phy)
        q_u = quantize(estimate(world, "U", ctx).feat, cfg.quant)
        q_b = quantize(estimate(world, "B", ctx).feat, cfg.quant)
        W = reconcile_helper(q_b, cfg.code, cfg.quant)
        z_b, _ = W.select(q_b)
        r = rand_bytes(32)
        v_b = confirm_tag(r, z_b)
        for n_flips in (1, 8, 80, 200):
            bad = W.with_syndrome_flips(n_flips, np.random.default_rng(n_flips))
            rec = reconcile(q_u, bad)
            if confirm_tag(r, rec.bits) == v_b:
                # r_U = 1 is only allowed when the strings really do agree
                np.testing.assert_array_equal(rec.bits, z_b)
            else:
                self.assertFalse(np.array_equal(rec.bits, z_b))

    def test_helper_data_from_another_campaign_is_rejected(self):
        cfg = DEFAULT
        w1 = RadioWorld(cfg.phy, seed=101)
        ctx = ProbeContext.derive(b"s" * 16, b"n" * 32, cfg.phy)
        q_u = quantize(estimate(w1, "U", ctx).feat, cfg.phy and cfg.quant)
        smaller = cfg.with_phy(n_probe_rounds=8)
        ctx2 = ProbeContext.derive(b"t" * 16, b"m" * 32, smaller.phy)
        q_b2 = quantize(estimate(RadioWorld(smaller.phy, seed=102), "B",
                                 ctx2).feat, smaller.quant)
        W2 = reconcile_helper(q_b2, smaller.code, smaller.quant)
        rec = reconcile(q_u, W2)
        self.assertFalse(rec.ok)


class TestEntropy(unittest.TestCase):
    def test_uniform_bits_have_full_entropy(self):
        rng = np.random.default_rng(5)
        s = rng.integers(0, 2, 20000)
        self.assertGreater(min_entropy_mcv(s, 2), 0.97)
        self.assertGreater(min_entropy_markov(s, 2), 0.95)

    def test_biased_source_is_penalised(self):
        rng = np.random.default_rng(6)
        s = (rng.random(20000) < 0.9).astype(int)
        self.assertLess(min_entropy_mcv(s, 2), 0.2)

    def test_correlated_source_is_caught_only_by_markov(self):
        rng = np.random.default_rng(8)
        s = np.zeros(20000, dtype=int)
        for i in range(1, s.size):                   # sticky chain
            s[i] = s[i - 1] if rng.random() < 0.9 else 1 - s[i - 1]
        rep = analyse(s, 2)
        self.assertGreater(rep.h_mcv, 0.9)           # looks unbiased
        self.assertLess(rep.h_markov, 0.2)           # but is predictable
        self.assertEqual(rep.h_min_per_symbol, rep.h_markov)


class TestPrivacyAmplification(unittest.TestCase):
    def test_length_and_determinism(self):
        z = np.random.default_rng(9).integers(0, 2, 800).astype(np.uint8)
        k = privacy_amplify(z, b"t2" * 16, 128)
        self.assertEqual(len(k), 16)
        self.assertEqual(k, privacy_amplify(z, b"t2" * 16, 128))

    def test_seed_and_input_sensitivity(self):
        z = np.random.default_rng(10).integers(0, 2, 800).astype(np.uint8)
        k = privacy_amplify(z, b"t2" * 16, 128)
        self.assertNotEqual(k, privacy_amplify(z, b"t3" * 16, 128))
        z2 = z.copy()
        z2[123] ^= 1
        self.assertNotEqual(k, privacy_amplify(z2, b"t2" * 16, 128))

    def test_output_is_balanced(self):
        rng = np.random.default_rng(12)
        bits = []
        for i in range(40):
            z = rng.integers(0, 2, 800).astype(np.uint8)
            k = privacy_amplify(z, H("t2", i), 128)
            bits.extend(np.unpackbits(np.frombuffer(k, dtype=np.uint8)))
        self.assertAlmostEqual(float(np.mean(bits)), 0.5, delta=0.05)


class TestKeySchedule(unittest.TestCase):
    def test_epsilon_case_is_unambiguous(self):
        t_h = H("t_h")
        k_pqc = rand_bytes(32)
        a = SessionKeys.derive(t_h, k_pqc, b"")
        b = SessionKeys.derive(t_h, k_pqc, bytes(16))
        self.assertNotEqual(a.k_u2b, b.k_u2b)

    def test_length_prefixing_prevents_sliding(self):
        t_h = H("t_h")
        a = SessionKeys.derive(t_h, b"AB", b"C")
        b = SessionKeys.derive(t_h, b"A", b"BC")
        self.assertNotEqual(a.k_u2b, b.k_u2b)

    def test_all_outputs_are_distinct(self):
        k = SessionKeys.derive(H("t"), rand_bytes(32), rand_bytes(16))
        self.assertEqual(len({k.k_u2b, k.k_b2u, k.k_cf_u, k.k_cf_b}), 4)
        self.assertNotEqual(k.n_u0, k.n_b0)

    def test_every_input_matters(self):
        t_h, p, y = H("t"), rand_bytes(32), rand_bytes(16)
        base = SessionKeys.derive(t_h, p, y).k_u2b
        self.assertNotEqual(base, SessionKeys.derive(H("t2"), p, y).k_u2b)
        self.assertNotEqual(base, SessionKeys.derive(t_h, rand_bytes(32), y).k_u2b)
        self.assertNotEqual(base, SessionKeys.derive(t_h, p, rand_bytes(16)).k_u2b)


class TestProbing(unittest.TestCase):
    def test_context_is_deterministic_and_session_bound(self):
        a = ProbeContext.derive(b"s" * 16, b"n" * 32, DEFAULT.phy)
        b = ProbeContext.derive(b"s" * 16, b"n" * 32, DEFAULT.phy)
        c = ProbeContext.derive(b"s" * 16, b"m" * 32, DEFAULT.phy)
        self.assertEqual(a.h_probe(), b.h_probe())
        self.assertNotEqual(a.h_probe(), c.h_probe())
        self.assertNotEqual(a.subcarriers, c.subcarriers)

    def test_tdd_gap_offsets_the_ue_soundings(self):
        ctx = ProbeContext.derive(b"s" * 16, b"n" * 32, DEFAULT.phy)
        self.assertTrue(np.all(ctx.times_s("U") > ctx.times_s("B")))


class TestProtocol(unittest.TestCase):
    def test_healthy_session(self):
        r = run_session(DEFAULT, pki=pki(), seed=555)
        self.assertTrue(r.established)
        self.assertTrue(r.k_pqc_match)
        self.assertTrue(r.keys_match)
        self.assertTrue(r.k_phy_match)

    def test_degraded_session_falls_back(self):
        cfg = DEFAULT.with_phy(snr_db=-10.0, n_avg_symbols=1)
        r = run_session(cfg, pki=pki(), seed=556)
        self.assertTrue(r.established)
        self.assertFalse(r.g_phy)
        self.assertEqual(r.k_phy_bits, 0)
        self.assertTrue(r.keys_match)

    def test_phy_trial_matches_session_decision(self):
        m = phy_trial(DEFAULT, seed=557)
        self.assertIn(m["g_phy"], (0.0, 1.0))
        if m["g_phy"]:
            self.assertEqual(m["key_agree"], 1.0)
            self.assertEqual(m["kdr_post"], 0.0)


class TestAttackSuite(unittest.TestCase):
    def test_all_attacks_behave_as_required(self):
        from hpls.adversary import ATTACKS
        for fn in ATTACKS:
            res = fn(DEFAULT, pki())
            self.assertTrue(res.ok, f"{res.name}: {res.observed}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
