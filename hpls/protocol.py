"""The hybrid PQC-PLS key-establishment protocol, Steps 1-6 + data plane.

The two state machines (:class:`UE`, :class:`GNB`) implement exactly the
operations of the protocol figures, in the same order, with the same
transcript bindings.  :func:`run_session` drives them and exposes a ``hooks``
dictionary so that an adversary can intercept, modify, drop or replay any
flight (see :mod:`hpls.adversary`).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np

from .channel import RadioWorld
from .config import DEFAULT, ProtocolConfig
from .gate import GateDecision, phy_gate, privacy_amplify
from .messages import (Finished, Flight1, Flight2, Flight3, Flight4, M1, M2,
                       M3, M4, MConf, Record)
from .primitives import (AEAD, CA, Certificate, H, KEM, NONCE_LEN, ReplayCache,
                         Sig, SlidingWindow, enc, hkdf_expand, hkdf_extract,
                         mac, nonce_xor, rand_bytes, verify_mac)
from .probing import Observation, ProbeContext, estimate
from .quantize import QuantResult, bit_disagreement, quantize
from .reconcile import (HelperData, ReconcileResult, confirm_tag, reconcile,
                        reconcile_helper)

DIR_UE = "UE->GNB"
DIR_GNB = "GNB->UE"


class Abort(Exception):
    """Protocol abort carrying the stage and the failing check."""

    def __init__(self, stage: str, reason: str) -> None:
        super().__init__(f"[{stage}] {reason}")
        self.stage, self.reason = stage, reason


# --------------------------------------------------------------------------
# PKI (built once, reused across sessions)
# --------------------------------------------------------------------------


@dataclass
class PKI:
    ca: CA
    cert_u: Certificate
    sk_u: bytes
    cert_b: Certificate
    sk_b: bytes

    @staticmethod
    def build(ue_id: str = "imsi-001010000000001",
              gnb_id: str = "gnb-001010-17") -> "PKI":
        ca = CA()
        pk_u, sk_u = Sig.keygen()
        pk_b, sk_b = Sig.keygen()
        return PKI(ca, ca.issue(ue_id, pk_u), sk_u, ca.issue(gnb_id, pk_b), sk_b)


# --------------------------------------------------------------------------
# key schedule
# --------------------------------------------------------------------------


@dataclass
class SessionKeys:
    k_u2b: bytes
    k_b2u: bytes
    k_cf_u: bytes
    k_cf_b: bytes
    n_u0: bytes
    n_b0: bytes
    prk: bytes

    @staticmethod
    def derive(t_h: bytes, k_pqc: bytes, k_phy: bytes) -> "SessionKeys":
        """Step 5: ``IKM = l_PQC||K_PQC||l_PHY||K_PHY`` then HKDF."""
        ikm = enc(len(k_pqc), k_pqc, len(k_phy), k_phy)
        prk = hkdf_extract(t_h, ikm)
        okm = hkdf_expand(prk, enc("HYBRID-KEYS", t_h), 4 * 32 + 2 * NONCE_LEN)
        parts = [okm[i:i + 32] for i in range(0, 128, 32)]
        n_u0 = okm[128:128 + NONCE_LEN]
        n_b0 = okm[128 + NONCE_LEN:128 + 2 * NONCE_LEN]
        return SessionKeys(parts[0], parts[1], parts[2], parts[3], n_u0, n_b0, prk)


def gate_key(t2: bytes, k_pqc: bytes) -> bytes:
    """``k_gate = HKDF-Expand(HKDF-Extract(T_2, K_PQC), "PHY-GATE")``"""
    return hkdf_expand(hkdf_extract(t2, k_pqc), enc("PHY-GATE"), 32)


# --------------------------------------------------------------------------
# UE state machine
# --------------------------------------------------------------------------


class UE:
    role = "U"

    def __init__(self, cfg: ProtocolConfig, pki: PKI, world: RadioWorld) -> None:
        self.cfg = cfg
        self.pki = pki
        self.world = world
        self.st: Dict[str, Any] = {}

    # -- Step 1 ---------------------------------------------------------
    def step1(self, sid: Optional[bytes] = None) -> Flight1:
        c = self.cfg
        sid = sid if sid is not None else rand_bytes(16)
        n_u = rand_bytes(c.crypto.lambda_bits // 8)
        pk_e, sk_e = KEM.keygen()
        m1 = M1(sid, n_u, pk_e, c.alg_list, c.sn_id)
        sig_u = Sig.sign(self.pki.sk_u, H("m1-tbs", m1.to_bytes_msg()))
        self.st.update(sid=sid, n_u=n_u, pk_e=pk_e, sk_e=sk_e, m1=m1, sig_u=sig_u)
        return Flight1(m1, sig_u, self.pki.cert_u)

    # -- Step 2 ---------------------------------------------------------
    def step2(self) -> ProbeContext:
        ctx = ProbeContext.derive(self.st["sid"], self.st["n_u"], self.cfg.phy)
        y = estimate(self.world, self.role, ctx)
        self.st.update(ctx=ctx, y=y, h_probe=ctx.h_probe())
        return ctx

    # -- Step 3 ---------------------------------------------------------
    def step3(self, f2: Flight2) -> None:
        m2, sig_b, cert_b = f2.m2, f2.sig_b, f2.cert_b
        if not self.pki.ca.verify(cert_b):
            raise Abort("step3", "gNB certificate invalid")
        tbs = H("m2-tbs", self.st["m1"].to_bytes_msg(), self.st["sig_u"],
                m2.to_bytes_msg())
        if not Sig.verify(cert_b.pk_sig, tbs, sig_b):
            raise Abort("step3", "sigma_B verification failed")
        # session-consistency checks that the signature makes meaningful
        if m2.sid != self.st["sid"] or m2.n_u != self.st["n_u"]:
            raise Abort("step3", "session/nonce mismatch in m2")
        if m2.sn_id != self.cfg.sn_id:
            raise Abort("step3", "serving-network mismatch (bidding-down)")
        if m2.alg_sel not in self.cfg.alg_list:
            raise Abort("step3", "selected algorithm not offered (downgrade)")
        if m2.h_probe != self.st["h_probe"]:
            raise Abort("step3", "h_probe mismatch (probing context not bound)")
        k_pqc = KEM.decaps(self.st["sk_e"], m2.c_kem)
        self.st.update(m2=m2, sig_b=sig_b, n_b=m2.n_b, w=m2.w, k_pqc=k_pqc)

    # -- Step 4 ---------------------------------------------------------
    def step4_local(self) -> GateDecision:
        c = self.cfg
        t2 = H("T2", self.st["m1"].to_bytes_msg(), self.st["sig_u"],
               self.st["m2"].to_bytes_msg(), self.st["sig_b"])
        self.st["t2"] = t2
        self.st["k_gate"] = gate_key(t2, self.st["k_pqc"])
        q = quantize(self.st["y"].feat, c.quant)
        g = phy_gate(q, self.st["w"], self.st["y"].snr_db_est,
                     self.st["ctx"].n_rounds, c.quant, c.gate)
        rec = reconcile(q, self.st["w"])
        self.st.update(q=q, gate=g, rec=rec, z=rec.bits)
        return g

    def step4_conf(self, mc: MConf) -> bool:
        """Reconciliation verification: ``r_U = 1[H_conf(r||Z_U) = v_B]``."""
        if mc.sid != self.st["sid"]:
            raise Abort("step4", "sid mismatch in reconciliation verification")
        r_u = confirm_tag(mc.r, self.st["z"]) == mc.v_b
        self.st["r_u"] = bool(r_u)
        self.st["d_u"] = bool(self.st["gate"].accept and r_u)
        return self.st["d_u"]

    def step4_send(self) -> Flight3:
        m3 = M3(self.st["sid"], self.st["d_u"])
        tau3 = mac(self.st["k_gate"], "UE-GATE", self.st["t2"], m3.to_bytes_msg())
        self.st["m3"], self.st["tau3"] = m3, tau3
        return Flight3(m3, tau3)

    def step4_recv(self, f4: Flight4) -> bool:
        m4, tau4 = f4.m4, f4.tau4
        if not verify_mac(self.st["k_gate"], tau4, "GNB-GATE", self.st["t2"],
                          m4.to_bytes_msg()):
            raise Abort("step4", "tau_4 MAC verification failed")
        if m4.sid != self.st["sid"] or m4.d_u != self.st["d_u"]:
            raise Abort("step4", "gate echo mismatch in m4")
        if m4.g_phy != (m4.d_u and m4.d_b):
            raise Abort("step4", "inconsistent joint gate decision")
        g_phy = bool(m4.g_phy)
        self.st.update(m4=m4, tau4=tau4, d_b=m4.d_b, g_phy=g_phy)
        if g_phy:
            k_phy = privacy_amplify(self.st["z"], self.st["t2"],
                                    self.cfg.gate.target_phy_bits)
        else:
            k_phy = b""                       # epsilon
        self.st["k_phy"] = k_phy
        return g_phy

    # -- Step 5 ---------------------------------------------------------
    def step5(self) -> SessionKeys:
        t_h = H("T_H", self.st["m1"].to_bytes_msg(), self.st["sig_u"],
                self.st["m2"].to_bytes_msg(), self.st["sig_b"],
                self.st["m3"].to_bytes_msg(), self.st["tau3"],
                self.st["m4"].to_bytes_msg(), self.st["tau4"])
        keys = SessionKeys.derive(t_h, self.st["k_pqc"], self.st["k_phy"])
        self.st.update(t_h=t_h, keys=keys)
        return keys

    # -- Step 6 ---------------------------------------------------------
    def step6_send(self) -> Finished:
        k = self.st["keys"]
        ad = (self.st["sid"], DIR_UE, 0, self.st["t_h"], self.st["g_phy"])
        ct = AEAD.seal(k.k_cf_u, k.n_u0, ad, b"")
        return Finished(self.st["sid"], ct)

    def step6_recv(self, fin: Finished) -> None:
        k = self.st["keys"]
        ad = (self.st["sid"], DIR_GNB, 0, self.st["t_h"], self.st["g_phy"])
        if AEAD.open(k.k_cf_b, k.n_b0, ad, fin.ct) is None:
            raise Abort("step6", "gNB key confirmation failed")
        self.st["established"] = True


# --------------------------------------------------------------------------
# gNB state machine
# --------------------------------------------------------------------------


class GNB:
    role = "B"

    def __init__(self, cfg: ProtocolConfig, pki: PKI, world: RadioWorld,
                 replay: Optional[ReplayCache] = None) -> None:
        self.cfg = cfg
        self.pki = pki
        self.world = world
        self.replay = replay if replay is not None else ReplayCache()
        self.st: Dict[str, Any] = {}

    # -- Step 1 ---------------------------------------------------------
    def step1(self, f1: Flight1) -> None:
        m1, sig_u, cert_u = f1.m1, f1.sig_u, f1.cert_u
        if not self.pki.ca.verify(cert_u):
            raise Abort("step1", "UE certificate invalid")
        if not Sig.verify(cert_u.pk_sig, H("m1-tbs", m1.to_bytes_msg()), sig_u):
            raise Abort("step1", "sigma_U verification failed")
        if not self.replay.check_and_insert(m1.sid, m1.n_u):
            raise Abort("step1", "ReplayCheck(sid, N_U) failed")
        if m1.sn_id != self.cfg.sn_id:
            raise Abort("step1", "serving-network identity mismatch")
        sel = next((a for a in self.cfg.alg_list if a in m1.alg_list), None)
        if sel is None:
            raise Abort("step1", "no common algorithm")
        self.st.update(m1=m1, sig_u=sig_u, sid=m1.sid, n_u=m1.n_u,
                       pk_e=m1.pk_e, alg_sel=sel)

    # -- Step 2 ---------------------------------------------------------
    def step2(self) -> ProbeContext:
        ctx = ProbeContext.derive(self.st["sid"], self.st["n_u"], self.cfg.phy)
        y = estimate(self.world, self.role, ctx)
        self.st.update(ctx=ctx, y=y, h_probe=ctx.h_probe())
        return ctx

    # -- Step 3 ---------------------------------------------------------
    def step3(self) -> Flight2:
        c = self.cfg
        n_b = rand_bytes(c.crypto.lambda_bits // 8)
        c_kem, k_pqc = KEM.encaps(self.st["pk_e"])
        q = quantize(self.st["y"].feat, c.quant)
        w = reconcile_helper(q, c.code, c.quant)
        z_b, _ = w.select(q)
        m2 = M2(self.st["sid"], self.st["n_u"], n_b, c_kem, w,
                self.st["alg_sel"], c.sn_id, self.st["h_probe"])
        tbs = H("m2-tbs", self.st["m1"].to_bytes_msg(), self.st["sig_u"],
                m2.to_bytes_msg())
        sig_b = Sig.sign(self.pki.sk_b, tbs)
        self.st.update(n_b=n_b, k_pqc=k_pqc, q=q, w=w, m2=m2, sig_b=sig_b,
                       z=z_b)
        return Flight2(m2, sig_b, self.pki.cert_b)

    # -- Step 4 ---------------------------------------------------------
    def step4_local(self) -> Tuple[GateDecision, MConf]:
        c = self.cfg
        t2 = H("T2", self.st["m1"].to_bytes_msg(), self.st["sig_u"],
               self.st["m2"].to_bytes_msg(), self.st["sig_b"])
        self.st["t2"] = t2
        self.st["k_gate"] = gate_key(t2, self.st["k_pqc"])
        g = phy_gate(self.st["q"], self.st["w"], self.st["y"].snr_db_est,
                     self.st["ctx"].n_rounds, c.quant, c.gate)
        r = rand_bytes(c.crypto.lambda_bits // 8)
        v_b = confirm_tag(r, self.st["z"])
        self.st.update(gate=g, d_b=bool(g.accept), r=r, v_b=v_b)
        return g, MConf(self.st["sid"], r, v_b)

    def step4_recv(self, f3: Flight3) -> Flight4:
        m3, tau3 = f3.m3, f3.tau3
        if not verify_mac(self.st["k_gate"], tau3, "UE-GATE", self.st["t2"],
                          m3.to_bytes_msg()):
            raise Abort("step4", "tau_3 MAC verification failed")
        if m3.sid != self.st["sid"]:
            raise Abort("step4", "sid mismatch in m3")
        d_u = bool(m3.d_u)
        g_phy = bool(d_u and self.st["d_b"])
        m4 = M4(self.st["sid"], d_u, self.st["d_b"], g_phy)
        tau4 = mac(self.st["k_gate"], "GNB-GATE", self.st["t2"], m4.to_bytes_msg())
        if g_phy:
            k_phy = privacy_amplify(self.st["z"], self.st["t2"],
                                    self.cfg.gate.target_phy_bits)
        else:
            k_phy = b""
        self.st.update(m3=m3, tau3=tau3, d_u=d_u, g_phy=g_phy, m4=m4,
                       tau4=tau4, k_phy=k_phy)
        return Flight4(m4, tau4)

    # -- Step 5 ---------------------------------------------------------
    def step5(self) -> SessionKeys:
        t_h = H("T_H", self.st["m1"].to_bytes_msg(), self.st["sig_u"],
                self.st["m2"].to_bytes_msg(), self.st["sig_b"],
                self.st["m3"].to_bytes_msg(), self.st["tau3"],
                self.st["m4"].to_bytes_msg(), self.st["tau4"])
        keys = SessionKeys.derive(t_h, self.st["k_pqc"], self.st["k_phy"])
        self.st.update(t_h=t_h, keys=keys)
        return keys

    # -- Step 6 ---------------------------------------------------------
    def step6_recv(self, fin: Finished) -> None:
        k = self.st["keys"]
        ad = (self.st["sid"], DIR_UE, 0, self.st["t_h"], self.st["g_phy"])
        if AEAD.open(k.k_cf_u, k.n_u0, ad, fin.ct) is None:
            raise Abort("step6", "UE key confirmation failed")

    def step6_send(self) -> Finished:
        k = self.st["keys"]
        ad = (self.st["sid"], DIR_GNB, 0, self.st["t_h"], self.st["g_phy"])
        ct = AEAD.seal(k.k_cf_b, k.n_b0, ad, b"")
        self.st["established"] = True
        return Finished(self.st["sid"], ct)


# --------------------------------------------------------------------------
# AEAD-protected data plane
# --------------------------------------------------------------------------


class DataPlane:
    """Directional AEAD channel with sliding-window anti-replay."""

    def __init__(self, sid: bytes, keys: SessionKeys, window: int = 64) -> None:
        self.sid = sid
        self.keys = keys
        self.ctr = {DIR_UE: 0, DIR_GNB: 0}
        self.win = {DIR_UE: SlidingWindow(window), DIR_GNB: SlidingWindow(window)}

    def _key_nonce(self, direction: str, i: int) -> Tuple[bytes, bytes]:
        if direction == DIR_UE:
            return self.keys.k_u2b, nonce_xor(self.keys.n_u0, i)
        return self.keys.k_b2u, nonce_xor(self.keys.n_b0, i)

    def send(self, direction: str, plaintext: bytes) -> Record:
        i = self.ctr[direction]
        self.ctr[direction] = i + 1
        key, nonce = self._key_nonce(direction, i)
        ct = AEAD.seal(key, nonce, (self.sid, direction, i), plaintext)
        return Record(self.sid, i, ct)

    def recv(self, direction: str, rec: Record) -> Optional[bytes]:
        if rec.sid != self.sid:
            return None
        if not self.win[direction].check_and_insert(rec.i):
            return None                      # ReplayCheck(i) failed
        key, nonce = self._key_nonce(direction, rec.i)
        return AEAD.open(key, nonce, (self.sid, direction, rec.i), rec.ct)


# --------------------------------------------------------------------------
# session driver
# --------------------------------------------------------------------------


@dataclass
class SessionResult:
    established: bool = False
    stage: str = "done"
    reason: str = ""
    g_phy: bool = False
    d_u: bool = False
    d_b: bool = False
    r_u: bool = False
    gate_u: Optional[GateDecision] = None
    gate_b: Optional[GateDecision] = None
    bdr_raw: float = float("nan")            # retained bits, pre-reconciliation
    bdr_all: float = float("nan")            # all samples, pre-reconciliation
    kdr_post: float = float("nan")           # after reconciliation
    retained_fraction: float = float("nan")
    recon_ok: bool = False
    recon_corrected: int = 0
    recon_failed_blocks: int = 0
    raw_bits: int = 0
    leak_bits: int = 0
    k_pqc_match: bool = False
    k_phy_match: bool = False
    k_phy_bits: int = 0
    keys_match: bool = False
    t_h: bytes = b""
    sizes: Dict[str, int] = field(default_factory=dict)
    step_ms: Dict[str, float] = field(default_factory=dict)
    entropy_u: Optional[Dict[str, float]] = None
    eve: Dict[str, float] = field(default_factory=dict)
    ue: Optional[UE] = None
    gnb: Optional[GNB] = None
    keys: Optional[SessionKeys] = None
    trace: List[str] = field(default_factory=list)


Hook = Callable[[Any], Any]


def _apply(hooks: Optional[Dict[str, Hook]], name: str, obj: Any) -> Any:
    if hooks and name in hooks:
        return hooks[name](obj)
    return obj


def run_session(cfg: ProtocolConfig = DEFAULT,
                world: Optional[RadioWorld] = None,
                pki: Optional[PKI] = None,
                hooks: Optional[Dict[str, Hook]] = None,
                replay: Optional[ReplayCache] = None,
                eve: bool = False,
                seed: Optional[int] = None,
                trace: bool = False) -> SessionResult:
    """Run one full session.  ``hooks`` may rewrite any flight in flight."""
    world = world or RadioWorld(cfg.phy, seed=seed)
    pki = pki or PKI.build()
    ue, gnb = UE(cfg, pki, world), GNB(cfg, pki, world, replay)
    res = SessionResult(ue=ue, gnb=gnb)
    log = res.trace.append if trace else (lambda *_: None)
    t: Dict[str, float] = {}

    def clock(name: str, fn, *a, **kw):
        t0 = time.perf_counter()
        out = fn(*a, **kw)
        t[name] = t.get(name, 0.0) + (time.perf_counter() - t0) * 1e3
        return out

    try:
        # ---- Step 1 ----
        f1 = clock("step1_ue", ue.step1)
        res.sizes["flight1"] = f1.size()
        log(f"Step1 UE  -> m1,sigma_U,Cert_U  ({f1.size()} B), sid={f1.m1.sid.hex()[:16]}")
        f1 = _apply(hooks, "flight1", f1)
        clock("step1_gnb", gnb.step1, f1)
        log("Step1 gNB : Verify(Cert_U,sigma_U,m1)=1, ReplayCheck=1")

        # ---- Step 2 ----
        ctx_u = clock("step2_ue", ue.step2)
        ctx_b = clock("step2_gnb", gnb.step2)
        assert ctx_u.h_probe() == ctx_b.h_probe()
        log(f"Step2     : probe_ctx bound, {ctx_u.n_rounds} rounds x "
            f"{ctx_u.n_pilots} pilots, h_probe={ctx_u.h_probe().hex()[:16]}")

        # ---- Step 3 ----
        f2 = clock("step3_gnb", gnb.step3)
        res.sizes["flight2"] = f2.size()
        res.sizes["W"] = f2.m2.w.size()
        res.leak_bits = f2.m2.w.leak_bits
        res.raw_bits = f2.m2.w.n_bits
        log(f"Step3 gNB -> m2,sigma_B,Cert_B  ({f2.size()} B), "
            f"|W|={f2.m2.w.size()} B, leak={res.leak_bits} bits")
        f2 = _apply(hooks, "flight2", f2)
        clock("step3_ue", ue.step3, f2)
        res.k_pqc_match = ue.st["k_pqc"] == gnb.st["k_pqc"]
        log(f"Step3 UE  : sigma_B ok, K_PQC match={res.k_pqc_match}")

        # ---- Step 4 ----
        g_u = clock("step4_ue_local", ue.step4_local)
        g_b, mc = clock("step4_gnb_local", gnb.step4_local)
        res.gate_u, res.gate_b = g_u, g_b
        res.bdr_all = bit_disagreement(ue.st["q"].bits, gnb.st["q"].bits)
        try:
            sel_u, _ = gnb.st["w"].select(ue.st["q"])
            res.bdr_raw = bit_disagreement(sel_u, gnb.st["z"])
        except ValueError:
            res.bdr_raw = float("nan")
        res.kdr_post = bit_disagreement(ue.st["z"], gnb.st["z"])
        res.retained_fraction = g_b.retained_fraction
        res.recon_ok = ue.st["rec"].ok
        res.recon_corrected = ue.st["rec"].corrected
        res.recon_failed_blocks = ue.st["rec"].failed_blocks
        res.entropy_u = g_u.entropy.as_dict() if g_u.entropy else None
        log(f"Step4     : T2={ue.st['t2'].hex()[:16]}, BDR_raw={res.bdr_raw:.4f}, "
            f"KDR_post={res.kdr_post:.4f}, corrected={res.recon_corrected}")
        log(f"Step4 gate: g_U={g_u.accept} {g_u.reasons()} | g_B={g_b.accept} "
            f"{g_b.reasons()}")
        res.sizes["mconf"] = mc.size()
        mc = _apply(hooks, "mconf", mc)
        clock("step4_ue_conf", ue.step4_conf, mc)
        res.r_u = bool(ue.st["r_u"])
        f3 = clock("step4_ue_send", ue.step4_send)
        res.sizes["flight3"] = f3.size()
        f3 = _apply(hooks, "flight3", f3)
        f4 = clock("step4_gnb_recv", gnb.step4_recv, f3)
        res.sizes["flight4"] = f4.size()
        f4 = _apply(hooks, "flight4", f4)
        clock("step4_ue_recv", ue.step4_recv, f4)
        res.d_u, res.d_b = bool(ue.st["d_u"]), bool(f4.m4.d_b)
        res.g_phy = bool(ue.st["g_phy"])
        res.k_phy_match = ue.st["k_phy"] == gnb.st["k_phy"]
        res.k_phy_bits = len(ue.st["k_phy"]) * 8
        log(f"Step4     : r_U={res.r_u}, d_U={res.d_u}, d_B={res.d_b}, "
            f"G_PHY={res.g_phy}, |K_PHY|={res.k_phy_bits} bits, "
            f"match={res.k_phy_match}")
        if eve:
            res.eve.update(_eve_observe(cfg, world, ctx_u, ue, gnb))
            log(f"Step4 Eve : BDR_raw={res.eve['eve_bdr_raw']:.4f}, "
                f"BDR_post={res.eve['eve_bdr_post']:.4f}, "
                f"recovers_Z={bool(res.eve['eve_recovers_z'])}, "
                f"key_match={bool(res.eve['eve_key_match'])}")

        # ---- Step 5 ----
        keys_u = clock("step5_ue", ue.step5)
        keys_b = clock("step5_gnb", gnb.step5)
        res.t_h = ue.st["t_h"]
        res.keys = keys_u
        res.keys_match = (keys_u.k_u2b == keys_b.k_u2b
                          and keys_u.k_b2u == keys_b.k_b2u)
        log(f"Step5     : T_H={res.t_h.hex()[:16]}, keys match={res.keys_match}")

        # ---- Step 6 ----
        fin_u = clock("step6_ue_send", ue.step6_send)
        res.sizes["fin_u"] = fin_u.size()
        fin_u = _apply(hooks, "fin_u", fin_u)
        clock("step6_gnb_recv", gnb.step6_recv, fin_u)
        fin_b = clock("step6_gnb_send", gnb.step6_send)
        res.sizes["fin_b"] = fin_b.size()
        fin_b = _apply(hooks, "fin_b", fin_b)
        clock("step6_ue_recv", ue.step6_recv, fin_b)
        res.established = True
        log("Step6     : two-sided key confirmation ok -> ESTABLISHED")

    except Abort as e:
        res.established = False
        res.stage, res.reason = e.stage, e.reason
        log(f"ABORT {e}")
    except AssertionError as e:                     # probing desynchronised
        res.established = False
        res.stage, res.reason = "step2", f"probe_ctx mismatch: {e}"

    res.step_ms = t
    res.sizes["handshake_total"] = sum(
        v for k, v in res.sizes.items() if k.startswith(("flight", "fin", "mconf")))
    return res


def run_pqc_only_session(cfg: ProtocolConfig = DEFAULT,
                         pki: Optional[PKI] = None) -> Dict[str, Any]:
    """Reference baseline: the same handshake with the PHY branch removed.

    Steps 1, 3 (without ``W`` and without ``h_probe``), 5 and 6 only -- i.e.
    an authenticated post-quantum AKE.  Used to price the physical-layer
    augmentation in bytes and milliseconds.
    """
    pki = pki or PKI.build()
    t: Dict[str, float] = {}

    def clock(name: str, fn, *a):
        t0 = time.perf_counter()
        out = fn(*a)
        t[name] = (time.perf_counter() - t0) * 1e3
        return out

    sid = rand_bytes(16)
    n_u = rand_bytes(cfg.crypto.lambda_bits // 8)
    pk_e, sk_e = clock("kem_keygen", KEM.keygen)
    m1 = M1(sid, n_u, pk_e, cfg.alg_list, cfg.sn_id)
    sig_u = clock("sign_u", Sig.sign, pki.sk_u, H("m1-tbs", m1.to_bytes_msg()))
    f1 = Flight1(m1, sig_u, pki.cert_u)
    clock("verify_cert_u", pki.ca.verify, pki.cert_u)
    clock("verify_sig_u", Sig.verify, pki.cert_u.pk_sig,
          H("m1-tbs", m1.to_bytes_msg()), sig_u)

    n_b = rand_bytes(cfg.crypto.lambda_bits // 8)
    c_kem, k_pqc_b = clock("kem_encaps", KEM.encaps, pk_e)
    m2 = M2(sid, n_u, n_b, c_kem, HelperData(8, 1, 1, 0, b"", 0, 0, b""),
            cfg.alg_list[0], cfg.sn_id, b"")
    tbs = H("m2-tbs", m1.to_bytes_msg(), sig_u, m2.to_bytes_msg())
    sig_b = clock("sign_b", Sig.sign, pki.sk_b, tbs)
    f2 = Flight2(m2, sig_b, pki.cert_b)
    clock("verify_cert_b", pki.ca.verify, pki.cert_b)
    clock("verify_sig_b", Sig.verify, pki.cert_b.pk_sig, tbs, sig_b)
    k_pqc_u = clock("kem_decaps", KEM.decaps, sk_e, c_kem)

    t_h = H("T_H", m1.to_bytes_msg(), sig_u, m2.to_bytes_msg(), sig_b)
    keys = clock("kdf", SessionKeys.derive, t_h, k_pqc_u, b"")
    ad_u = (sid, DIR_UE, 0, t_h, False)
    fin_u = Finished(sid, AEAD.seal(keys.k_cf_u, keys.n_u0, ad_u, b""))
    ok_u = AEAD.open(keys.k_cf_u, keys.n_u0, ad_u, fin_u.ct) is not None
    ad_b = (sid, DIR_GNB, 0, t_h, False)
    fin_b = Finished(sid, AEAD.seal(keys.k_cf_b, keys.n_b0, ad_b, b""))
    ok_b = AEAD.open(keys.k_cf_b, keys.n_b0, ad_b, fin_b.ct) is not None

    sizes = {"flight1": f1.size(), "flight2": f2.size(),
             "fin_u": fin_u.size(), "fin_b": fin_b.size()}
    sizes["handshake_total"] = sum(sizes.values())
    return {"established": bool(ok_u and ok_b and k_pqc_u == k_pqc_b),
            "sizes": sizes, "step_ms": t,
            "compute_ms": float(sum(t.values()))}


def _eve_observe(cfg: ProtocolConfig, world: RadioWorld, ctx: ProbeContext,
                 ue: UE, gnb: GNB) -> Dict[str, float]:
    """Best-effort passive eavesdropper.

    Eve sounds the same (session-bound) campaign, quantises her own CSI and --
    since the helper data ``W`` and the transcript hash ``T_2`` are public --
    also runs the *same* reconciliation and privacy amplification that the UE
    runs.  This is the strongest passive attack the sketch permits.
    """
    y_e = estimate(world, "E", ctx)
    q_e = quantize(y_e.feat, cfg.quant)
    z_b = gnb.st["z"]
    sel_e, _ = gnb.st["w"].select(q_e)
    out: Dict[str, float] = {
        "eve_snr_db": y_e.snr_db_est,
        "eve_bdr_raw": bit_disagreement(sel_e, z_b),
    }
    rec_e = reconcile(q_e, gnb.st["w"])
    out["eve_bdr_post"] = bit_disagreement(rec_e.bits, z_b)
    out["eve_recovers_z"] = float(np.array_equal(rec_e.bits, z_b))
    out["eve_decode_failed_blocks"] = float(rec_e.failed_blocks)
    if ue.st.get("g_phy"):
        k_e = privacy_amplify(rec_e.bits, ue.st["t2"], cfg.gate.target_phy_bits)
        out["eve_key_match"] = float(k_e == ue.st["k_phy"])
    else:
        out["eve_key_match"] = 0.0
    return out
