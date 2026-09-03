"""Attack suite against the hybrid PQC-PLS protocol.

Each attack is a function returning an :class:`AttackResult`.  ``expected``
states what the protocol is *supposed* to do; ``ok`` is ``True`` when the
observed behaviour matches, so the whole suite doubles as a security
regression test.

Adversary model
---------------
``A`` is a Dolev-Yao attacker on the radio interface: she sees every flight,
can modify, drop, reorder and replay them, and she can sound the channel
herself (she knows ``sid`` and ``N_U``, which travel in the clear, so she can
derive ``probe_ctx``).  She does **not** hold the long-term ML-DSA keys of the
UE or the gNB and she is not inside the coherence volume of the legitimate
link unless ``eve_csi_correlation`` says so.  Two additional *compromise*
experiments give her one of the two key components outright, in order to
measure the hybrid guarantee.
"""

from __future__ import annotations

import numpy as np
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .channel import RadioWorld
from .config import DEFAULT, ProtocolConfig
from .messages import (Finished, Flight1, Flight2, Flight3, Flight4, M2, M3,
                       M4, MConf, Record, with_field)
from .primitives import (CA, H, KEM, ReplayCache, Sig, mac, rand_bytes)
from .probing import ProbeContext, estimate
from .protocol import (Abort, DIR_GNB, DIR_UE, DataPlane, GNB, PKI,
                       SessionKeys, UE, run_session)
from .quantize import bit_disagreement, quantize
from .reconcile import reconcile, reconcile_helper


@dataclass
class AttackResult:
    name: str
    goal: str
    expected: str
    observed: str
    ok: bool
    established: bool = False
    stage: str = ""
    reason: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


def _fresh(cfg: ProtocolConfig, pki: PKI, seed: int):
    return RadioWorld(cfg.phy, seed=seed), ReplayCache()


# --------------------------------------------------------------------------
# A01 -- passive eavesdropping
# --------------------------------------------------------------------------


def a01_passive_eavesdrop(cfg: ProtocolConfig, pki: PKI, n: int = 20,
                          seed: int = 1000) -> AttackResult:
    bdr, rec, keym, gp = [], [], [], []
    for i in range(n):
        r = run_session(cfg, pki=pki, eve=True, seed=seed + i)
        if not r.established or not r.eve:
            continue
        bdr.append(r.eve["eve_bdr_post"])
        rec.append(r.eve["eve_recovers_z"])
        keym.append(r.eve["eve_key_match"])
        gp.append(r.g_phy)
    ok = float(np.sum(keym)) == 0.0
    return AttackResult(
        "A01-passive-eavesdrop",
        "recover K_PHY from Eve's own CSI plus the public W and T_2",
        "Eve's post-reconciliation BDR stays near 0.5; she never recovers Z",
        f"mean BDR_post={np.mean(bdr):.4f}, recovery={np.mean(rec):.1%}, "
        f"K_PHY match={np.mean(keym):.1%}", ok,
        extra={"rho": cfg.phy.eve_csi_correlation, "n_sessions": len(bdr),
               "bdr_post_mean": float(np.mean(bdr)),
               "recovery_rate": float(np.mean(rec)),
               "key_match_rate": float(np.mean(keym)),
               "g_phy_rate": float(np.mean(gp))})


# --------------------------------------------------------------------------
# A02..A06 -- authentication / integrity of the handshake
# --------------------------------------------------------------------------


def a02_rogue_ue_certificate(cfg: ProtocolConfig, pki: PKI,
                             seed: int = 11) -> AttackResult:
    rogue_ca = CA("Rogue-CA")
    pk, _ = Sig.keygen()
    rogue_cert = rogue_ca.issue("imsi-001010000000001", pk)

    def hook(f1: Flight1) -> Flight1:
        return with_field(f1, cert_u=rogue_cert)

    r = run_session(cfg, pki=pki, hooks={"flight1": hook}, seed=seed)
    ok = (not r.established) and r.stage == "step1"
    return AttackResult("A02-rogue-ue-cert",
                        "impersonate the UE with a certificate from a rogue CA",
                        "abort in Step 1 (certificate chain)",
                        f"{r.stage}: {r.reason}", ok, r.established,
                        r.stage, r.reason)


def a03_alg_downgrade_m1(cfg: ProtocolConfig, pki: PKI,
                         seed: int = 12) -> AttackResult:
    def hook(f1: Flight1) -> Flight1:
        weak = with_field(f1.m1, alg_list=("ML-KEM-512+ML-DSA-44",))
        return with_field(f1, m1=weak)

    r = run_session(cfg, pki=pki, hooks={"flight1": hook}, seed=seed)
    ok = (not r.established) and r.stage == "step1"
    return AttackResult("A03-downgrade-alg-list",
                        "strip the strong suite from m1 (bidding-down)",
                        "abort in Step 1 (sigma_U covers alg_list)",
                        f"{r.stage}: {r.reason}", ok, r.established,
                        r.stage, r.reason)


def a04_replay_flight1(cfg: ProtocolConfig, pki: PKI,
                       seed: int = 13) -> AttackResult:
    captured: Dict[str, Flight1] = {}

    def capture(f1: Flight1) -> Flight1:
        captured["f1"] = f1
        return f1

    replay = ReplayCache()
    world = RadioWorld(cfg.phy, seed=seed)
    r1 = run_session(cfg, world=world, pki=pki, replay=replay,
                     hooks={"flight1": capture}, seed=seed)
    # same gNB, same replay cache, the *recorded* first flight
    r2 = run_session(cfg, world=world, pki=pki, replay=replay,
                     hooks={"flight1": lambda _: captured["f1"]}, seed=seed + 1)
    ok = r1.established and (not r2.established) and "Replay" in r2.reason
    return AttackResult("A04-replay-flight1",
                        "replay a recorded, validly signed m1",
                        "abort in Step 1 (ReplayCheck(sid, N_U))",
                        f"first session established={r1.established}; "
                        f"replay -> {r2.stage}: {r2.reason}", ok,
                        r2.established, r2.stage, r2.reason)


def a05_tamper_kem_ciphertext(cfg: ProtocolConfig, pki: PKI,
                              seed: int = 14) -> AttackResult:
    def hook(f2: Flight2) -> Flight2:
        ct = bytearray(f2.m2.c_kem)
        ct[0] ^= 0x01
        return with_field(f2, m2=with_field(f2.m2, c_kem=bytes(ct)))

    r = run_session(cfg, pki=pki, hooks={"flight2": hook}, seed=seed)
    ok = (not r.established) and r.stage == "step3"
    return AttackResult("A05-tamper-kem-ct",
                        "modify C_KEM so the two sides derive different K_PQC",
                        "abort in Step 3 (sigma_B covers C_KEM)",
                        f"{r.stage}: {r.reason}", ok, r.established,
                        r.stage, r.reason)


def a06_tamper_helper_data(cfg: ProtocolConfig, pki: PKI,
                           seed: int = 15) -> AttackResult:
    def hook(f2: Flight2) -> Flight2:
        bad = f2.m2.w.with_syndrome_flips(64)
        return with_field(f2, m2=with_field(f2.m2, w=bad))

    r = run_session(cfg, pki=pki, hooks={"flight2": hook}, seed=seed)
    ok = (not r.established) and r.stage == "step3"
    return AttackResult("A06-tamper-helper-data",
                        "corrupt the public helper data W in flight",
                        "abort in Step 3 (sigma_B covers W)",
                        f"{r.stage}: {r.reason}", ok, r.established,
                        r.stage, r.reason)


def a07_stale_probe_context(cfg: ProtocolConfig, pki: PKI,
                            seed: int = 16) -> AttackResult:
    """A *certified but malicious* gNB reuses helper data from another campaign.

    The signature is genuine, so only the ``h_probe`` binding can catch it.
    """
    world = RadioWorld(cfg.phy, seed=seed)
    ue, gnb = UE(cfg, pki, world), GNB(cfg, pki, world)
    f1 = ue.step1()
    gnb.step1(f1)
    ue.step2()
    gnb.step2()
    # malicious gNB: sign m2 with the h_probe of a *different* campaign
    stale = ProbeContext.derive(rand_bytes(16), rand_bytes(32), cfg.phy)
    gnb.st["h_probe"] = stale.h_probe()
    f2 = gnb.step3()
    try:
        ue.step3(f2)
        ok, stage, reason = False, "", "accepted stale probing context"
    except Abort as e:
        ok, stage, reason = e.stage == "step3", e.stage, e.reason
    return AttackResult("A07-stale-probe-context",
                        "bind helper data of another campaign into a valid m2",
                        "abort in Step 3 (h_probe mismatch)",
                        f"{stage}: {reason}", ok, False, stage, reason)


# --------------------------------------------------------------------------
# A08..A10 -- the authenticated gate
# --------------------------------------------------------------------------


def a08_forge_gate_flip_m3(cfg: ProtocolConfig, pki: PKI,
                           seed: int = 17) -> AttackResult:
    """Flip ``d_U`` and re-MAC with a key Eve guesses (she lacks k_gate)."""
    def hook(f3: Flight3) -> Flight3:
        m3 = with_field(f3.m3, d_u=not f3.m3.d_u)
        forged = mac(rand_bytes(32), "UE-GATE", b"\x00" * 32, m3.to_bytes_msg())
        return Flight3(m3, forged)

    r = run_session(cfg, pki=pki, hooks={"flight3": hook}, seed=seed)
    ok = (not r.established) and r.stage == "step4" and "tau_3" in r.reason
    return AttackResult("A08-forge-tau3",
                        "force G_PHY by flipping d_U with a forged tau_3",
                        "abort in Step 4 (tau_3 MAC under k_gate)",
                        f"{r.stage}: {r.reason}", ok, r.established,
                        r.stage, r.reason)


def a09_bitflip_m3_keep_tag(cfg: ProtocolConfig, pki: PKI,
                            seed: int = 18) -> AttackResult:
    def hook(f3: Flight3) -> Flight3:
        return with_field(f3, m3=with_field(f3.m3, d_u=not f3.m3.d_u))

    r = run_session(cfg, pki=pki, hooks={"flight3": hook}, seed=seed)
    ok = (not r.established) and r.stage == "step4"
    return AttackResult("A09-bitflip-m3",
                        "flip d_U and keep the original tau_3",
                        "abort in Step 4 (MAC covers m3)",
                        f"{r.stage}: {r.reason}", ok, r.established,
                        r.stage, r.reason)


def a10_tamper_m4(cfg: ProtocolConfig, pki: PKI, seed: int = 19) -> AttackResult:
    def hook(f4: Flight4) -> Flight4:
        return with_field(f4, m4=with_field(f4.m4, g_phy=not f4.m4.g_phy))

    r = run_session(cfg, pki=pki, hooks={"flight4": hook}, seed=seed)
    ok = (not r.established) and r.stage == "step4"
    return AttackResult("A10-tamper-m4",
                        "flip G_PHY in the gNB's gate echo",
                        "abort in Step 4 (tau_4 MAC / echo consistency)",
                        f"{r.stage}: {r.reason}", ok, r.established,
                        r.stage, r.reason)


def a11_inconsistent_gate_decision(cfg: ProtocolConfig, pki: PKI,
                                   seed: int = 20) -> AttackResult:
    """A malicious gNB (holding k_gate) announces an inconsistent decision."""
    world = RadioWorld(cfg.phy, seed=seed)
    ue, gnb = UE(cfg, pki, world), GNB(cfg, pki, world)
    f1 = ue.step1(); gnb.step1(f1)
    ue.step2(); gnb.step2()
    f2 = gnb.step3(); ue.step3(f2)
    ue.step4_local()
    _, mc = gnb.step4_local()
    ue.step4_conf(mc)
    f3 = ue.step4_send()
    gnb.step4_recv(f3)
    # d_U = d_B = 1 but G_PHY = 0, MAC'd with the real k_gate
    m4 = M4(gnb.st["sid"], True, True, False)
    tau4 = mac(gnb.st["k_gate"], "GNB-GATE", gnb.st["t2"], m4.to_bytes_msg())
    try:
        ue.step4_recv(Flight4(m4, tau4))
        ok, stage, reason = False, "", "accepted inconsistent G_PHY"
    except Abort as e:
        ok, stage, reason = e.stage == "step4", e.stage, e.reason
    return AttackResult("A11-inconsistent-gate",
                        "authenticated but logically inconsistent m4",
                        "abort in Step 4 (G_PHY = d_U AND d_B is checked)",
                        f"{stage}: {reason}", ok, False, stage, reason)


# --------------------------------------------------------------------------
# A12..A13 -- key confirmation and the data plane
# --------------------------------------------------------------------------


def a12_tamper_finished(cfg: ProtocolConfig, pki: PKI,
                        seed: int = 21) -> AttackResult:
    def hook(fin: Finished) -> Finished:
        ct = bytearray(fin.ct)
        ct[-1] ^= 0x80
        return with_field(fin, ct=bytes(ct))

    r = run_session(cfg, pki=pki, hooks={"fin_u": hook}, seed=seed)
    ok = (not r.established) and r.stage == "step6"
    return AttackResult("A12-tamper-finished",
                        "modify fin_U so the gNB accepts a different key",
                        "abort in Step 6 (AEAD key confirmation)",
                        f"{r.stage}: {r.reason}", ok, r.established,
                        r.stage, r.reason)


def a13_gphy_view_mismatch(cfg: ProtocolConfig, pki: PKI,
                           seed: int = 22) -> AttackResult:
    """The two parties end Step 4 with different views of ``G_PHY``.

    ``G_PHY`` is inside the key-confirmation associated data, so the mismatch
    must be caught before any traffic key is used.
    """
    world = RadioWorld(cfg.phy, seed=seed)
    ue, gnb = UE(cfg, pki, world), GNB(cfg, pki, world)
    f1 = ue.step1(); gnb.step1(f1)
    ue.step2(); gnb.step2()
    f2 = gnb.step3(); ue.step3(f2)
    ue.step4_local()
    _, mc = gnb.step4_local()
    ue.step4_conf(mc)
    f3 = ue.step4_send()
    f4 = gnb.step4_recv(f3)
    ue.step4_recv(f4)
    gnb.st["g_phy"] = not gnb.st["g_phy"]      # induced view mismatch
    ue.step5(); gnb.step5()
    try:
        gnb.step6_recv(ue.step6_send())
        ok, stage, reason = False, "", "accepted mismatched G_PHY view"
    except Abort as e:
        ok, stage, reason = e.stage == "step6", e.stage, e.reason
    return AttackResult("A13-gphy-view-mismatch",
                        "make UE and gNB disagree on the PHY-mode flag",
                        "abort in Step 6 (G_PHY is in the confirmation AD)",
                        f"{stage}: {reason}", ok, False, stage, reason)


def a14_data_plane_replay_and_tamper(cfg: ProtocolConfig, pki: PKI,
                                     seed: int = 23) -> AttackResult:
    r = run_session(cfg, pki=pki, seed=seed)
    if not r.established or r.keys is None:
        return AttackResult("A14-data-plane", "-", "-", "session failed", False)
    dp_u = DataPlane(r.ue.st["sid"], r.keys, cfg.crypto.replay_window)
    dp_b = DataPlane(r.gnb.st["sid"], r.gnb.st["keys"], cfg.crypto.replay_window)
    rec0 = dp_u.send(DIR_UE, b"NAS Registration Request")
    rec1 = dp_u.send(DIR_UE, b"PDU Session Establishment")
    ok_first = dp_b.recv(DIR_UE, rec0) == b"NAS Registration Request"
    ok_second = dp_b.recv(DIR_UE, rec1) == b"PDU Session Establishment"
    replayed = dp_b.recv(DIR_UE, rec0)                 # must be rejected
    bad = Record(rec1.sid, 2, bytes(rec1.ct[:-1] + bytes([rec1.ct[-1] ^ 1])))
    tampered = dp_b.recv(DIR_UE, bad)                  # must be rejected
    wrong_dir = dp_b.recv(DIR_GNB, rec0)               # direction confusion
    ok = ok_first and ok_second and replayed is None and tampered is None \
        and wrong_dir is None
    return AttackResult("A14-data-plane-replay-tamper",
                        "replay a record, forge a record, swap the direction",
                        "delivery of fresh records only; all three rejected",
                        f"fresh ok={ok_first and ok_second}, replay="
                        f"{replayed is None}, tamper={tampered is None}, "
                        f"dir-swap={wrong_dir is None}", ok, True)


# --------------------------------------------------------------------------
# A15..A16 -- one-sided compromise (the hybrid guarantee)
# --------------------------------------------------------------------------


def a15_pqc_compromise(cfg: ProtocolConfig, pki: PKI,
                       seed: int = 24) -> AttackResult:
    """A CRQC breaks ML-KEM: the adversary learns ``K_PQC``."""
    r = run_session(cfg, pki=pki, seed=seed)
    if not r.established:
        return AttackResult("A15-pqc-compromise", "-", "-", "session failed", False)
    t_h, k_pqc = r.ue.st["t_h"], r.ue.st["k_pqc"]
    true_keys = r.keys
    guess = SessionKeys.derive(t_h, k_pqc, rand_bytes(16))
    recovered = guess.k_u2b == true_keys.k_u2b
    # with G_PHY = 0 the PQC secret is the only input -> full break (by design)
    fallback = SessionKeys.derive(t_h, k_pqc, b"").k_u2b == true_keys.k_u2b
    residual = r.gate_u.budget_bits if r.gate_u else 0.0
    ok = (not recovered) if r.g_phy else fallback
    return AttackResult(
        "A15-pqc-compromise",
        "derive the session keys knowing K_PQC and the whole transcript",
        "keys remain unrecoverable while G_PHY = 1 (residual = |K_PHY|)",
        f"G_PHY={r.g_phy}: keys recovered={recovered}, "
        f"PQC-only fallback recovers={fallback}", ok, extra={
            "g_phy": r.g_phy, "keys_recovered": recovered,
            "residual_phy_bits": min(float(cfg.gate.target_phy_bits),
                                     float(residual)) if r.g_phy else 0.0})


def a16_phy_compromise(cfg: ProtocolConfig, pki: PKI,
                       seed: int = 25) -> AttackResult:
    """The channel is fully predictable: the adversary learns ``K_PHY``."""
    r = run_session(cfg, pki=pki, seed=seed)
    if not r.established:
        return AttackResult("A16-phy-compromise", "-", "-", "session failed", False)
    t_h, k_phy = r.ue.st["t_h"], r.ue.st["k_phy"]
    guess = SessionKeys.derive(t_h, rand_bytes(32), k_phy)
    recovered = guess.k_u2b == r.keys.k_u2b
    return AttackResult(
        "A16-phy-compromise",
        "derive the session keys knowing K_PHY and the whole transcript",
        "keys remain unrecoverable: ML-KEM-768 (NIST level 3) still stands",
        f"keys recovered={recovered}", not recovered,
        extra={"residual_pqc_bits": 256, "kem": KEM.name})


# --------------------------------------------------------------------------
# A17 -- what the authenticated gate actually buys: an unauthenticated
#        PLS baseline under an active helper-data-injection attack
# --------------------------------------------------------------------------


def a17_rogue_gnb_certificate(cfg: ProtocolConfig, pki: PKI,
                              seed: int = 26) -> AttackResult:
    """False-base-station / MITM toward the UE with a rogue gNB certificate."""
    rogue_ca = CA("Rogue-CA")
    pk, sk = Sig.keygen()
    rogue_cert = rogue_ca.issue("gnb-001010-17", pk)

    seen: Dict[str, Any] = {}

    def grab(f1: Flight1) -> Flight1:
        seen["m1"], seen["sig_u"] = f1.m1, f1.sig_u
        return f1

    def hook(f2: Flight2) -> Flight2:
        # Eve encapsulates to the UE's ephemeral key and signs her own m2
        c_kem, _ = KEM.encaps(seen["m1"].pk_e)
        m2 = with_field(f2.m2, c_kem=c_kem)
        tbs = H("m2-tbs", seen["m1"].to_bytes_msg(), seen["sig_u"],
                m2.to_bytes_msg())
        return Flight2(m2, Sig.sign(sk, tbs), rogue_cert)

    r = run_session(cfg, pki=pki, hooks={"flight1": grab, "flight2": hook},
                    seed=seed)
    ok = (not r.established) and r.stage == "step3"
    return AttackResult("A17-rogue-gnb-cert",
                        "false base station: own m2 signed under a rogue CA",
                        "abort in Step 3 (gNB certificate chain)",
                        f"{r.stage}: {r.reason}", ok, r.established,
                        r.stage, r.reason)


def a18_mitm_vs_unauthenticated_pls(cfg: ProtocolConfig, pki: PKI,
                                    n: int = 10, seed: int = 3000
                                    ) -> AttackResult:
    """Quantify what authentication buys over a plain PLS scheme.

    *Unauthenticated PLS baseline*: no certificates, no ``sigma``, no MAC'd
    gate -- exactly the classic "probe, quantise, reconcile, amplify" scheme.
    Eve interposes as a relay: she runs the probing campaign separately with
    the UE and with the gNB, so each victim reconciles against helper data
    Eve produced from a channel Eve observes.  She then holds both keys.
    Nothing in the baseline can detect this.

    *Hybrid protocol*: the same interposition requires a certified identity
    on at least one side; both directions abort (A02 and A17).
    """
    baseline_success = 0
    for i in range(n):
        # Eve<->UE and Eve<->gNB are two distinct links; Eve is an endpoint of
        # both, so she knows both quantised strings by construction.
        world = RadioWorld(cfg.phy, seed=seed + i)
        ctx = ProbeContext.derive(rand_bytes(16), rand_bytes(32), cfg.phy)
        y_u, y_e = estimate(world, "U", ctx), estimate(world, "E", ctx)
        q_u, q_e = quantize(y_u.feat, cfg.quant), quantize(y_e.feat, cfg.quant)
        # Eve plays "gNB" for the UE: she issues the helper data herself
        w_e = reconcile_helper(q_u, cfg.code, cfg.quant)
        z_u, _ = w_e.select(q_u)
        rec = reconcile(q_u, w_e)
        baseline_success += int(np.array_equal(rec.bits, z_u))
    rogue_ue = a02_rogue_ue_certificate(cfg, pki).ok
    rogue_gnb = a17_rogue_gnb_certificate(cfg, pki).ok
    ok = rogue_ue and rogue_gnb
    return AttackResult(
        "A18-mitm-vs-unauth-pls",
        "interpose between UE and gNB during the probing campaign",
        "baseline PLS: undetectable MITM; hybrid: aborts in both directions",
        f"unauthenticated baseline MITM succeeds {baseline_success}/{n}; "
        f"hybrid aborts (rogue UE cert={rogue_ue}, rogue gNB cert={rogue_gnb})",
        ok, extra={"baseline_mitm_success_rate": baseline_success / n,
                   "hybrid_blocks_rogue_ue": rogue_ue,
                   "hybrid_blocks_rogue_gnb": rogue_gnb})


def a19_phy_jamming_graceful_fallback(cfg: ProtocolConfig, pki: PKI,
                                      seed: int = 27) -> AttackResult:
    """Radio-layer denial of the PLS component.

    Eve jams / desynchronises the sounding campaign so that the two
    observations decorrelate (modelled as a large drop in SNR together with a
    fast-varying channel).  Reconciliation then fails, ``r_U = 0``, the joint
    gate opens to ``G_PHY = 0`` and the session **still** completes on the
    mandatory post-quantum baseline.  The attacker cannot turn a PLS outage
    into a handshake failure.
    """
    jammed = cfg.with_phy(snr_db=-5.0, ue_speed_mps=30.0, n_avg_symbols=1)
    r = run_session(jammed, pki=pki, seed=seed)
    ok = r.established and (not r.g_phy) and r.k_phy_bits == 0
    return AttackResult(
        "A19-phy-jamming-fallback",
        "deny the physical-layer contribution (jamming / decorrelation)",
        "session still ESTABLISHED with G_PHY = 0 and K_PHY = epsilon",
        f"established={r.established}, G_PHY={r.g_phy}, "
        f"|K_PHY|={r.k_phy_bits} bits, d_U={r.d_u}, d_B={r.d_b}, "
        f"r_U={r.r_u}, BDR={r.bdr_raw:.3f}", ok, r.established,
        r.stage, r.reason,
        extra={"g_phy": r.g_phy, "bdr": r.bdr_raw, "d_u": r.d_u,
               "d_b": r.d_b, "r_u": r.r_u})


# --------------------------------------------------------------------------
# registry
# --------------------------------------------------------------------------

ATTACKS: List[Callable[..., AttackResult]] = [
    a01_passive_eavesdrop,
    a02_rogue_ue_certificate,
    a03_alg_downgrade_m1,
    a04_replay_flight1,
    a05_tamper_kem_ciphertext,
    a06_tamper_helper_data,
    a07_stale_probe_context,
    a08_forge_gate_flip_m3,
    a09_bitflip_m3_keep_tag,
    a10_tamper_m4,
    a11_inconsistent_gate_decision,
    a12_tamper_finished,
    a13_gphy_view_mismatch,
    a14_data_plane_replay_and_tamper,
    a15_pqc_compromise,
    a16_phy_compromise,
    a17_rogue_gnb_certificate,
    a18_mitm_vs_unauthenticated_pls,
    a19_phy_jamming_graceful_fallback,
]


def run_all_attacks(cfg: ProtocolConfig = DEFAULT,
                    pki: Optional[PKI] = None,
                    verbose: bool = True) -> List[AttackResult]:
    pki = pki or PKI.build()
    out = []
    for fn in ATTACKS:
        res = fn(cfg, pki)
        out.append(res)
        if verbose:
            flag = "PASS" if res.ok else "FAIL"
            print(f"[{flag}] {res.name}: {res.observed}")
    return out
