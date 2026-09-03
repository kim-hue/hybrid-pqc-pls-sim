"""Experiment 1 -- functional verification.

Executes the protocol step by step and prints every quantity the figures
name, for two regimes:

* a healthy link, where the joint gate opens (``G_PHY = 1``) and the session
  key mixes both secrets;
* a broken link, where reconciliation fails, the gate closes
  (``G_PHY = 0``) and the session completes on the post-quantum baseline.

It then asserts the correctness properties of the protocol.
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from hpls.config import DEFAULT                                   # noqa: E402
from hpls.primitives import KEM, STATS, Sig                       # noqa: E402
from hpls.protocol import (DIR_GNB, DIR_UE, DataPlane, PKI,       # noqa: E402
                           SessionKeys, run_session)

RESULTS = pathlib.Path(__file__).resolve().parents[1] / "results"


def show(res, header: str, out: list[str]) -> None:
    def p(s: str = "") -> None:
        print(s)
        out.append(s)

    p("=" * 78)
    p(header)
    p("=" * 78)
    for line in res.trace:
        p("  " + line)
    p()
    p(f"  session state          : "
      f"{'ESTABLISHED' if res.established else 'ABORT @ ' + res.stage}")
    if not res.established:
        p(f"  abort reason           : {res.reason}")
    p(f"  K_PQC agreement        : {res.k_pqc_match}")
    p(f"  G_PHY                  : {res.g_phy}   (d_U={res.d_u}, "
      f"d_B={res.d_b}, r_U={res.r_u})")
    p(f"  |K_PHY|                : {res.k_phy_bits} bits "
      f"(agreement={res.k_phy_match})")
    p(f"  session keys agree     : {res.keys_match}")
    p(f"  probe samples          : {DEFAULT.phy.n_samples()}"
      f"  retained={res.retained_fraction:.3f}")
    p(f"  BDR all / retained     : {res.bdr_all:.4f} / {res.bdr_raw:.4f}")
    p(f"  KDR after reconcile    : {res.kdr_post:.4f} "
      f"(corrected={res.recon_corrected} bits, "
      f"failed blocks={res.recon_failed_blocks})")
    if res.gate_u:
        g = res.gate_u
        p(f"  entropy budget (UE)    : H_inf={g.h_min_bits:.1f} - "
          f"leak={g.leak_bits} - 2log2(1/eps)="
          f"{2 * DEFAULT.gate.pa_epsilon_log2} => {g.budget_bits:.1f} bits "
          f">= L={DEFAULT.gate.target_phy_bits}? {g.entropy_ok}")
        p(f"  gate detail (UE)       : SNR={g.snr_db:.1f} dB, "
          f"reliable={g.reliable_fraction:.3f}, checks={g.reasons()}")
    if res.entropy_u:
        e = res.entropy_u
        p(f"  entropy estimators     : MCV={e['h_mcv']:.3f}, "
          f"Markov={e['h_markov']:.3f}, Shannon={e['h_shannon']:.3f} "
          f"bits/sym, lag-1 rho={e['lag1_corr']:.3f}")
    if res.keys:
        p(f"  k_(U->B)               : {res.keys.k_u2b.hex()[:32]}...")
        p(f"  k_(B->U)               : {res.keys.k_b2u.hex()[:32]}...")
        p(f"  T_H                    : {res.t_h.hex()}")
    p(f"  on-the-wire sizes (B)  : {res.sizes}")
    p()


def main() -> dict:
    out: list[str] = []
    pki = PKI.build()
    summary: dict = {"primitives": {"kem": KEM.name, "sig": Sig.name}}

    print(f"KEM={KEM.name} (pk {KEM.pk_len} B, ct {KEM.ct_len} B)   "
          f"SIG={Sig.name} (pk {Sig.pk_len} B, sig {Sig.sig_len} B)")
    p = DEFAULT.phy
    print(f"radio: {p.tdl_profile}, tau_rms={p.delay_spread_ns} ns, "
          f"v={p.ue_speed_mps} m/s, f_d={p.doppler_hz():.1f} Hz, "
          f"T_c={p.coherence_time_s()*1e3:.1f} ms, "
          f"B_c={p.coherence_bandwidth_hz()/1e3:.0f} kHz")
    print(f"probing: {p.n_probe_rounds} rounds x {p.n_pilots()} pilots "
          f"(spacing {p.effective_pilot_spacing()} SC), "
          f"interval {p.effective_probe_interval_us()/1e3:.1f} ms, "
          f"{p.n_avg_symbols} symbols averaged "
          f"=> effective SNR {p.effective_snr_db():.1f} dB\n")

    healthy = run_session(DEFAULT, pki=pki, eve=True, seed=2024, trace=True)
    show(healthy, "REGIME A -- healthy link: authenticated PHY augmentation",
         out)

    broken = DEFAULT.with_phy(snr_db=-5.0, ue_speed_mps=30.0, n_avg_symbols=1)
    fb = run_session(broken, pki=pki, eve=True, seed=2025, trace=True)
    show(fb, "REGIME B -- degraded link: authenticated PQC-only fallback", out)

    # --- data plane -------------------------------------------------------
    dp_u = DataPlane(healthy.ue.st["sid"], healthy.keys)
    dp_b = DataPlane(healthy.gnb.st["sid"], healthy.gnb.st["keys"])
    msgs = [b"Registration Request", b"PDU Session Establishment Request",
            b"x" * 1400]
    recs = [dp_u.send(DIR_UE, m) for m in msgs]
    got = [dp_b.recv(DIR_UE, r) for r in recs]
    dl = dp_b.send(DIR_GNB, b"Registration Accept")
    got_dl = dp_u.recv(DIR_GNB, dl)
    replay = dp_b.recv(DIR_UE, recs[0])
    line = (f"data plane: {len(msgs)} UL records delivered="
            f"{got == msgs}, DL record delivered={got_dl == b'Registration Accept'}"
            f", replay rejected={replay is None}, "
            f"expansion={recs[0].size() - len(msgs[0])} B/record")
    print(line)
    out.append(line)

    # --- correctness assertions ------------------------------------------
    assert healthy.established and healthy.keys_match and healthy.k_pqc_match
    assert healthy.g_phy and healthy.k_phy_match
    assert healthy.k_phy_bits == DEFAULT.gate.target_phy_bits
    assert fb.established and fb.keys_match and not fb.g_phy
    assert fb.k_phy_bits == 0
    assert got == msgs and got_dl == b"Registration Accept" and replay is None

    # hybrid composition: flipping either input changes every derived key
    k1 = SessionKeys.derive(healthy.t_h, healthy.ue.st["k_pqc"],
                            healthy.ue.st["k_phy"])
    k2 = SessionKeys.derive(healthy.t_h, bytes(32), healthy.ue.st["k_phy"])
    k3 = SessionKeys.derive(healthy.t_h, healthy.ue.st["k_pqc"], bytes(16))
    k4 = SessionKeys.derive(bytes(32), healthy.ue.st["k_pqc"],
                            healthy.ue.st["k_phy"])
    assert len({k1.k_u2b, k2.k_u2b, k3.k_u2b, k4.k_u2b}) == 4
    line = ("key-schedule dependency: session keys change when K_PQC, K_PHY "
            "or T_H changes -> OK")
    print(line)
    out.append(line)
    print("\nALL FUNCTIONAL CHECKS PASSED")
    out.append("ALL FUNCTIONAL CHECKS PASSED")

    summary["healthy"] = {
        "established": healthy.established, "g_phy": healthy.g_phy,
        "k_phy_bits": healthy.k_phy_bits, "keys_match": healthy.keys_match,
        "bdr_retained": healthy.bdr_raw, "kdr_post": healthy.kdr_post,
        "retained_fraction": healthy.retained_fraction,
        "h_min_bits": healthy.gate_u.h_min_bits,
        "leak_bits": healthy.gate_u.leak_bits,
        "budget_bits": healthy.gate_u.budget_bits,
        "entropy": healthy.entropy_u, "sizes": healthy.sizes,
        "step_ms": healthy.step_ms, "eve": healthy.eve,
    }
    summary["fallback"] = {
        "established": fb.established, "g_phy": fb.g_phy,
        "k_phy_bits": fb.k_phy_bits, "keys_match": fb.keys_match,
        "bdr_retained": fb.bdr_raw, "kdr_post": fb.kdr_post,
        "recon_failed_blocks": fb.recon_failed_blocks,
        "d_u": fb.d_u, "d_b": fb.d_b, "r_u": fb.r_u,
    }
    summary["crypto_op_ms"] = STATS.snapshot()

    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "functional_trace.txt").write_text("\n".join(out) + "\n")
    (RESULTS / "functional.json").write_text(json.dumps(summary, indent=2,
                                                        default=str))
    return summary


if __name__ == "__main__":
    main()
