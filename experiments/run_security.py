"""Experiment 2 -- security evaluation.

Part 1  the attack suite (:mod:`hpls.adversary`): 19 attacks against
        authentication, transcript integrity, the authenticated gate, key
        confirmation, the data plane, and one-sided key compromise.
Part 2  quantitative sweeps of the physical-layer security margin:
        eavesdropper correlation, link SNR, mobility, pilot spacing,
        code strength and guard-band width.
"""

from __future__ import annotations

import csv
import json
import math
import pathlib
import sys

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from hpls import viz                                            # noqa: E402
from hpls.adversary import run_all_attacks                      # noqa: E402
from hpls.config import DEFAULT                                 # noqa: E402
from hpls.metrics import phy_trial, sweep                       # noqa: E402
from hpls.protocol import PKI, run_session                      # noqa: E402

RESULTS = pathlib.Path(__file__).resolve().parents[1] / "results"
QUICK = "--quick" in sys.argv
N = 12 if QUICK else 40
N_SESS = 8 if QUICK else 24


# --------------------------------------------------------------------------
def part1_attacks(pki: PKI) -> list:
    print("\n" + "=" * 78)
    print("PART 1 -- ATTACK SUITE")
    print("=" * 78)
    results = run_all_attacks(DEFAULT, pki)
    passed = sum(r.ok for r in results)
    print(f"\n{passed}/{len(results)} attacks behaved as the protocol requires")
    with (RESULTS / "attacks.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["name", "goal", "expected", "observed", "verdict",
                    "abort_stage", "abort_reason"])
        for r in results:
            w.writerow([r.name, r.goal, r.expected, r.observed,
                        "PASS" if r.ok else "FAIL", r.stage, r.reason])
    (RESULTS / "attacks.json").write_text(json.dumps(
        [r.__dict__ for r in results], indent=2, default=str))
    return results


# --------------------------------------------------------------------------
def part2_eve_correlation() -> list:
    print("\n" + "=" * 78)
    print("PART 2a -- eavesdropper CSI correlation sweep")
    print("=" * 78)
    rhos = [0.0, 0.2, 0.4, 0.6, 0.8, 0.9, 0.95, 0.99]
    rows = sweep(lambda r: DEFAULT.with_phy(eve_csi_correlation=r), rhos, N)
    print(f"{'rho':>6} {'Eve BDR raw':>12} {'Eve BDR post':>13} "
          f"{'Z recovered':>12} {'K_PHY match':>12} {'legit KDR':>10}")
    for r, row in zip(rhos, rows):
        print(f"{r:>6.2f} {row['eve_bdr_raw']:>12.4f} "
              f"{row['eve_bdr_post']:>13.4f} {row['eve_recovers_z']:>12.1%} "
              f"{row['eve_key_match']:>12.1%} {row['kdr_post']:>10.4f}")

    viz.use_style()
    fig, axes = viz.plt.subplots(1, 2, figsize=(10.5, 3.9))
    ax = axes[0]
    viz.line(ax, rhos, [r["eve_bdr_raw"] for r in rows], 0, "Eve, before reconciliation")
    viz.line(ax, rhos, [r["eve_bdr_post"] for r in rows], 1, "Eve, after using $W$")
    viz.line(ax, rhos, [r["bdr_retained"] for r in rows], 2, "legitimate UE-gNB")
    ax.axhline(0.5, color=viz.INK_MUTED, lw=0.9, ls=":")
    ax.annotate("0.5 = no information", (0.02, 0.505), color=viz.INK_MUTED,
                fontsize=8.5)
    ax.set_xlabel(r"eavesdropper CSI correlation $\rho$")
    ax.set_ylabel("bit disagreement rate")
    ax.set_title("Eve's bit error rate against $Z_B$")
    ax.set_ylim(-0.02, 0.58)
    ax.legend(loc="lower left")

    ax = axes[1]
    viz.line(ax, rhos, [100 * r["eve_recovers_z"] for r in rows], 0,
             r"Eve recovers $Z_B$")
    viz.line(ax, rhos, [100 * r["eve_key_match"] for r in rows], 3,
             r"Eve recovers $K_{PHY}$")
    ax.set_xlabel(r"eavesdropper CSI correlation $\rho$")
    ax.set_ylabel("success rate (%)")
    ax.set_title(f"Passive key-recovery success ({N} trials/point)")
    ax.set_ylim(-4, 104)
    ax.legend(loc="upper left")
    p = viz.save(fig, RESULTS / "fig_eve_correlation.png")
    print(f"  -> {p}")
    return rows


def part2_snr(pki: PKI) -> list:
    print("\n" + "=" * 78)
    print("PART 2b -- link SNR sweep (full protocol sessions)")
    print("=" * 78)
    snrs = [-10, -5, 0, 5, 10, 15, 20, 25, 30]
    rows = []
    for s in snrs:
        cfg = DEFAULT.with_phy(snr_db=s)
        est, gphy, kmatch, bdr, kdr = [], [], [], [], []
        for i in range(N_SESS):
            r = run_session(cfg, pki=pki, seed=70000 + 100 * s + i)
            est.append(r.established)
            gphy.append(r.g_phy)
            kmatch.append(r.keys_match)
            bdr.append(r.bdr_raw)
            kdr.append(r.kdr_post)
        m = sweep(lambda _: cfg, [s], N)[0]
        rows.append({"snr_db": s, "established": float(np.mean(est)),
                     "g_phy": float(np.mean(gphy)),
                     "keys_match": float(np.mean(kmatch)),
                     "bdr_retained": float(np.mean(bdr)),
                     "kdr_post": float(np.mean(kdr)),
                     "gate_entropy_ok": m["entropy_ok"],
                     "gate_snr_ok": m["snr_ok"], "r_u": m["r_u"],
                     "budget_bits": m["budget_bits"],
                     "h_min_total": m["h_min_total"]})
    print(f"{'SNR':>5} {'BDR':>8} {'KDR':>8} {'r_U':>7} {'snr_ok':>7} "
          f"{'ent_ok':>7} {'G_PHY':>7} {'estab.':>7} {'keys=':>7}")
    for r in rows:
        print(f"{r['snr_db']:>5} {r['bdr_retained']:>8.4f} "
              f"{r['kdr_post']:>8.4f} {r['r_u']:>7.1%} {r['gate_snr_ok']:>7.1%} "
              f"{r['gate_entropy_ok']:>7.1%} {r['g_phy']:>7.1%} "
              f"{r['established']:>7.1%} {r['keys_match']:>7.1%}")

    viz.use_style()
    fig, axes = viz.plt.subplots(1, 2, figsize=(10.5, 3.9))
    ax = axes[0]
    floor = 1e-5          # symlog floor: exact zeros are plotted at the axis base
    viz.line(ax, snrs, [max(r["bdr_retained"], floor) for r in rows], 0,
             "before reconciliation")
    viz.line(ax, snrs, [max(r["kdr_post"], floor) for r in rows], 1,
             "after reconciliation")
    ax.set_yscale("symlog", linthresh=1e-5)
    ax.axhline(DEFAULT.code.t / 255, color=viz.INK_MUTED, lw=0.9, ls=":")
    ax.annotate(f"BCH(255, 191, t=8) corrects {DEFAULT.code.t / 255:.3f}",
                (-10, 0.035), color=viz.INK_MUTED, fontsize=8.5)
    ax.annotate(r"exact 0 drawn at $10^{-5}$", (14, 2.6e-5),
                color=viz.INK_MUTED, fontsize=8.5)
    ax.set_ylim(0, 1.0)
    ax.set_xlabel("link SNR (dB)")
    ax.set_ylabel("bit / key disagreement rate (symlog)")
    ax.set_title("Reconciliation performance")
    ax.legend(loc="lower left")

    ax = axes[1]
    # 'established' and 'entropy budget' both sit near 100 %: give them
    # distinct dash patterns so a coincident series is never hidden.
    viz.line(ax, snrs, [100 * r["established"] for r in rows], 2,
             "session established", lw=3.0)
    viz.line(ax, snrs, [100 * r["gate_entropy_ok"] for r in rows], 3,
             "entropy budget alone", ls="--")
    viz.line(ax, snrs, [100 * r["g_phy"] for r in rows], 0, r"$G_{PHY}=1$")
    viz.line(ax, snrs, [100 * r["r_u"] for r in rows], 1,
             r"reconciliation check $r_U$", ls=":")
    ax.set_xlabel("link SNR (dB)")
    ax.set_ylabel("rate (%)")
    ax.set_title(f"Gate outcome vs. link quality ({N_SESS} sessions/point)")
    ax.set_ylim(-4, 108)
    ax.legend(loc="center left")
    p = viz.save(fig, RESULTS / "fig_snr.png")
    print(f"  -> {p}")
    return rows


def part2_mobility() -> list:
    print("\n" + "=" * 78)
    print("PART 2c -- mobility sweep (probe interval fixed at 12 ms)")
    print("=" * 78)
    speeds = [0.5, 1, 3, 8, 15, 25, 40]
    rows = sweep(lambda v: DEFAULT.with_phy(ue_speed_mps=v,
                                            probe_interval_us=12000.0),
                 speeds, N)
    print(f"{'v m/s':>6} {'f_d Hz':>8} {'BDR':>8} {'KDR':>8} {'lag1':>7} "
          f"{'H_inf':>8} {'G_PHY':>7}")
    for v, row in zip(speeds, rows):
        fd = v * DEFAULT.phy.carrier_hz / 299792458.0
        print(f"{v:>6.1f} {fd:>8.1f} {row['bdr_retained']:>8.4f} "
              f"{row['kdr_post']:>8.4f} {row['lag1_corr']:>7.3f} "
              f"{row['h_min_total']:>8.1f} {row['g_phy']:>7.1%}")

    viz.use_style()
    fig, axes = viz.plt.subplots(1, 2, figsize=(10.5, 3.9))
    ax = axes[0]
    viz.line(ax, speeds, [r["bdr_retained"] for r in rows], 0,
             "before reconciliation")
    viz.line(ax, speeds, [r["kdr_post"] for r in rows], 1,
             "after reconciliation")
    ax.set_xlabel("UE speed (m/s)")
    ax.set_ylabel("bit / key disagreement rate")
    ax.set_title("Reciprocity loss with mobility")
    ax.legend()
    ax = axes[1]
    viz.line(ax, speeds, [r["h_min_total"] for r in rows], 2,
             r"$H_\infty(Z)$ estimate")
    viz.line(ax, speeds, [r["budget_bits"] for r in rows], 3,
             "extractable budget")
    ax.axhline(DEFAULT.gate.target_phy_bits, color=viz.INK_MUTED, lw=0.9, ls=":")
    ax.annotate(f"L = {DEFAULT.gate.target_phy_bits} bits",
                (0.6, DEFAULT.gate.target_phy_bits + 14),
                color=viz.INK_MUTED, fontsize=8.5)
    ax.set_xlabel("UE speed (m/s)")
    ax.set_ylabel("bits")
    ax.set_title("Entropy budget with mobility")
    ax.legend()
    p = viz.save(fig, RESULTS / "fig_mobility.png")
    print(f"  -> {p}")
    return rows


def part2_pilot_spacing() -> list:
    print("\n" + "=" * 78)
    print("PART 2d -- pilot spacing: raw rate vs. real entropy")
    print("=" * 78)
    mults = [0.5, 1.0, 2.0, 3.0, 4.0, 6.0, 8.0]
    rows = sweep(lambda m: DEFAULT.with_phy(pilot_spacing_mult=m), mults, N)
    print(f"{'mult':>5} {'pilots':>7} {'samples':>8} {'lag1':>7} "
          f"{'H/sym':>7} {'H_inf':>8} {'leak':>6} {'budget':>8} {'G_PHY':>7}")
    for m, row in zip(mults, rows):
        cfg = DEFAULT.with_phy(pilot_spacing_mult=m)
        print(f"{m:>5.1f} {cfg.phy.n_pilots():>7} {row['n_samples']:>8.0f} "
              f"{row['lag1_corr']:>7.3f} {row['h_min_per_sym']:>7.3f} "
              f"{row['h_min_total']:>8.1f} {row['leak_bits']:>6.0f} "
              f"{row['budget_bits']:>8.1f} {row['g_phy']:>7.1%}")

    viz.use_style()
    fig, axes = viz.plt.subplots(1, 2, figsize=(10.5, 3.9))
    ax = axes[0]
    viz.line(ax, mults, [r["h_min_per_sym"] for r in rows], 0,
             r"min-entropy per sample")
    viz.line(ax, mults, [r["lag1_corr"] for r in rows], 1,
             r"lag-1 correlation")
    ax.set_xlabel(r"pilot spacing / coherence bandwidth")
    ax.set_ylabel("bits per sample  /  correlation")
    ax.set_title("Oversampling inflates the raw rate, not the entropy")
    ax.legend()
    ax = axes[1]
    viz.line(ax, mults, [r["h_min_total"] for r in rows], 0,
             r"$H_\infty(Z)$")
    viz.line(ax, mults, [r["leak_bits"] for r in rows], 1,
             r"syndrome leakage $|W|$")
    viz.line(ax, mults, [r["budget_bits"] for r in rows], 2,
             "extractable budget")
    ax.axhline(DEFAULT.gate.target_phy_bits, color=viz.INK_MUTED, lw=0.9, ls=":")
    ax.annotate(f"L = {DEFAULT.gate.target_phy_bits}",
                (3.6, DEFAULT.gate.target_phy_bits + 40), color=viz.INK_MUTED,
                fontsize=8.5)
    ax.set_xlabel(r"pilot spacing / coherence bandwidth")
    ax.set_ylabel("bits")
    ax.set_title("Entropy budget vs. pilot spacing")
    ax.legend()
    p = viz.save(fig, RESULTS / "fig_pilot_spacing.png")
    print(f"  -> {p}")
    return rows


def part2_code_and_guard() -> tuple:
    print("\n" + "=" * 78)
    print("PART 2e -- BCH strength and guard-band width")
    print("=" * 78)
    ts = [4, 8, 12, 16, 20, 24]
    rows_t = sweep(lambda t: DEFAULT.with_code(t=t), ts, N)
    print(f"{'t':>4} {'leak':>6} {'KDR':>8} {'recon ok':>9} {'budget':>8} "
          f"{'G_PHY':>7}")
    for t, row in zip(ts, rows_t):
        print(f"{t:>4} {row['leak_bits']:>6.0f} {row['kdr_post']:>8.5f} "
              f"{row['recon_ok']:>9.1%} {row['budget_bits']:>8.1f} "
              f"{row['g_phy']:>7.1%}")

    guards = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6]
    rows_g = sweep(lambda g: DEFAULT.with_quant(guard_band=g), guards, N)
    print(f"\n{'guard':>6} {'retained':>9} {'BDR':>8} {'KDR':>8} "
          f"{'H_inf':>8} {'budget':>8} {'G_PHY':>7}")
    for g, row in zip(guards, rows_g):
        print(f"{g:>6.2f} {row['retained_fraction']:>9.3f} "
              f"{row['bdr_retained']:>8.4f} {row['kdr_post']:>8.5f} "
              f"{row['h_min_total']:>8.1f} {row['budget_bits']:>8.1f} "
              f"{row['g_phy']:>7.1%}")

    viz.use_style()
    fig, axes = viz.plt.subplots(1, 2, figsize=(10.5, 3.9))
    ax = axes[0]
    viz.line(ax, ts, [r["h_min_total"] for r in rows_t], 0,
             r"$H_\infty(Z)$")
    viz.line(ax, ts, [r["leak_bits"] for r in rows_t], 1,
             r"syndrome leakage $|W|$")
    viz.line(ax, ts, [r["budget_bits"] for r in rows_t], 2,
             "extractable budget")
    ax.axhline(DEFAULT.gate.target_phy_bits, color=viz.INK_MUTED, lw=0.9, ls=":")
    ax.axhline(0.0, color=viz.INK_MUTED, lw=0.9)
    ax.annotate(f"L = {DEFAULT.gate.target_phy_bits} bits",
                (17.5, DEFAULT.gate.target_phy_bits + 30),
                color=viz.INK_MUTED, fontsize=8.5)
    ax.set_xticks(ts)
    ax.set_xlabel("BCH designed error capability $t$   (n = 255)")
    ax.set_ylabel("bits")
    ax.set_title("Choosing the sketch: correction vs. leakage\n"
                 "(reconciliation succeeded for every $t$ at 20 dB)",
                 fontsize=10)
    ax.legend(loc="lower left")
    ax = axes[1]
    viz.line(ax, guards, [r["bdr_retained"] for r in rows_g], 0,
             "BDR of retained bits")
    viz.line(ax, guards, [r["retained_fraction"] for r in rows_g], 1,
             "retained fraction")
    viz.line(ax, guards, [r["g_phy"] for r in rows_g], 2, r"$G_{PHY}=1$ rate")
    ax.set_xlabel("guard-band half-width (normalised std)")
    ax.set_ylabel("rate")
    ax.set_title("Guard band trades samples for reliability")
    ax.legend(loc="center right")
    p = viz.save(fig, RESULTS / "fig_code_guard.png")
    print(f"  -> {p}")
    return rows_t, rows_g


def main() -> dict:
    RESULTS.mkdir(exist_ok=True)
    pki = PKI.build()
    attacks = part1_attacks(pki)
    out = {
        "attacks": [{"name": r.name, "ok": r.ok, "observed": r.observed,
                     "stage": r.stage, "reason": r.reason, "extra": r.extra}
                    for r in attacks],
        "attacks_passed": sum(r.ok for r in attacks),
        "attacks_total": len(attacks),
        "eve_correlation": part2_eve_correlation(),
        "snr": part2_snr(pki),
        "mobility": part2_mobility(),
        "pilot_spacing": part2_pilot_spacing(),
    }
    rows_t, rows_g = part2_code_and_guard()
    out["code_t"] = rows_t
    out["guard_band"] = rows_g
    (RESULTS / "security.json").write_text(json.dumps(out, indent=2,
                                                      default=str))
    print(f"\nwrote {RESULTS / 'security.json'}")
    return out


if __name__ == "__main__":
    main()
