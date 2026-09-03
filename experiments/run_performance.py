"""Experiment 3 -- performance evaluation.

1.  per-step computation latency of the full handshake;
2.  where the wall-clock time actually goes (computation vs. the sounding
    campaign, which is set by the coherence time);
3.  on-the-wire cost, hybrid vs. an authenticated PQC-only baseline;
4.  micro-benchmarks of every cryptographic primitive;
5.  cost of the physical-layer pipeline as a function of campaign size;
6.  AEAD data-plane throughput.
"""

from __future__ import annotations

import json
import pathlib
import statistics as st
import sys
import time

import numpy as np

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from hpls import viz                                                # noqa: E402
from hpls.bch import get_bch                                        # noqa: E402
from hpls.config import DEFAULT                                     # noqa: E402
from hpls.entropy import analyse                                    # noqa: E402
from hpls.gate import privacy_amplify                               # noqa: E402
from hpls.primitives import (AEAD, H, KEM, Sig, hkdf_expand,        # noqa: E402
                             hkdf_extract, mac, rand_bytes)
from hpls.probing import ProbeContext, estimate                     # noqa: E402
from hpls.protocol import (DIR_UE, DataPlane, PKI, run_session,     # noqa: E402
                           run_pqc_only_session)
from hpls.channel import RadioWorld                                 # noqa: E402
from hpls.quantize import quantize                                  # noqa: E402
from hpls.reconcile import reconcile, reconcile_helper              # noqa: E402

RESULTS = pathlib.Path(__file__).resolve().parents[1] / "results"
QUICK = "--quick" in sys.argv
N = 8 if QUICK else 30

STEP_GROUPS = [
    ("Step 1  UE sign + gNB verify", ["step1_ue", "step1_gnb"]),
    ("Step 2  probing + estimation", ["step2_ue", "step2_gnb"]),
    ("Step 3  KEM + helper + sign/verify", ["step3_gnb", "step3_ue"]),
    ("Step 4  quantise + reconcile + gate", ["step4_ue_local", "step4_gnb_local",
                                             "step4_ue_conf", "step4_ue_send",
                                             "step4_gnb_recv", "step4_ue_recv"]),
    ("Step 5  hybrid key schedule", ["step5_ue", "step5_gnb"]),
    ("Step 6  key confirmation", ["step6_ue_send", "step6_gnb_recv",
                                  "step6_gnb_send", "step6_ue_recv"]),
]


def bench(fn, n: int = 50) -> tuple[float, float]:
    """Returns (mean ms, p95 ms)."""
    ts = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        ts.append((time.perf_counter() - t0) * 1e3)
    return float(st.mean(ts)), float(np.percentile(ts, 95))


def part1_handshake_latency(pki: PKI) -> dict:
    print("\n" + "=" * 78)
    print(f"PART 1 -- handshake computation latency ({N} sessions)")
    print("=" * 78)
    runs, sizes, gphy = [], [], []
    for i in range(N):
        r = run_session(DEFAULT, pki=pki, seed=90000 + i)
        assert r.established and r.keys_match, "handshake did not complete"
        runs.append(r.step_ms)
        sizes.append(r.sizes)
        gphy.append(r.g_phy)
    print(f"all {N} sessions established; G_PHY = 1 in "
          f"{100 * float(np.mean(gphy)):.1f} % of them "
          f"(the rest fell back to the PQC-only baseline)")
    keys = sorted({k for r in runs for k in r})
    per_step = {k: [r.get(k, 0.0) for r in runs] for k in keys}

    print(f"{'operation':<24}{'mean ms':>10}{'p95 ms':>10}")
    for k in keys:
        print(f"{k:<24}{st.mean(per_step[k]):>10.2f}"
              f"{np.percentile(per_step[k], 95):>10.2f}")

    grouped = {}
    for label, members in STEP_GROUPS:
        vals = [sum(r.get(m, 0.0) for m in members) for r in runs]
        grouped[label] = {"mean_ms": float(st.mean(vals)),
                          "p95_ms": float(np.percentile(vals, 95))}
    total = [sum(r.values()) for r in runs]
    print(f"\n{'group':<40}{'mean ms':>10}{'p95 ms':>10}")
    for label, v in grouped.items():
        print(f"{label:<40}{v['mean_ms']:>10.2f}{v['p95_ms']:>10.2f}")
    print(f"{'TOTAL handshake computation':<40}{st.mean(total):>10.2f}"
          f"{np.percentile(total, 95):>10.2f}")

    probe_ms = (DEFAULT.phy.n_probe_rounds
                * DEFAULT.phy.effective_probe_interval_us() / 1e3)
    print(f"\nsounding campaign wall time            {probe_ms:>10.1f} ms"
          f"   ({DEFAULT.phy.n_probe_rounds} rounds x "
          f"{DEFAULT.phy.effective_probe_interval_us()/1e3:.1f} ms "
          f"= {DEFAULT.phy.n_probe_rounds} coherence times)")
    print(f"=> the handshake is dominated by the radio campaign, not by "
          f"cryptography ({100*probe_ms/(probe_ms+st.mean(total)):.1f} % of "
          f"the total)")

    viz.use_style()
    fig, ax = viz.plt.subplots(figsize=(8.4, 3.8))
    labels = [lbl.replace("  ", ": ") for lbl, _ in STEP_GROUPS][::-1]
    means = [grouped[lbl]["mean_ms"] for lbl, _ in STEP_GROUPS][::-1]
    y = np.arange(len(labels))
    ax.barh(y, means, height=0.66, color=viz.SERIES[0],
            edgecolor=viz.SURFACE, linewidth=1.2)
    for yi, v in zip(y, means):
        ax.annotate(f"{v:.1f} ms", (v, yi), xytext=(5, 0),
                    textcoords="offset points", va="center",
                    color=viz.INK_2, fontsize=8.5)
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=8.5)
    ax.set_xlabel("computation time (ms)")
    ax.set_xlim(0, max(means) * 1.18)
    ax.grid(axis="y", visible=False)
    ax.set_title(f"Handshake computation: {st.mean(total):.0f} ms total\n"
                 f"(the {probe_ms:.0f} ms sounding campaign, set by the "
                 f"coherence time, dominates the wall clock)", fontsize=10)
    p = viz.save(fig, RESULTS / "fig_latency_steps.png")
    print(f"  -> {p}")
    return {"per_step_ms": {k: {"mean": float(st.mean(v)),
                                "p95": float(np.percentile(v, 95))}
                            for k, v in per_step.items()},
            "grouped_ms": grouped,
            "total_compute_ms": {"mean": float(st.mean(total)),
                                 "p95": float(np.percentile(total, 95))},
            "probe_campaign_ms": probe_ms,
            "g_phy_rate": float(np.mean(gphy)),
            "sizes": sizes[0]}


def part2_wire_cost(pki: PKI) -> dict:
    print("\n" + "=" * 78)
    print("PART 2 -- on-the-wire cost vs. authenticated PQC-only baseline")
    print("=" * 78)
    hyb = run_session(DEFAULT, pki=pki, seed=91000)
    base = run_pqc_only_session(DEFAULT, pki=pki)
    h, b = hyb.sizes, base["sizes"]
    rows = [("flight 1  m1,sigma_U,Cert_U", b["flight1"], h["flight1"]),
            ("flight 2  m2,sigma_B,Cert_B", b["flight2"], h["flight2"]),
            ("  of which helper data W", 0, h["W"]),
            ("(r, v_B) reconciliation check", 0, h["mconf"]),
            ("flight 3  m3,tau_3", 0, h["flight3"]),
            ("flight 4  m4,tau_4", 0, h["flight4"]),
            ("fin_U", b["fin_u"], h["fin_u"]),
            ("fin_B", b["fin_b"], h["fin_b"]),
            ("TOTAL", b["handshake_total"], h["handshake_total"])]
    print(f"{'message':<34}{'PQC-only B':>12}{'hybrid B':>10}{'delta':>9}")
    for name, bb, hh in rows:
        print(f"{name:<34}{bb:>12}{hh:>10}{hh - bb:>+9}")
    over = h["handshake_total"] - b["handshake_total"]
    print(f"\nPHY augmentation overhead: {over} B "
          f"({100 * over / b['handshake_total']:.1f} % of the PQC-only "
          f"handshake)")
    print(f"certificates alone account for "
          f"{pki.cert_u.size() + pki.cert_b.size()} B "
          f"({Sig.name} keys + signatures)")

    # Two linear panels: bars encode magnitude by length, so no log axis.
    viz.use_style()
    fig, axes = viz.plt.subplots(1, 2, figsize=(10.0, 3.8),
                                 gridspec_kw={"width_ratios": [1, 1.25]})
    ax = axes[0]
    ax.bar([0, 1], [b["handshake_total"] / 1024, h["handshake_total"] / 1024],
           width=0.55, color=[viz.SERIES[0], viz.SERIES[1]],
           edgecolor=viz.SURFACE, linewidth=1.2)
    for xi, v in enumerate([b["handshake_total"], h["handshake_total"]]):
        ax.annotate(f"{v / 1024:.2f} KiB", (xi, v / 1024), xytext=(0, 4),
                    textcoords="offset points", ha="center",
                    color=viz.INK_2, fontsize=9)
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["PQC-only\nbaseline", "hybrid\nPQC-PLS"], fontsize=9)
    ax.set_ylabel("total handshake (KiB)")
    ax.set_ylim(0, h["handshake_total"] / 1024 * 1.16)
    ax.grid(axis="x", visible=False)
    ax.set_title(f"Total handshake: +{over} B "
                 f"({100 * over / b['handshake_total']:.1f} %)", fontsize=10)

    ax = axes[1]
    comp = [("helper data $W$ (in $m_2$)", h["W"]),
            ("$(r, v_B)$ check", h["mconf"]),
            ("flight 4  $m_4, \\tau_4$", h["flight4"]),
            ("flight 3  $m_3, \\tau_3$", h["flight3"])]
    y = np.arange(len(comp))
    ax.barh(y, [c[1] for c in comp], height=0.62, color=viz.SERIES[1],
            edgecolor=viz.SURFACE, linewidth=1.2)
    for yi, (_, v) in zip(y, comp):
        ax.annotate(f"{v} B", (v, yi), xytext=(5, 0),
                    textcoords="offset points", va="center",
                    color=viz.INK_2, fontsize=8.5)
    ax.set_yticks(y)
    ax.set_yticklabels([c[0] for c in comp], fontsize=8.5)
    ax.set_xlabel("bytes")
    ax.set_xlim(0, max(c[1] for c in comp) * 1.2)
    ax.grid(axis="y", visible=False)
    ax.set_title("What the PHY branch adds", fontsize=10)
    p = viz.save(fig, RESULTS / "fig_wire_cost.png")
    print(f"  -> {p}")
    return {"pqc_only": b, "hybrid": h, "overhead_bytes": over,
            "overhead_pct": 100 * over / b["handshake_total"],
            "pqc_only_compute_ms": base["compute_ms"]}


def part3_primitives() -> dict:
    print("\n" + "=" * 78)
    print("PART 3 -- cryptographic primitive micro-benchmarks")
    print("=" * 78)
    pk, sk = KEM.keygen()
    ct, ss = KEM.encaps(pk)
    spk, ssk = Sig.keygen()
    msg = rand_bytes(32)
    sig = Sig.sign(ssk, msg)
    key = rand_bytes(32)
    blob_1k = rand_bytes(1024)
    z = np.random.default_rng(0).integers(0, 2, 765).astype(np.uint8)
    code = get_bch(DEFAULT.code.m, DEFAULT.code.t)
    blk = z[:code.n]
    syn = code.sketch(blk)
    err = np.zeros(code.n, dtype=np.uint8)
    err[[3, 40, 91, 150, 200, 210, 233, 250]] = 1
    diff = code.sketch(blk ^ err) ^ syn

    items = [
        (f"{KEM.name} KeyGen", lambda: KEM.keygen(), ""),
        (f"{KEM.name} Encaps", lambda: KEM.encaps(pk), f"ct {KEM.ct_len} B"),
        (f"{KEM.name} Decaps", lambda: KEM.decaps(sk, ct), ""),
        (f"{Sig.name} KeyGen", lambda: Sig.keygen(), ""),
        (f"{Sig.name} Sign", lambda: Sig.sign(ssk, msg),
         f"sig {Sig.sig_len} B"),
        (f"{Sig.name} Verify", lambda: Sig.verify(spk, msg, sig), ""),
        ("SHA3-256 (1 KiB)", lambda: H(blob_1k), ""),
        ("HKDF-Extract+Expand", lambda: hkdf_expand(
            hkdf_extract(msg, key), b"info", 152), ""),
        ("HMAC-SHA-256 tag", lambda: mac(key, "UE-GATE", msg, msg), ""),
        ("AES-256-GCM seal 1 KiB", lambda: AEAD.seal(
            key, rand_bytes(12), (b"sid", 0), blob_1k), ""),
        (f"BCH({code.n},{code.k}) sketch", lambda: code.sketch(blk), ""),
        (f"BCH({code.n},{code.k}) decode t={code.t}",
         lambda: code.decode_syndrome(diff), ""),
    ]
    print(f"{'primitive':<34}{'mean ms':>10}{'p95 ms':>10}  note")
    out = {}
    for name, fn, note in items:
        m, p95 = bench(fn, 30 if "KeyGen" in name or "BCH" in name else 60)
        out[name] = {"mean_ms": m, "p95_ms": p95}
        print(f"{name:<34}{m:>10.3f}{p95:>10.3f}  {note}")
    return out


def part4_phy_pipeline() -> dict:
    print("\n" + "=" * 78)
    print("PART 4 -- physical-layer pipeline cost vs. campaign size")
    print("=" * 78)
    mults = [1.0, 2.0, 3.0, 4.0, 6.0]
    rows = []
    for m in mults:
        cfg = DEFAULT.with_phy(pilot_spacing_mult=m)
        world = RadioWorld(cfg.phy, seed=42)
        ctx = ProbeContext.derive(b"s" * 16, b"n" * 32, cfg.phy)
        y_u = estimate(world, "U", ctx)
        y_b = estimate(world, "B", ctx)
        q_b = quantize(y_b.feat, cfg.quant)
        q_u = quantize(y_u.feat, cfg.quant)
        W = reconcile_helper(q_b, cfg.code, cfg.quant)
        z_b, lv = W.select(q_b)
        t_est, _ = bench(lambda: estimate(world, "B", ctx), 10)
        t_q, _ = bench(lambda: quantize(y_b.feat, cfg.quant), 20)
        t_h, _ = bench(lambda: reconcile_helper(q_b, cfg.code, cfg.quant), 10)
        t_r, _ = bench(lambda: reconcile(q_u, W), 10)
        t_e, _ = bench(lambda: analyse(lv, 1 << cfg.quant.bits_per_sample), 10)
        t_pa, _ = bench(lambda: privacy_amplify(z_b, b"t2" * 16, 128), 10)
        rows.append({"mult": m, "n_samples": int(q_b.levels.size),
                     "n_bits": W.n_bits, "estimate_ms": t_est,
                     "quantize_ms": t_q, "helper_ms": t_h, "reconcile_ms": t_r,
                     "entropy_ms": t_e, "pa_ms": t_pa,
                     "total_ms": t_est + t_q + t_h + t_r + t_e + t_pa})
    print(f"{'mult':>5}{'samples':>9}{'Z bits':>8}{'estim.':>9}{'quant':>8}"
          f"{'sketch':>8}{'decode':>8}{'H_inf':>8}{'PA':>8}{'total':>9}")
    for r in rows:
        print(f"{r['mult']:>5.1f}{r['n_samples']:>9}{r['n_bits']:>8}"
              f"{r['estimate_ms']:>9.2f}{r['quantize_ms']:>8.2f}"
              f"{r['helper_ms']:>8.2f}{r['reconcile_ms']:>8.2f}"
              f"{r['entropy_ms']:>8.2f}{r['pa_ms']:>8.2f}{r['total_ms']:>9.2f}")

    viz.use_style()
    fig, ax = viz.plt.subplots(figsize=(8.6, 4.0))
    x = [r["n_bits"] for r in rows]
    viz.line(ax, x, [r["reconcile_ms"] for r in rows], 0,
             "reconciliation (BCH decode)")
    viz.line(ax, x, [r["helper_ms"] for r in rows], 1, "sketch (helper data)")
    viz.line(ax, x, [r["estimate_ms"] for r in rows], 2, "channel estimation")
    viz.line(ax, x, [r["pa_ms"] for r in rows], 3, "privacy amplification")
    ax.set_xlabel(r"length of the retained string $|Z|$ (bits)")
    ax.set_ylabel("time (ms)")
    ax.set_title("Physical-layer pipeline cost (pure Python reference "
                 "implementation)")
    ax.legend()
    p = viz.save(fig, RESULTS / "fig_phy_pipeline.png")
    print(f"  -> {p}")
    return {"rows": rows}


def part5_data_plane(pki: PKI) -> dict:
    print("\n" + "=" * 78)
    print("PART 5 -- AEAD data-plane throughput")
    print("=" * 78)
    r = run_session(DEFAULT, pki=pki, seed=92000)
    dp_u = DataPlane(r.ue.st["sid"], r.keys)
    dp_b = DataPlane(r.gnb.st["sid"], r.gnb.st["keys"])
    rows = []
    for size in (64, 256, 1024, 1400, 8192):
        payload = rand_bytes(size)
        n = 2000 if size <= 1400 else 500
        for _ in range(50):                       # warm-up
            dp_b.recv(DIR_UE, dp_u.send(DIR_UE, payload))
        t0 = time.perf_counter()
        for _ in range(n):
            rec = dp_u.send(DIR_UE, payload)
            dp_b.recv(DIR_UE, rec)
        dt = time.perf_counter() - t0
        mbps = n * size / dt / 1e6
        aead = len(rec.ct) - size                 # GCM tag
        framing = rec.size() - len(rec.ct)        # simulator TLV framing
        rows.append({"record_bytes": size, "records_per_s": n / dt,
                     "throughput_MBps": mbps, "aead_tag_bytes": aead,
                     "framing_bytes": framing,
                     "aead_overhead_pct": 100 * aead / size})
        print(f"  {size:>5} B payload: {n/dt:>9.0f} records/s, "
              f"{mbps:>6.1f} MB/s seal+open, +{aead} B GCM tag "
              f"({100*aead/size:.1f} %)"
              f" [+{framing} B simulator TLV framing]")
    print("  note: a deployment carries sid/counter in the PDCP header, so "
          "the real per-record expansion is the 16 B GCM tag")
    return {"rows": rows}


def main() -> dict:
    RESULTS.mkdir(exist_ok=True)
    pki = PKI.build()
    out = {"latency": part1_handshake_latency(pki),
           "wire": part2_wire_cost(pki),
           "primitives": part3_primitives(),
           "phy_pipeline": part4_phy_pipeline(),
           "data_plane": part5_data_plane(pki)}
    (RESULTS / "performance.json").write_text(json.dumps(out, indent=2,
                                                         default=str))
    print(f"\nwrote {RESULTS / 'performance.json'}")
    return out


if __name__ == "__main__":
    main()
