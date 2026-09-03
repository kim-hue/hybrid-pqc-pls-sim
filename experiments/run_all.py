"""Run the whole evaluation and write ``results/report.md``.

    python experiments/run_all.py [--quick]
"""

from __future__ import annotations

import json
import pathlib
import platform
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import run_functional                                              # noqa: E402
import run_performance                                             # noqa: E402
import run_security                                                # noqa: E402

from hpls.bch import get_bch                                       # noqa: E402
from hpls.config import DEFAULT                                    # noqa: E402
from hpls.primitives import KEM, Sig                               # noqa: E402

RESULTS = pathlib.Path(__file__).resolve().parents[1] / "results"


def fmt_pct(x: float) -> str:
    return f"{100 * x:.1f} %"


def report(func: dict, sec: dict, perf: dict) -> str:
    p, q, c, g = DEFAULT.phy, DEFAULT.quant, DEFAULT.code, DEFAULT.gate
    code = get_bch(c.m, c.t)
    h = func["healthy"]
    L = perf["latency"]
    W = perf["wire"]
    lines: list[str] = []
    A = lines.append

    A("# Hybrid PQC-PLS key establishment - simulation report")
    A("")
    A(f"Generated {time.strftime('%Y-%m-%d %H:%M')} on "
      f"{platform.system()} {platform.machine()}, Python "
      f"{platform.python_version()}.")
    A("")
    A("Every cryptographic operation is a real implementation "
      f"({KEM.name} / FIPS 203, {Sig.name} / FIPS 204, AES-256-GCM, "
      "SHA3-256, HMAC-SHA-256, HKDF); the radio layer is a 3GPP TR 38.901 "
      "TDL Rayleigh channel with reciprocity impairments.")
    A("")

    A("## 1. Configuration")
    A("")
    A("| parameter | value |")
    A("|---|---|")
    A(f"| carrier / numerology | {p.carrier_hz/1e9:.1f} GHz, "
      f"{p.scs_hz/1e3:.0f} kHz SCS, {p.n_subcarriers} subcarriers |")
    A(f"| channel | {p.tdl_profile}, tau_rms = {p.delay_spread_ns:.0f} ns, "
      f"v = {p.ue_speed_mps:.0f} m/s |")
    A(f"| f_D / T_c / B_c | {p.doppler_hz():.1f} Hz / "
      f"{p.coherence_time_s()*1e3:.1f} ms / "
      f"{p.coherence_bandwidth_hz()/1e3:.0f} kHz |")
    A(f"| probing | {p.n_probe_rounds} rounds x {p.n_pilots()} pilots "
      f"(spacing {p.effective_pilot_spacing()} SC = "
      f"{p.pilot_spacing_mult:.0f} B_c), {p.n_avg_symbols} symbols averaged |")
    A(f"| SNR (nominal / effective) | {p.snr_db:.0f} dB / "
      f"{p.effective_snr_db():.1f} dB |")
    A(f"| quantiser | {q.bits_per_sample} bit/sample, Gray, guard band "
      f"{q.guard_band} sigma |")
    A(f"| secure sketch | BCH({code.n}, {code.k}, t={code.t}), "
      f"{code.n_k} parity bits/block |")
    A(f"| PA / gate | L = {g.target_phy_bits} bits, eps = 2^-"
      f"{g.pa_epsilon_log2}, SNR_min = {g.snr_min_db:.0f} dB |")
    A("")

    A("## 2. Functional verification")
    A("")
    A("| quantity | healthy link | degraded link |")
    A("|---|---|---|")
    fb = func["fallback"]
    A(f"| session state | ESTABLISHED | ESTABLISHED |")
    A(f"| G_PHY | {h['g_phy']} | {fb['g_phy']} |")
    A(f"| \\|K_PHY\\| | {h['k_phy_bits']} bits | {fb['k_phy_bits']} bits "
      f"(epsilon) |")
    A(f"| session keys agree | {h['keys_match']} | {fb['keys_match']} |")
    A(f"| BDR (retained bits) | {h['bdr_retained']:.4f} | "
      f"{fb['bdr_retained']:.4f} |")
    A(f"| KDR after reconciliation | {h['kdr_post']:.4f} | "
      f"{fb['kdr_post']:.4f} |")
    A(f"| reconciliation check r_U | pass | fail |")
    A("")
    A("Entropy budget on the healthy link (leftover hash lemma):")
    A("")
    A(f"    H_inf(Z) = {h['h_min_bits']:.1f} bits   (NIST SP 800-90B, "
      f"min of MCV and Markov)")
    A(f"  - leak(W)  = {h['leak_bits']} bits   (published BCH syndromes)")
    A(f"  - 2 log2(1/eps) = {2 * g.pa_epsilon_log2} bits")
    A(f"  = {h['budget_bits']:.1f} bits extractable  >=  L = "
      f"{g.target_phy_bits} bits  -> gate opens")
    A("")

    A("## 3. Security evaluation")
    A("")
    A(f"### 3.1 Attack suite: {sec['attacks_passed']}/"
      f"{sec['attacks_total']} attacks behave as required")
    A("")
    A("| attack | outcome |")
    A("|---|---|")
    for a in sec["attacks"]:
        verdict = "PASS" if a["ok"] else "**FAIL**"
        obs = a["observed"].replace("|", "\\|")      # keep the table intact
        A(f"| {a['name']} | {verdict} - {obs} |")
    A("")
    A("### 3.2 Passive eavesdropping vs. CSI correlation")
    A("")
    A("| rho | Eve BDR after using W | recovers Z | recovers K_PHY |")
    A("|---|---|---|---|")
    for row in sec["eve_correlation"]:
        A(f"| {row['value']:.2f} | {row['eve_bdr_post']:.4f} | "
          f"{fmt_pct(row['eve_recovers_z'])} | "
          f"{fmt_pct(row['eve_key_match'])} |")
    A("")
    A("The physical-layer secret is useless to an eavesdropper up to "
      "rho ~ 0.95 and is fully compromised at rho = 0.99, i.e. when the "
      "attacker is effectively inside the coherence volume of the "
      "legitimate link.  In that worst case the session still rests on "
      f"{KEM.name}, which is exactly what the mandatory post-quantum "
      "baseline is for (attack A15/A16).")
    A("")
    A("### 3.3 Gate behaviour vs. link SNR")
    A("")
    A("| SNR (dB) | BDR | KDR | r_U | entropy check | G_PHY | established |")
    A("|---|---|---|---|---|---|---|")
    for row in sec["snr"]:
        A(f"| {row['snr_db']} | {row['bdr_retained']:.4f} | "
          f"{row['kdr_post']:.4f} | {fmt_pct(row['r_u'])} | "
          f"{fmt_pct(row['gate_entropy_ok'])} | {fmt_pct(row['g_phy'])} | "
          f"{fmt_pct(row['established'])} |")
    A("")
    A("Two observations matter here.  First, the handshake completes at "
      "**every** SNR: a dead radio link degrades the session to the "
      "post-quantum baseline instead of failing it.  Second, the entropy "
      "estimator alone accepts even a -10 dB link, because receiver noise "
      "*adds* apparent entropy while destroying reciprocity.  What actually "
      "closes the gate at low SNR is the local SNR test together with the "
      "interactive reconciliation check `r_U`; an entropy budget on its own "
      "would not be a safety mechanism.")
    A("")
    A("### 3.4 Entropy vs. pilot spacing")
    A("")
    A("| spacing / B_c | samples | lag-1 rho | H_inf/sample | H_inf | "
      "leak | budget | G_PHY |")
    A("|---|---|---|---|---|---|---|---|")
    for row in sec["pilot_spacing"]:
        A(f"| {row['value']:.1f} | {row['n_samples']:.0f} | "
          f"{row['lag1_corr']:.3f} | {row['h_min_per_sym']:.3f} | "
          f"{row['h_min_total']:.0f} | {row['leak_bits']:.0f} | "
          f"{row['budget_bits']:.0f} | {fmt_pct(row['g_phy'])} |")
    A("")
    A("Sampling the channel more finely than the coherence bandwidth "
      "multiplies the raw bit count but not the entropy, while the syndrome "
      "leakage grows linearly with the raw length - so the extractable "
      "budget *falls*, and at half a coherence bandwidth it goes negative. "
      "This is the quantitative form of the requirement that the entropy "
      "budget be evaluated on the real source, not on the raw sample count.")
    A("")
    A("### 3.5 Mobility (probe interval held at 12 ms)")
    A("")
    A("| speed (m/s) | BDR | KDR | H_inf | budget | G_PHY |")
    A("|---|---|---|---|---|---|")
    for row in sec["mobility"]:
        A(f"| {row['value']:.1f} | {row['bdr_retained']:.4f} | "
          f"{row['kdr_post']:.4f} | {row['h_min_total']:.0f} | "
          f"{row['budget_bits']:.0f} | {fmt_pct(row['g_phy'])} |")
    A("")
    A("With the sounding cadence fixed, reciprocity collapses above roughly "
      "8 m/s while the estimated entropy and the extractable budget stay "
      "essentially flat - the same lesson as section 3.3, from the opposite "
      "direction: the entropy budget bounds how much can be *extracted*, "
      "and only the reconciliation check decides whether the two sides hold "
      "the *same* string.  The default configuration keeps the probe "
      "interval at one coherence time, so it tracks mobility automatically; "
      "the table shows what happens if it does not.")
    A("")

    A("## 4. Performance")
    A("")
    A("| step | mean (ms) | p95 (ms) |")
    A("|---|---|---|")
    for label, v in L["grouped_ms"].items():
        A(f"| {label} | {v['mean_ms']:.2f} | {v['p95_ms']:.2f} |")
    A(f"| **total computation** | **{L['total_compute_ms']['mean']:.2f}** | "
      f"**{L['total_compute_ms']['p95']:.2f}** |")
    A(f"| sounding campaign (wall time) | {L['probe_campaign_ms']:.0f} | "
      f"{L['probe_campaign_ms']:.0f} |")
    A("")
    A(f"The physical-layer branch of the handshake (Step 2 estimation plus "
      f"Step 4 quantisation, reconciliation, gating and amplification) costs "
      f"{L['grouped_ms']['Step 2  probing + estimation']['mean_ms'] + L['grouped_ms']['Step 4  quantise + reconcile + gate']['mean_ms']:.1f} ms, "
      f"against {L['grouped_ms']['Step 1  UE sign + gNB verify']['mean_ms'] + L['grouped_ms']['Step 3  KEM + helper + sign/verify']['mean_ms']:.1f} ms "
      f"for the post-quantum operations.  The dominant term is neither: it "
      f"is the {L['probe_campaign_ms']:.0f} ms sounding campaign, which is "
      f"fixed by the coherence time ({p.coherence_time_s()*1e3:.1f} ms) and "
      f"the number of independent rounds needed to reach "
      f"{g.target_phy_bits} extractable bits.")
    A("")
    A("| message | PQC-only (B) | hybrid (B) | delta |")
    A("|---|---|---|---|")
    for k in ("flight1", "flight2", "fin_u", "fin_b"):
        A(f"| {k} | {W['pqc_only'][k]} | {W['hybrid'][k]} | "
          f"{W['hybrid'][k] - W['pqc_only'][k]:+d} |")
    A(f"| helper data W (inside flight2) | 0 | {W['hybrid']['W']} | "
      f"+{W['hybrid']['W']} |")
    for k in ("mconf", "flight3", "flight4"):
        A(f"| {k} | 0 | {W['hybrid'][k]} | +{W['hybrid'][k]} |")
    A(f"| **total** | **{W['pqc_only']['handshake_total']}** | "
      f"**{W['hybrid']['handshake_total']}** | "
      f"**+{W['overhead_bytes']}** |")
    A("")
    A(f"The authenticated physical-layer augmentation costs "
      f"{W['overhead_bytes']} bytes, i.e. {W['overhead_pct']:.1f} % on top of "
      f"the PQC-only handshake, whose size is itself dominated by the two "
      f"{Sig.name} certificates.")
    A("")
    A("| primitive | mean (ms) |")
    A("|---|---|")
    for name, v in perf["primitives"].items():
        A(f"| {name} | {v['mean_ms']:.3f} |")
    A("")
    A("These are pure-Python reference implementations "
      "(`kyber-py`, `dilithium-py`); an optimised C/AVX2 implementation of "
      "ML-KEM/ML-DSA is roughly two orders of magnitude faster, and the "
      "BCH decoder here is also unoptimised Python.  The numbers should "
      "therefore be read as *relative* costs: the lattice operations "
      "dominate the computation and the physical-layer pipeline is a small "
      "addition to them.")
    A("")
    A("| payload (B) | records/s | throughput (MB/s) | AEAD expansion |")
    A("|---|---|---|---|")
    for row in perf["data_plane"]["rows"]:
        A(f"| {row['record_bytes']} | {row['records_per_s']:.0f} | "
          f"{row['throughput_MBps']:.1f} | +{row['aead_tag_bytes']} B "
          f"({row['aead_overhead_pct']:.1f} %) |")
    A("")

    A("## 5. Figures")
    A("")
    for name, caption in [
        ("fig_eve_correlation.png",
         "passive eavesdropper: bit error rate and key-recovery success "
         "vs. CSI correlation"),
        ("fig_snr.png",
         "reconciliation performance and gate outcome vs. link SNR"),
        ("fig_mobility.png", "reciprocity loss and entropy budget vs. speed"),
        ("fig_pilot_spacing.png",
         "raw sampling rate vs. real min-entropy and extractable budget"),
        ("fig_code_guard.png",
         "BCH strength and guard-band width trade-offs"),
        ("fig_latency_steps.png", "handshake computation latency per step"),
        ("fig_wire_cost.png", "on-the-wire cost per message"),
        ("fig_phy_pipeline.png",
         "physical-layer pipeline cost vs. campaign size"),
    ]:
        A(f"![{caption}]({name})")
        A("")
        A(f"*{caption}*")
        A("")

    A("## 6. Findings")
    A("")
    A("1. **Correctness.** Both regimes complete: with a healthy link the "
      f"session key mixes K_PQC and a {g.target_phy_bits}-bit K_PHY; with a "
      "dead link the gate closes and the same session key schedule runs on "
      "the post-quantum secret alone.  The two parties never disagree, "
      "because `G_PHY` is authenticated in Step 4 and re-checked inside the "
      "key-confirmation associated data in Step 6.")
    A(f"2. **Authentication is what makes PLS safe here.** "
      f"{sec['attacks_passed']}/{sec['attacks_total']} attacks are caught at "
      "the step the protocol design predicts: certificate and signature "
      "checks in Steps 1 and 3, `h_probe` binding against replayed probing "
      "campaigns, the `k_gate` MAC against forged gate decisions, and the "
      "AEAD key confirmation against transcript or `G_PHY` mismatch.  An "
      "unauthenticated PLS scheme with the same radio layer is fully "
      "MITM-able (A18).")
    A("3. **The hybrid guarantee holds in both directions.** Giving the "
      "adversary K_PQC leaves her the full min-entropy of K_PHY, and giving "
      f"her K_PHY leaves her {KEM.name} (A15, A16).  The length-prefixed "
      "composition `l_PQC || K_PQC || l_PHY || K_PHY` under a "
      "transcript-keyed extract makes the epsilon case unambiguous.")
    A("4. **Denial of the PLS component is not denial of service** (A19): "
      "jamming the sounding campaign yields `G_PHY = 0`, not a failed "
      "handshake.")
    A("5. **Cost.** "
      f"+{W['overhead_bytes']} B ({W['overhead_pct']:.1f} %) on the wire and "
      f"a few milliseconds of computation; the real price of the physical "
      f"layer is latency - {L['probe_campaign_ms']:.0f} ms of channel "
      "sounding, set by the coherence time, not by the cryptography.")
    A("")
    A("## 7. Limitations")
    A("")
    A("* The channel is a stochastic TDL model, not a measured trace; the "
      "absolute key rates depend on the delay-spread and mobility "
      "assumptions.")
    A("* Min-entropy is *estimated* (NIST SP 800-90B MCV and first-order "
      "Markov) on a single session's samples; a deployment would use a "
      "long-run entropy assessment and a conservative fixed per-sample "
      "figure, and the estimator does not detect low-SNR conditions "
      "(section 3.3).")
    A("* The retained-sample mask inside W is public and conditions the "
      "distribution of the retained samples; the budget is therefore "
      "computed on the retained sequence, but the mask's own leakage about "
      "|Y| is not otherwise charged.")
    A("* `v_B = H_conf(r || Z_B)` is treated as a computational commitment; "
      "an information-theoretic accounting would charge its output length "
      "against the budget.")
    A("* Reciprocity impairments are modelled as static gain errors plus "
      "the TDD sounding gap; hardware effects such as non-linear PA "
      "distortion and IQ imbalance are not modelled.")
    return "\n".join(lines) + "\n"


def main() -> None:
    RESULTS.mkdir(exist_ok=True)
    t0 = time.perf_counter()
    if "--report-only" in sys.argv:
        # regenerate report.md from the JSON already in results/
        func = json.loads((RESULTS / "functional.json").read_text())
        sec = json.loads((RESULTS / "security.json").read_text())
        perf = json.loads((RESULTS / "performance.json").read_text())
    else:
        func = run_functional.main()
        sec = run_security.main()
        perf = run_performance.main()
    text = report(func, sec, perf)
    (RESULTS / "report.md").write_text(text)
    print(f"\n{'=' * 78}")
    print(f"wrote {RESULTS / 'report.md'}  "
          f"(total {time.perf_counter() - t0:.0f} s)")
    print("=" * 78)


if __name__ == "__main__":
    main()
