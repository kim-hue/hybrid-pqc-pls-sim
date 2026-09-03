"""Metric helpers for the parameter sweeps.

:func:`phy_trial` executes exactly the physical-layer pipeline of Steps 2-4
(probe -> quantise -> helper data -> reconcile -> PHYGate -> privacy
amplification) without the post-quantum handshake, which makes large Monte
Carlo sweeps cheap.  The decisions it reports are the same ones
:func:`hpls.protocol.run_session` would reach, because it calls the same
functions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

import numpy as np

from .channel import RadioWorld
from .config import ProtocolConfig
from .gate import phy_gate, privacy_amplify
from .primitives import H, rand_bytes
from .probing import ProbeContext, estimate
from .quantize import bit_disagreement, quantize
from .reconcile import confirm_tag, reconcile, reconcile_helper


def phy_trial(cfg: ProtocolConfig, seed: int, with_eve: bool = True
              ) -> Dict[str, float]:
    """One physical-layer key-agreement trial.  Returns flat metrics."""
    world = RadioWorld(cfg.phy, seed=seed)
    ctx = ProbeContext.derive(H("sid", seed)[:16], H("nu", seed), cfg.phy)
    y_u = estimate(world, "U", ctx)
    y_b = estimate(world, "B", ctx)
    q_u = quantize(y_u.feat, cfg.quant)
    q_b = quantize(y_b.feat, cfg.quant)

    W = reconcile_helper(q_b, cfg.code, cfg.quant)
    z_b, lv_b = W.select(q_b)
    sel_u, _ = W.select(q_u)
    rec = reconcile(q_u, W)

    g_u = phy_gate(q_u, W, y_u.snr_db_est, ctx.n_rounds, cfg.quant, cfg.gate)
    g_b = phy_gate(q_b, W, y_b.snr_db_est, ctx.n_rounds, cfg.quant, cfg.gate)

    # reconciliation verification of Step 4
    r = rand_bytes(32)
    r_u = confirm_tag(r, rec.bits) == confirm_tag(r, z_b)
    d_u = bool(g_u.accept and r_u)
    d_b = bool(g_b.accept)
    g_phy = bool(d_u and d_b)

    t2 = H("T2-surrogate", seed)
    key_agree = float("nan")
    if g_phy:
        k_u = privacy_amplify(rec.bits, t2, cfg.gate.target_phy_bits)
        k_b = privacy_amplify(z_b, t2, cfg.gate.target_phy_bits)
        key_agree = float(k_u == k_b)

    out: Dict[str, float] = {
        "n_samples": float(q_b.levels.size),
        "n_bits": float(W.n_bits),
        "retained_fraction": float(g_b.retained_fraction),
        "bdr_all": bit_disagreement(q_u.bits, q_b.bits),
        "bdr_retained": bit_disagreement(sel_u, z_b),
        "kdr_post": bit_disagreement(rec.bits, z_b),
        "recon_ok": float(rec.ok),
        "recon_corrected": float(rec.corrected),
        "recon_failed_blocks": float(rec.failed_blocks),
        "leak_bits": float(W.leak_bits),
        "h_min_total": float(g_b.h_min_bits),
        "h_min_per_sym": float(g_b.entropy.h_min_per_symbol) if g_b.entropy else 0.0,
        "h_mcv": float(g_b.entropy.h_mcv) if g_b.entropy else 0.0,
        "h_markov": float(g_b.entropy.h_markov) if g_b.entropy else 0.0,
        "lag1_corr": float(g_b.entropy.lag1_corr) if g_b.entropy else 0.0,
        "budget_bits": float(g_b.budget_bits),
        "snr_db_est": float(y_b.snr_db_est),
        "gate_u": float(g_u.accept),
        "gate_b": float(g_b.accept),
        "entropy_ok": float(g_b.entropy_ok),
        "snr_ok": float(g_b.snr_ok),
        "r_u": float(r_u),
        "d_u": float(d_u),
        "d_b": float(d_b),
        "g_phy": float(g_phy),
        "key_agree": key_agree,
        "helper_bytes": float(W.size()),
    }
    if with_eve:
        y_e = estimate(world, "E", ctx)
        q_e = quantize(y_e.feat, cfg.quant)
        sel_e, _ = W.select(q_e)
        rec_e = reconcile(q_e, W)
        out["eve_bdr_raw"] = bit_disagreement(sel_e, z_b)
        out["eve_bdr_post"] = bit_disagreement(rec_e.bits, z_b)
        out["eve_recovers_z"] = float(np.array_equal(rec_e.bits, z_b))
        if g_phy:
            k_e = privacy_amplify(rec_e.bits, t2, cfg.gate.target_phy_bits)
            out["eve_key_match"] = float(k_e == privacy_amplify(
                z_b, t2, cfg.gate.target_phy_bits))
        else:
            out["eve_key_match"] = 0.0
    return out


def sweep(cfg_fn, values, n_trials: int = 40, seed0: int = 5000,
          with_eve: bool = True) -> List[Dict[str, float]]:
    """Monte Carlo a metric set over a parameter list."""
    rows = []
    for j, v in enumerate(values):
        cfg = cfg_fn(v)
        acc: Dict[str, List[float]] = {}
        for i in range(n_trials):
            m = phy_trial(cfg, seed=seed0 + 1000 * j + i, with_eve=with_eve)
            for k, val in m.items():
                acc.setdefault(k, []).append(val)
        row = {"value": v}
        for k, vals in acc.items():
            a = np.asarray(vals, dtype=float)
            a = a[~np.isnan(a)]
            row[k] = float(a.mean()) if a.size else float("nan")
            if k in ("bdr_retained", "kdr_post", "eve_bdr_post"):
                row[k + "_p95"] = float(np.percentile(a, 95)) if a.size else float("nan")
        rows.append(row)
    return rows


def kgr_bits_per_second(row: Dict[str, float], cfg: ProtocolConfig) -> float:
    """Effective key-generation rate: admitted PHY bits per second of probing."""
    probe_s = (cfg.phy.n_probe_rounds
               * cfg.phy.effective_probe_interval_us() * 1e-6)
    return row.get("g_phy", 0.0) * cfg.gate.target_phy_bits / max(probe_s, 1e-9)
