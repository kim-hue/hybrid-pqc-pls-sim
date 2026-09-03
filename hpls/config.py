"""Configuration for the hybrid PQC-PLS key-establishment simulator.

All protocol-visible parameters live here so that experiments can sweep them
without touching protocol logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Tuple

C_LIGHT = 299_792_458.0


@dataclass(frozen=True)
class PhyConfig:
    """Physical-layer / radio parameters."""

    # --- OFDM numerology (5G NR FR1, 30 kHz SCS, 100 MHz, 273 RB) ---
    carrier_hz: float = 3.5e9
    scs_hz: float = 30e3
    n_subcarriers: int = 3276

    # --- propagation ---
    tdl_profile: str = "TDL-C"          # TDL-A | TDL-B | TDL-C | FLAT
    delay_spread_ns: float = 300.0      # rms delay spread (NLOS urban)
    ue_speed_mps: float = 3.0           # pedestrian
    n_sinusoids: int = 24               # sum-of-sinusoids per tap (Jakes)

    # --- probing schedule ---
    n_probe_rounds: int = 24
    # If None, the round spacing is auto-set to one coherence time.
    probe_interval_us: float | None = None
    # If None, the pilot spacing is `pilot_spacing_mult` coherence bandwidths.
    pilot_spacing: int | None = None
    pilot_spacing_mult: float = 3.0
    # OFDM symbols averaged per sounding round (SRS/CSI-RS burst): reduces the
    # channel-estimation noise by 10*log10(M) dB.
    n_avg_symbols: int = 8
    tdd_gap_us: float = 500.0           # UL-sounding -> DL-sounding offset

    # --- receiver / hardware ---
    snr_db: float = 20.0
    # static per-device transceiver mismatch (breaks perfect reciprocity)
    gain_mismatch_db: float = 0.5       # std of the scalar gain error
    freq_mismatch_db: float = 0.2       # std of the per-subcarrier gain error

    # --- eavesdropper ---
    eve_csi_correlation: float = 0.3    # rho between Eve's and Alice's CFR
    eve_snr_db: float = 25.0            # Eve may have a better receiver

    def coherence_time_s(self) -> float:
        """Classical Clarke/Jakes coherence time 0.423 / f_d."""
        return 0.423 / max(self.doppler_hz(), 1e-9)

    def doppler_hz(self) -> float:
        return self.ue_speed_mps * self.carrier_hz / C_LIGHT

    def coherence_bandwidth_hz(self) -> float:
        """Conservative 50%-coherence bandwidth 1 / (5 * tau_rms)."""
        return 1.0 / (5.0 * self.delay_spread_ns * 1e-9)

    def effective_pilot_spacing(self) -> int:
        if self.pilot_spacing is not None:
            return max(1, int(self.pilot_spacing))
        return max(1, int(round(self.pilot_spacing_mult
                                * self.coherence_bandwidth_hz() / self.scs_hz)))

    def effective_snr_db(self) -> float:
        """SNR after averaging ``n_avg_symbols`` pilot symbols per round."""
        import math
        return self.snr_db + 10.0 * math.log10(max(self.n_avg_symbols, 1))

    def effective_probe_interval_us(self) -> float:
        if self.probe_interval_us is not None:
            return float(self.probe_interval_us)
        return self.coherence_time_s() * 1e6

    def n_pilots(self) -> int:
        return len(range(0, self.n_subcarriers, self.effective_pilot_spacing()))

    def n_samples(self) -> int:
        return self.n_pilots() * self.n_probe_rounds


@dataclass(frozen=True)
class QuantConfig:
    """Channel quantiser (CQG: multi-bit, block-normalised, Gray-coded)."""

    bits_per_sample: int = 1
    block_size: int = 0        # 0 => normalise over the whole probe matrix
    guard_band: float = 0.3    # guard half-width in normalised-std units


@dataclass(frozen=True)
class CodeConfig:
    """Binary BCH code used for the syndrome-based secure sketch."""

    m: int = 8            # GF(2^m) => block length n = 2^m - 1 = 255
    t: int = 8            # designed error-correcting capability (BER <= 3.1 %)


@dataclass(frozen=True)
class GateConfig:
    """PHYGate admission thresholds and privacy-amplification budget."""

    target_phy_bits: int = 128        # |K_PHY| when G_PHY = 1
    snr_min_db: float = 10.0
    min_probe_rounds: int = 8
    # fraction of samples that must be further than `reliability_margin`
    # (in normalised std units) from the nearest quantisation threshold
    reliability_margin: float = 0.15
    min_reliable_fraction: float = 0.60
    # leftover-hash-lemma security parameter: |K| <= H_inf - leak - 2*log2(1/eps)
    pa_epsilon_log2: int = 32
    entropy_confidence: float = 0.99


@dataclass(frozen=True)
class CryptoConfig:
    kem: str = "ML-KEM-768"
    sig: str = "ML-DSA-65"
    aead: str = "AES-256-GCM"
    hash: str = "SHA3-256"
    lambda_bits: int = 256            # nonce length
    replay_window: int = 64           # data-plane anti-replay window


@dataclass(frozen=True)
class ProtocolConfig:
    sn_id: str = "mcc001-mnc01"
    alg_list: Tuple[str, ...] = ("ML-KEM-768+ML-DSA-65", "ML-KEM-512+ML-DSA-44")
    phy: PhyConfig = field(default_factory=PhyConfig)
    quant: QuantConfig = field(default_factory=QuantConfig)
    code: CodeConfig = field(default_factory=CodeConfig)
    gate: GateConfig = field(default_factory=GateConfig)
    crypto: CryptoConfig = field(default_factory=CryptoConfig)

    def with_phy(self, **kw) -> "ProtocolConfig":
        return replace(self, phy=replace(self.phy, **kw))

    def with_gate(self, **kw) -> "ProtocolConfig":
        return replace(self, gate=replace(self.gate, **kw))

    def with_quant(self, **kw) -> "ProtocolConfig":
        return replace(self, quant=replace(self.quant, **kw))

    def with_code(self, **kw) -> "ProtocolConfig":
        return replace(self, code=replace(self.code, **kw))


DEFAULT = ProtocolConfig()
