# hybrid_pqc_pls_sim

Mô phỏng **đầy đủ từng bước** giao thức thiết lập khoá hybrid PQC–PLS
(Step 1 → Step 6 + data plane) trên một kênh truyền vật lý được mô phỏng theo
3GPP TR 38.901, kèm **đánh giá bảo mật** (19 tấn công) và **đánh giá hiệu năng**.

Mọi phép mã hoá đều là hiện thực thật, không phải mô hình giả:

| Thành phần | Hiện thực |
|---|---|
| KEM | **ML-KEM-768** (FIPS 203, `kyber-py`) |
| Chữ ký | **ML-DSA-65** (FIPS 204, `dilithium-py`) |
| AEAD | **AES-256-GCM** (`cryptography`) |
| Hash / MAC / KDF | SHA3-256, HMAC-SHA-256, HKDF (RFC 5869) |
| Secure sketch | BCH nhị phân trên GF(2^m) tự hiện thực (Berlekamp–Massey + Chien) |
| Privacy amplification | Toeplitz universal hash (strong extractor), seed từ `T_2` |
| Min-entropy | Bộ đánh giá kiểu NIST SP 800-90B (MCV + Markov bậc 1) |

## Cài đặt & chạy

```bash
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt

./.venv/bin/python experiments/run_all.py           # toàn bộ, ~2 phút
./.venv/bin/python experiments/run_all.py --quick    # bản nhanh
./.venv/bin/python -m unittest discover -s tests -v  # 36 unit test
```

Kết quả ghi vào `results/`: `report.md` (báo cáo tổng hợp), `functional_trace.txt`
(vết chạy từng bước), `attacks.csv`, `security.json`, `performance.json` và 8
hình `fig_*.png`.

Chạy riêng từng phần:

```bash
./.venv/bin/python experiments/run_functional.py    # kiểm chứng đúng đắn
./.venv/bin/python experiments/run_security.py      # tấn công + quét tham số
./.venv/bin/python experiments/run_performance.py   # độ trễ, byte, thông lượng
./.venv/bin/python experiments/run_all.py --report-only   # dựng lại report.md từ JSON
```

## Ánh xạ giao thức → mã nguồn

Mỗi ký hiệu trong hình giao thức ứng với đúng một hàm:

| Giao thức | Mã nguồn |
|---|---|
| `m_1, sigma_U, Cert_U` | `UE.step1` → `messages.M1`, `messages.Flight1` |
| `Verify(Cert_U, sigma_U, m_1)`, `ReplayCheck(sid, N_U)` | `GNB.step1`, `primitives.ReplayCache` |
| `probe_U/probe_B(sid, N_U)`, `probe_ctx`, `h_probe` | `probing.ProbeContext.derive` |
| `Y_U ← Estimate_U(probe_ctx)` | `probing.estimate` (qua `channel.RadioWorld`) |
| `(C_KEM, K_PQC) ← KEM.Encaps(pk_E)` | `GNB.step3`, `primitives.KEM` |
| `W ← ReconcileHelper(Y_B)` | `reconcile.reconcile_helper` (mask + syndrome BCH) |
| `sigma_B ← Sign(sk_B, H(m1‖sigma_U‖m2))` | `GNB.step3` |
| `T_2`, `k_gate = HKDF(…, "PHY-GATE")` | `protocol.gate_key` |
| `g ← PHYGate(Y, W)` | `gate.phy_gate` (SNR, rounds, reliability, entropy budget) |
| `Z_U ← Reconcile(Quantize(Y_U), W)` | `quantize.quantize` + `reconcile.reconcile` |
| `v_B = H_conf(r‖Z_B)`, `r_U` | `reconcile.confirm_tag`, `UE.step4_conf` |
| `tau_3 = MAC_{k_gate}(…)`, `G_PHY = d_U ∧ d_B` | `UE.step4_send`, `GNB.step4_recv` |
| `K_PHY = PA(Z, T_2)` | `gate.privacy_amplify` |
| `T_H`, `IKM = l‖K_PQC‖l‖K_PHY`, HKDF | `protocol.SessionKeys.derive` |
| `fin_U/fin_B = Seal(k_cf, n^0, AD, ε)` | `UE.step6_send`, `GNB.step6_send` |
| `nonce_i = n^0 ⊕ i`, `ReplayCheck(i)` | `protocol.DataPlane`, `primitives.SlidingWindow` |

## Mô hình kênh vật lý

* TDL-A/B/C của TR 38.901; mỗi tap là quá trình Rayleigh sinh bằng
  sum-of-sinusoids (Jakes) ⇒ tự tương quan thời gian `J_0(2π f_d Δt)`,
  thời gian kết hợp `0.423/f_d`.
* CFR tại sóng mang con: `H(t,f) = Σ_l a_l(t) e^{-j2π f τ_l}`.
* **Tương hỗ (reciprocity) và các sai lệch thật:** hai chiều dùng chung một
  realization lan truyền (TDD), nhưng khác nhau ở (i) nhiễu thu độc lập,
  (ii) sai số hiệu chuẩn RF tĩnh (scalar + theo từng sóng mang con),
  (iii) khoảng trễ `tdd_gap_us` giữa hai lần sounding.
* **Eve:** `H_E = ρ·H + sqrt(1-ρ²)·H_ind` — `ρ→1` mô hình hoá kẻ nghe nằm
  trong vùng kết hợp của liên kết hợp lệ (trường hợp xấu nhất).

## Mô hình đối thủ

Dolev–Yao trên giao diện vô tuyến: thấy/sửa/xoá/phát lại mọi flight, và tự
sounding được kênh (vì `sid`, `N_U` truyền rõ nên Eve tự dẫn được `probe_ctx`).
Eve **không** có khoá ML-DSA dài hạn. Hai thử nghiệm compromise bổ sung giao
cho Eve trực tiếp `K_PQC` (A15) hoặc `K_PHY` (A16) để đo đúng bảo đảm hybrid.

## Những phát hiện chính

1. **Đúng đắn hai nhánh.** Kênh tốt → `G_PHY=1`, khoá phiên trộn `K_PQC` với
   `K_PHY` 128 bit; kênh chết → `G_PHY=0`, phiên **vẫn** hoàn tất trên nền
   post-quantum. Hai bên không bao giờ lệch nhau vì `G_PHY` được MAC ở Step 4
   và kiểm lại trong AD của key confirmation ở Step 6.
2. **19/19 tấn công bị bắt đúng ở bước mà thiết kế dự đoán.**
3. **Bảo đảm hybrid đúng cả hai chiều** (A15/A16).
4. **Chặn PLS không phải là chặn dịch vụ** (A19): jamming chỉ hạ `G_PHY` về 0.
5. **Ước lượng entropy một mình không phải là cơ chế an toàn**: ở SNR −10 dB
   bộ đánh giá vẫn "đạt" vì nhiễu *thêm* entropy biểu kiến; thứ thực sự đóng
   gate là kiểm tra SNR cục bộ + kiểm tra reconciliation `r_U` có tương tác.
6. **Lấy mẫu dày hơn băng kết hợp làm giảm** ngân sách trích xuất: số bit thô
   tăng nhưng entropy không tăng, còn rò rỉ syndrome tăng tuyến tính.

Chi tiết số liệu, bảng và hình: xem `results/report.md`.

## Giới hạn đã biết

Xem mục 7 của `results/report.md` (kênh là mô hình ngẫu nhiên không phải
trace đo thật; min-entropy là *ước lượng*; mask trong `W` là công khai;
`v_B` được coi là commitment tính toán; chưa mô hình hoá méo PA/IQ imbalance).
