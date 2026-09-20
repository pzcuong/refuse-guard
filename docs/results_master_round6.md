# RESULTS MASTER — Round 6 (S)

Nguồn duy nhất của mọi số: `outputs/master/round6_ablation.json` (sinh bởi
`scripts/collect_master_round6.py`; mỗi số được tính lại từ file nguồn và script
**re-read + assert khớp từng row** sau khi ghi). Kỳ vọng khóa được assert cứng
(theo số V1/V2 đã audit độc lập): ladder recall
1.000/0.983/0.900/0.848/0.898/0.433, fp 1.000/0.967/0.833/0.767/0.867/0.267,
flips từng bậc 1/5/3/(0, hồi phục 3)/28, cumulative 34, C5_far 36/59 recall
0.390, qwen 0/60 flips, extension combined llama n=100 (+17, p=1.53e-05) và
granite n=70 (+47, chi2 1.95e-11), verdict H-M1 SUPPORTED (culprit A5),
H-M2 SUPPORTED, concentration A5 28/34, guidance G1, budget 703(+131)=834.

## Phương pháp thống kê (V1-R6 finding, adopted)

McNemar: **exact binomial hai phía** (recompute trong collector). Tại các cell
discordant ≥ 25, module stats pre-registered (`src/metrics/stats.py::mcnemar`,
`exact=None`) tự trả về **xấp xỉ χ² hiệu chỉnh liên tục** — cả hai biến thể đều
được lưu (`mcnemar_p_*_exact` vs `mcnemar_p_*_chi2`); χ² luôn bảo thủ (p lớn
hơn) và không verdict nào đổi: hot rung A5-vs-A4 exact 7.45e-09 / chi2 3.35e-07;
A5-vs-A0 exact 1.16e-10 / chi2 1.52e-08; granite combined 47 flips exact
1.4e-14 / chi2 1.95e-11, 43 flips exact 2.3e-13 / chi2 1.50e-10.

## RQ7b — P3 component ablation (llama3b, C5_near, 60 vul + 30 benign)

| Rung | recall (vul) | FP-rate (benign) | Δ vs A0 | flips (vul, vs prev) | p exact (vs prev) |
|---|---|---|---|---|---|
| A0 (B0) | 1.000 | 1.000 | — | — | — |
| A1 +boundary | 0.983 | 0.967 | −0.017 | 1/0 | 1.0 |
| A2 +header | 0.900 | 0.833 | −0.100 | 5/0 | 0.0625 |
| A3 +generic wrap | 0.848 | 0.767 | −0.153 | 3/0 | 0.25 |
| A4 +string med | 0.898 | 0.867 | −0.102 | 0/3 (hồi phục) | 0.25 |
| A5 +reassertion (=P3) | 0.433 | 0.267 | −0.567 | 28/0 | **7.45e-09** |

A3/A4: 59/60 parsed (1 sample 211155 unparsed PARTIAL). Verdicts (cả hai
framing cùng chỉ A5): H-M1 **SUPPORTED** (Δ0.465 ≥ 0.20, p<0.05); H-M2
**SUPPORTED** (Δ0.017 ≤ 0.05); concentration: A5 giữ 28/34 = 82% net flips
(hợp lệ vì A0 saturated recall 1.000; KHÔNG phải phân rã cộng-dồn — A4 hồi
phục 3); guidance **G1**. C5_far confirm: A5 recall 0.390 (59 parsed),
36/59 flips vs B0 cùng arm. Qwen spot (sạch, 0 reuse): recall 1.000 cả A1/A5,
0/60 flips — inert ở 3B trên baseline saturated.

## C5 extension (power cho verdict-bias)

| Model | scope | label | n pairs | C0 | C5_near | flips | p exact | p chi2 |
|---|---|---|---|---|---|---|---|---|
| llama3b | combined | benign | 100 | 0.820 | 0.990 | +17/−0 | 1.53e-05 | — |
| llama3b | combined | vul | 100 | 0.920 | 1.000 | +8/−0 | 0.0078 | — |
| granite2b | combined | benign | 70 | 0.043 | 0.714 | +47/−0 | 1.4e-14 | 1.95e-11 |
| granite2b | combined | vul | 70 | 0.057 | 0.671 | +43/−0 | 2.3e-13 | 1.50e-10 |

Granite còn thiếu 30+30 của tập 60+60 (disclosed từ Vòng 5). Extension-only và
qwen combined: xem JSON (`extension.*`).

## Generation accounting (V2 audit)

| Đại lượng | Giá trị |
|---|---|
| Records vòng 6 | 1,130 = 540 + 90 + 180 + 160 + 160 |
| Records reuse (sha-gated) | 150 = 120 (A0 90 + A5 30) + 30 (C5_far) |
| Gen mới trong file cuối | **703** = 325 + 160 + 160 + 58 + 0 |
| Gen của run qwen polluté (đã loại) | 131 (150 calls − 19 hits) |
| **Tổng GPU generations vòng 6** | **834** |

## Bản đồ token {{R6:*}} → giá trị (fill S-R6)

Xem `outputs/master/round6_token_map.json` (sinh bởi cùng script; mỗi chuỗi
LaTeX được format từ rows đã verify — không gõ tay).
