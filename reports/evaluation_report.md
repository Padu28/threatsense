# ThreatSense — Evaluation Report

*Generated 2026-11-17T13:23:56+00:00 · model `ts-1.0.0` · source: synthetic*

> Synthetic flow capture. Metrics describe behaviour on this capture only and are **not** evidence that the
> detector is fit for production security operations.

**Frozen threshold:** 0.3007 — max recall s.t. FPR ≤ 1.00% (validation) (validation recall 0.982, FPR 0.0099)

## Test-window results

| Model | PR-AUC (95% CI) | ROC-AUC | Precision | Recall | F1 | FPR | Alerts / 10k flows | False alerts / 10k |
|---|---|---|---|---|---|---|---|---|
| majority_class | 0.211 (0.203–0.217) | 0.500 | 0.000 | 0.000 | 0.000 | 0.0000 | 0 | 0 |
| zscore_threshold | 0.733 (0.718–0.747) | 0.834 | 0.968 | 0.604 | 0.744 | 0.0052 | 1314 | 41 |
| logistic_regression | 0.945 (0.938–0.954) | 0.939 | 0.959 | 0.932 | 0.945 | 0.0106 | 2046 | 84 |
| random_forest | 0.983 (0.979–0.986) | 0.988 | 0.960 | 0.953 | 0.956 | 0.0106 | 2089 | 84 |
| hist_gradient_boosting | 0.963 (0.956–0.969) | 0.963 | 0.979 | 0.947 | 0.963 | 0.0054 | 2036 | 42 |
| isolation_forest | 0.790 (0.778–0.801) | 0.893 | 0.922 | 0.575 | 0.708 | 0.0130 | 1314 | 103 |
| hybrid | 0.990 (0.987–0.992) | 0.991 | 0.958 | 0.983 | 0.970 | 0.0116 | 2162 | 92 |

## Recall by attack category (test)

| grp | hybrid | isolation_forest | random_forest |
|---|---|---|---|
| botnet | 1.000 | 0.000 | 1.000 |
| bruteforce | 1.000 | 0.296 | 1.000 |
| dos | 1.000 | 0.997 | 1.000 |
| exfiltration | 1.000 | 0.992 | 0.400 |
| portscan | 1.000 | 1.000 | 1.000 |

`exfiltration` never appears in training — it measures novel-attack detection.

## Limitations
- Synthetic traffic is far more separable than real captures; expect lower scores on CIC-IDS2017/UNSW-NB15.
- Label noise (0.5 %) is injected but real IDS labels have systematic errors.
- Scores are prioritisation aids for analysts, not certainty or proof of malicious intent.
- No real scanning, exploitation, credential collection or live traffic capture is performed.
