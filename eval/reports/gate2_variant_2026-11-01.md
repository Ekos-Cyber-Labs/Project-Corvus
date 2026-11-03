# Gate 2 — learned-rule variant evidence: VALID

Producing command: `corvus eval gate2 --rule 1 --train-gt data/lab-chain1/ground_truth_cadena1.jsonl --positive data/lab-chain1b-positive --positive-gt data/lab-chain1b-positive/ground_truth_positive.jsonl --negative data/lab-chain1b-control --negative-gt data/lab-chain1b-control/ground_truth_control.jsonl --baseline-dir data/replay-linux-baseline` (n = 1 run, git commit `4e5acf9940668e6544ae0bb3f7219335fa94f5e1`).
Variant window: 2026-11-01T02:56:51.084000+00:00 to 2026-11-01T03:22:51.260000+00:00 (n=16 steps across both variant ground truths; every timestamp below is data-derived, no wall-clock time enters any number).
Working tree: dirty at run start (n=7 changed paths); the commit recorded above is the parent of uncommitted work.
Rule under test: db id=1 version=1 status=shadow native_rule_id=100000 sigma id `7a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d` (Shadow Staging Via Shell With Chmod).
Verdict codes: none

## 1. Anti-leak checks

| check | result | detail |
|---|---|---|
| `a-created-before-variant` | PASS | rule created 2026-10-31T23:22:35.525000+00:00 before first variant step 2026-11-01T02:56:51.084000+00:00 |
| `b-lineage-in-training-windows` | PASS | n=2 cited uid(s) all in the recorded accepted backtest target_matched (n=2); training windows n=7 (2026-10-31T04:24:55.479000+00:00..2026-10-31T04:25:57.772000+00:00) |
| `b-lineage-outside-variant-windows` | PASS | n=2 cited uid(s), none present in either variant export |
| `c-no-variant-values-in-rule` | PASS | n=5 variant-only declared value(s) checked (n=5 declared), none in the text |
| `d-model-never-saw-variant` | PASS | n=8 recorded attempt(s), all created before first variant step 2026-11-01T02:56:51.084000+00:00 |

## 2. Positive run (rule present)

Export `data/lab-chain1b-positive`: n=1001 events from n=1 archive file(s), n=168 alerts from n=1 alert file(s); data window ['2026-11-01T03:20:52.550000+00:00', '2026-11-01T03:23:01.427000+00:00']. Learned alerts n=7, other-learned n=0, shipped n=161.

| step | technique | window | expected | learned n | first delay | rule id/version | shipped | verdict |
|---|---|---|---|---|---|---|---|---|
| 1 | T1046 | 2026-11-01T03:21:32.232000+00:00..2026-11-01T03:21:36.599000+00:00 | miss | 0 | - | 1/v1 | 5501x1, 5715x1 | PASS |
| 2 | T1110.001 | 2026-11-01T03:21:36.620000+00:00..2026-11-01T03:21:48.782000+00:00 | miss | 0 | - | 1/v1 | 5501x1, 5502x1, 5503x4, 5715x1, 5760x7, 5763x1 | PASS |
| 3 | T1078.003 | 2026-11-01T03:21:48.801000+00:00..2026-11-01T03:21:53.094000+00:00 | miss | 0 | - | 1/v1 | 40112x2, 5501x5, 5502x3, 5715x1, 5760x2 | PASS |
| 4 | T1548.003 | 2026-11-01T03:21:53.113000+00:00..2026-11-01T03:21:57.254000+00:00 | miss | 0 | - | 1/v1 | 2502x2, 40112x2, 5501x3, 5502x3, 5715x1 | PASS |
| 5 | T1053.003 | 2026-11-01T03:21:57.272000+00:00..2026-11-01T03:22:01.322000+00:00 | miss | 0 | - | 1/v1 | 40112x2, 5402x2, 5501x5, 5502x5, 5715x1 | PASS |
| 6 | T1098.004 | 2026-11-01T03:22:01.341000+00:00..2026-11-01T03:22:12.890000+00:00 | miss | 0 | - | 1/v1 | 40112x3, 5402x2, 5501x9, 5502x7, 5715x3 | PASS |
| 7 | T1005 | 2026-11-01T03:22:12.909000+00:00..2026-11-01T03:22:31.902000+00:00 | detect | 7 | 5.7 s | 1/v1 | 40112x5, 5402x4, 5501x15, 5502x11, 5715x3 | PASS |
| 8 | T1005 | 2026-11-01T03:22:31.927000+00:00..2026-11-01T03:22:51.260000+00:00 | miss | 0 | - | 1/v1 | 40112x4, 5402x4, 5501x11, 5502x11, 5715x3 | PASS |

No learned alerts outside any step window (n=0 false positives over n=1001 events scanned).

### Baseline backtest (same rule, same engine, 0 expected)

Baseline `data/replay-linux-baseline` (store): n=55794 events, window ['2026-10-28T00:00:01.332000+00:00', '2026-10-30T23:59:49.819000+00:00'], matches n=0.

## 3. Negative control (rule absent)

Export `data/lab-chain1b-control`: n=1360 events, n=215 alerts; data window ['2026-11-01T02:56:00+00:00', '2026-11-01T02:58:08.433000+00:00']. Learned-rule alerts n=0 (must be 0), other-learned n=0, shipped n=215.

| step | technique | window | learned n | shipped |
|---|---|---|---|---|
| 1 | T1046 | 2026-11-01T02:56:51.084000+00:00..2026-11-01T02:56:54.950000+00:00 | 0 | 5501x1, 5502x2, 5715x1 |
| 2 | T1110.001 | 2026-11-01T02:56:54.974000+00:00..2026-11-01T02:57:05.134000+00:00 | 0 | 5501x1, 5502x1, 5503x3, 5551x1, 5715x1, 5760x4 |
| 3 | T1078.003 | 2026-11-01T02:57:05.161000+00:00..2026-11-01T02:57:09.469000+00:00 | 0 | 40112x2, 5501x5, 5502x3, 5715x1, 5760x5, 5763x1 |
| 4 | T1548.003 | 2026-11-01T02:57:09.488000+00:00..2026-11-01T02:57:13.689000+00:00 | 0 | 2502x2, 40112x2, 5501x3, 5502x3, 5715x1 |
| 5 | T1053.003 | 2026-11-01T02:57:13.711000+00:00..2026-11-01T02:57:18.281000+00:00 | 0 | 11x1, 40112x2, 5402x2, 5501x5, 5502x5, 5715x1 |
| 6 | T1098.004 | 2026-11-01T02:57:18.306000+00:00..2026-11-01T02:57:30.021000+00:00 | 0 | 40112x2, 5402x2, 5501x7, 5502x7, 5715x3 |
| 7 | T1005 | 2026-11-01T02:57:30.047000+00:00..2026-11-01T02:57:49.606000+00:00 | 0 | 40112x6, 5402x6, 5501x17, 5502x13, 5715x3 |
| 8 | T1005 | 2026-11-01T02:57:49.629000+00:00..2026-11-01T02:58:08.710000+00:00 | 0 | 40112x4, 5402x4, 5501x11, 5502x11, 5715x3 |

## 4. Ledger (model spend around detection)

Detection window: 2026-11-01T02:56:51.084000+00:00 to 2026-11-01T03:22:18.796000+00:00 (first variant step to last learned-rule finding, both data-derived; rows on the boundary count as inside).

- before: llm_attempts n=43 (rule_proposal/muse-spark-1.3x43), spend n=43 ($0.857111).
- inside: llm_attempts n=0 (no rows), spend n=0 ($0.000000).
- after: llm_attempts n=0 (no rows), spend n=0 ($0.000000).
The `inside` segment must be zero for detection (triage and analysis may run later and appear under `after`, reported here, never hidden).

## 5. Honest limits (generated from the data above)

- Expected miss and missed (the rule's confirmed limit): steps [1, 2, 3, 4, 5, 6, 8].
- Expected detect but missed (failures): steps none.
- Steps no rule of any kind covered (neither learned nor shipped alerts in-window): none.
- Distinct learned rules involved in the positive export: n=1 (mine `7a1b2c3d-4e5f-4a6b-8c9d-0e1f2a3b4c5d`, others none).
- Training set: n=1 incident(s) (id 1), n=10 incident events, n=2 cited events.
- Variant vs training behavior: DIFFERENT technique sequence (train ['1:T1046', '2:T1110.001', '3:T1078.003', '4:T1548.003', '5:T1053.003', '6:T1098.004', '7:T1048'], positive ['1:T1046', '2:T1110.001', '3:T1078.003', '4:T1548.003', '5:T1053.003', '6:T1098.004', '7:T1005', '8:T1005'], negative ['1:T1046', '2:T1110.001', '3:T1078.003', '4:T1548.003', '5:T1053.003', '6:T1098.004', '7:T1005', '8:T1005']); variant-declared distinct values n=5 (.cache-sysd.gz, .s2.dat, 8443, 8444, gzip).
- No model weights are updated anywhere in this pipeline: what is learned is a verified, versioned Sigma rule (see the rule-proposal loop, which stores text plus lineage, never gradients).

## 6. Inputs

- train ground truth: `data/lab-chain1/ground_truth_cadena1.jsonl` (train steps n=7).
- positive export: `data/lab-chain1b-positive` with `data/lab-chain1b-positive/ground_truth_positive.jsonl`.
- negative export: `data/lab-chain1b-control` with `data/lab-chain1b-control/ground_truth_control.jsonl`.
- baseline: `data/replay-linux-baseline`.
