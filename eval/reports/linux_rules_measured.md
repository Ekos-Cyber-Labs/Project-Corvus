# Linux shipped-rule measurement

Date: 2026-10-30 (maintainer local, UTC-6). Producing command: `uv run python eval/linux_rules_measured.py` (run from the repo root; every number carries its n).

## Rule inventory

`data/sigma/sigma_all_rules.zip` holds 149 `rules/linux/*.yml` rules (n=149, counted from the zip). Loaded with the same status gate as Windows (`test` + `stable`): 73 evaluate (n=73), 76 skipped (n=76).

Skip buckets (first hit wins, same order as the Windows report):

- `status` 15:
  - 15 x `experimental`
- `logsource` 45:
  - 14 x `product=linux category=None service=None`
  - 24 x `product=linux category=None service=auditd`
  - 1 x `product=linux category=None service=clamav`
  - 1 x `product=linux category=None service=cron`
  - 1 x `product=linux category=None service=guacamole`
  - 1 x `product=linux category=None service=sshd`
  - 2 x `product=linux category=None service=syslog`
  - 1 x `product=linux category=None service=vsftpd`
- `unmapped_field` 16:
  - 2 x `linux/file_event Image`
  - 3 x `linux/network_connection DestinationHostname`
  - 1 x `linux/network_connection Image`
  - 1 x `linux/network_connection Initiated`
  - 2 x `linux/process_creation CurrentDirectory`
  - 5 x `linux/process_creation ParentCommandLine`
  - 2 x `linux/process_creation ParentImage`

The auditd-service rules and the syslog/sshd/cron keyword rules stay out of scope; they remain counted under `logsource` above. Rules using an unmapped field (`ParentImage`, `ParentCommandLine`, `CurrentDirectory`, `Image` on file/network rows, `Initiated`, `DestinationHostname`) are skipped and counted under `unmapped_field`, never evaluated against null.

## False positives on the benign baseline

Window 2026-10-28T00:00:01.332000+00:00..2026-10-30T23:59:49.819000+00:00, n=55794 events. 7 matches on 7 events (n=7 matches, n=7 events).

| rule id | title | level | baseline hits |
|---|---|---|---|
| `86157017-c2b1-4d4a-8c33-93b8e67e4af4` | Potential Suspicious Change To Sensitive/Critical Files | medium | 6 |
| `0f79c4d2-4e1f-4683-9c36-b5469a665e06` | Access of Sudoers File Content | medium | 1 |

## Chain coverage

Window 2026-10-31T00:00:00.836000+00:00..2026-10-31T04:26:56+00:00, n=3567 events. 5 matches on 5 events (n=5 matches, n=5 events).

| rule id | title | level | chain hits | step windows |
|---|---|---|---|---|
| `30bcce26-51c5-49f2-99c8-7b59e3af36c7` | Execution Of Script Located In Potentially Suspicious Directory | medium | 3 | 7 |
| `00b90cc1-17ec-402c-96ad-3a8117d7a582` | Suspicious Curl File Upload - Linux | medium | 1 | 7 |
| `86157017-c2b1-4d4a-8c33-93b8e67e4af4` | Potential Suspicious Change To Sensitive/Critical Files | medium | 1 | (outside every step window) |

## Uncovered chain steps

Steps with no firing shipped rule inside their window: 1, 2, 3, 4, 5, 6 (n=6 of 7 steps).

- step 1 (T1046, 2026-10-31T04:24:55.479000+00:00..2026-10-31T04:25:00.134000+00:00): UNCOVERED
- step 2 (T1110.001, 2026-10-31T04:25:00.160000+00:00..2026-10-31T04:25:14.099000+00:00): UNCOVERED
- step 3 (T1078.003, 2026-10-31T04:25:14.129000+00:00..2026-10-31T04:25:18.361000+00:00): UNCOVERED
- step 4 (T1548.003, 2026-10-31T04:25:18.390000+00:00..2026-10-31T04:25:22.747000+00:00): UNCOVERED
- step 5 (T1053.003, 2026-10-31T04:25:22.774000+00:00..2026-10-31T04:25:26.800000+00:00): UNCOVERED
- step 6 (T1098.004, 2026-10-31T04:25:26.828000+00:00..2026-10-31T04:25:38.752000+00:00): UNCOVERED
- step 7 (T1048, 2026-10-31T04:25:38.781000+00:00..2026-10-31T04:25:57.772000+00:00): covered

Evaluated in 1.3 s wall.
