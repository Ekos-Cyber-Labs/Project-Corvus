# OCSF events in Corvus

Everything inside Corvus is OCSF at the version pinned by
`OCSF_SCHEMA_VERSION` in [ocsf.py](../corvus/normalize/ocsf.py)
(currently `1.4.0`). Field names and activity IDs match the OCSF 1.4.0
schema (schema.ocsf.io). Classes, activity ids, and attributes are
verified against the pinned v1.4.0 schema files (including extensions
such as win) before use, never written from memory. Every event's
`metadata.version` defaults to that constant, so a version bump is a
one-line change.

Shared rules for all ten classes:

- `type_uid` is computed as `class_uid * 100 + activity_id`. It is a
  read-only computed field: any `type_uid` present in input is ignored and
  recomputed, so dumped events always validate back with a matching id.
- `time` is UTC epoch milliseconds and must be on or after 2000-01-01
  (`946684800000`). A timezone-aware `datetime` is converted; a naive
  `datetime` is rejected; an integer below the floor is rejected as looking
  like epoch seconds.
- `severity_id` follows the OCSF enum 0 Unknown, 1 Informational, 2 Low,
  3 Medium, 4 High, 5 Critical, 6 Fatal, plus 99 Other.
- `raw_data` keeps the original event as a JSON string, minus file-path
  ingestion fields (see below); `unmapped` holds anything a mapper could
  not place. Nothing is dropped silently: unmapped records are counted
  per `(channel, event id)` in `WindowsReadStats`, and archive members
  with no Windows event JSON (for example network pcaps) count as
  `unsupported` instead of raising.
- `entity_keys` is a Corvus extension with canonical, lowercased keys for
  deterministic correlation: `user` as `domain\user`, `host` as the short
  hostname, `ip` as the device address, plus `src_ip` / `dst_ip` from the
  endpoints. All classes compute them with the one shared
  `compute_entity_keys` function from the actor, device and endpoint
  fields, so a placeholder device address never hides an endpoint address.

## Classes and activity IDs

The Source column names the mapper that produces each class. Only
Detection Finding has no mapper yet.

| OCSF class | class_uid | category_uid | Activity IDs we use | Source |
|---|---|---|---|---|
| Authentication | 3002 | 3 | 1 Logon, 2 Logoff, 3 Authentication Ticket, 4 Service Ticket Request, 5 Service Ticket Renew, 6 Preauth | `windows.py` (Security 4624/4625) |
| Process Activity | 1007 | 1 | 1 Launch, 2 Terminate, 3 Open, 4 Inject, 5 Set User ID | `windows.py` (Sysmon 1, Sysmon 10 as Open) |
| Network Activity | 4001 | 4 | 1 Open, 2 Close, 3 Reset, 4 Fail, 5 Refuse, 6 Traffic, 7 Listen | `windows.py` (Sysmon 3) |
| File System Activity | 1001 | 1 | 1 Create, 2 Read, 3 Update, 4 Delete, 5 Rename, 6 Set Attributes, 7 Set Security, 8 Get Attributes, 9 Get Security, 10 Encrypt, 11 Decrypt, 12 Mount, 13 Unmount, 14 Open | `windows.py` (Sysmon 11) |
| Scheduled Job Activity | 1006 | 1 | 1 Create, 2 Update, 3 Delete, 4 Enable, 5 Disable, 6 Start | `windows.py` (Security 4698, TaskScheduler 106) |
| Script Activity | 1009 | 1 | 1 Execute | `windows.py` (PowerShell 4104/4103, Windows PowerShell 800) |
| Registry Key Activity | 201001 | 1 | 1 Create, 4 Delete, 5 Rename | `windows.py` (Sysmon 12 CreateKey/DeleteKey, Sysmon 14 as Rename; `extensions/windows/events/registry_key_activity.json`) |
| Registry Value Activity | 201002 | 1 | 2 Set, 4 Delete | `windows.py` (Sysmon 13, Sysmon 12 DeleteValue; `extensions/windows/events/registry_value_activity.json`) |
| Windows Service Activity | 201004 | 1 | 1 Create | `windows.py` (Security 4697, System 7045; `extensions/windows/events/windows_service_activity.json`) |
| Detection Finding | 2004 | 2 | 1 Create, 2 Update, 3 Close |  |

Other activity IDs pass through unchanged; the table lists the schema
values Corvus mappers may emit.

## Class-specific fields

- Authentication carries `status` (for example `Success` / `Failure`) and
  `status_id` (0 Unknown, 1 Success, 2 Failure, 99 Other), which feed the
  success-vs-attempt factor of the severity floor, plus `logon_type` /
  `logon_type_id` (Windows LogonType mapped to the pinned OCSF 1.4.0 enum:
  0 Unknown, 1 System, 2 Interactive, 3 Network, 4 Batch, 5 OS Service,
  7 Unlock, 8 Network Cleartext, 9 New Credentials, 10 Remote Interactive,
  11 Cached Interactive, 12 Cached Remote Interactive, 13 Cached Unlock,
  99 Other; Windows 0 becomes 1, 12 and 13 pass straight through, and
  anything else without an OCSF counterpart becomes 99; the raw value
  stays in `unmapped`).
- Process Activity carries `process` (`pid`, `name`, `cmd_line`, `file`,
  `parent_process`); the actor may additionally carry the process object
  for process events. For handle opens it also carries `actual_permissions`
  (the platform-native granted access mask, kept as the original hex
  string).
- Script Activity carries `script` (`uid` holding the PowerShell
  `ScriptBlockId`, `script_content`, `type_id` 2 / `type` `"PowerShell"`);
  `MessageNumber` / `MessageTotal` stay in `unmapped`, and the messages of
  a split block share the script `uid` for downstream grouping. Module
  logging (4103, content in `Payload`) and classic pipeline execution
  (Windows PowerShell 800, content in `Message`) map to the same class
  with no block id; Windows PowerShell 600 (provider lifecycle) stays
  unmapped and counted.
- Registry Key Activity carries `reg_key` (`path`; object
  `extensions/windows/objects/registry_key.json`) and, for renames,
  `prev_reg_key` with the pre-rename path. Sysmon 12 `CreateKey`
  maps to activity 1 Create and `DeleteKey` to 4 Delete; NXLog
  replaces the `EventType` field with the record severity (`INFO`),
  so the operation is read from the `Message` `EventType:` line,
  falling back to 1 Create when neither source has a known op; both
  stay in `unmapped`. Sysmon 14 maps to 5 Rename with `NewName` as
  the key and `TargetObject` as the previous key. The initiating
  process (`Image` / `ProcessId`) is `actor.process`; the NXLog
  `AccountName` / `Domain` pair is `actor.user`.
- Registry Value Activity carries `reg_value` (`path`, `name`
  derived as the last backslash component, `data`; object
  `extensions/windows/objects/registry_value.json`). Sysmon 13 maps
  to activity 2 Set; Sysmon 12 `DeleteValue` maps to 4 Delete with
  the same path/name derivation and no `data`.
  `TargetObject` and `Details` are kept verbatim in `path` and
  `data`.
- Windows Service Activity carries `win_service` (`name`,
  `cmd_line`, `service_start_name`, `service_start_type` /
  `service_start_type_id`, `service_type` / `service_type_id`;
  object `extensions/windows/objects/win_service.json`, enums
  `extensions/windows/dictionary.json`). Both sources map to
  activity 1 Create: Security 4697 (`ServiceName`, `ServiceFileName`,
  SCM-number `ServiceStartType`, hex `ServiceType`, `ServiceAccount`,
  installer in `SubjectUserName` / `SubjectDomainName`) and System
  7045 (`ServiceName`, `ImagePath`, word `StartType` such as
  `auto start`, word `ServiceType`, installer in `AccountName` /
  `Domain`; no service-account field, so `service_start_name` stays
  empty). Raw type values stay in `unmapped`.
- Network Activity carries `action` / `action_id` (0 Unknown, 1 Allowed,
  2 Denied, 99 Other) alongside the endpoints.
- File System Activity carries `file` (`path`, `name`; `name` is derived
  from `path` when missing).
- Scheduled Job Activity carries `job` (`name`, `cmd_line`).
- All classes may carry `device` (`hostname`, `ip`), `actor` with `user`
  (`name`, `domain`), and `src_endpoint` / `dst_endpoint` (`ip`, `port`).

## Windows replay normalizer (`windows.py`)

Reads `.evtx` files (via the `evtx` package), bare `.json` JSON-lines
files, and OTRF JSON-lines members inside `.zip` / `.tar.gz` / `.tgz`
archives. The JSON layout is picked per record from its keys: flat
records (`Channel` / `EventID`), the older winlogbeat layout (`log_name` /
`event_id` with the payload nested under `event_data`), and the newer
nested layout (a `winlog` object holding `channel` / `event_id` /
`event_data`).

- Channels match case-insensitively (`security` maps like `Security`),
  and `metadata.log_name` always carries the canonical spelling
  (`Security`, `Microsoft-Windows-Sysmon/Operational`,
  `Microsoft-Windows-TaskScheduler/Operational`), so downstream grouping
  stays deterministic. Records with no channel (ETW traces converted to
  `.evtx`) count under the `System.Provider` name instead of `unknown`.
- `metadata.product` names the producing product (`Sysmon` for the
  Sysmon channel, `Microsoft Windows` otherwise).
- `metadata.uid` is opaque: the truncated SHA-256 of the dataset-relative
  path plus the record id. Dataset file names, which may encode ATT&CK
  technique ids, can never leak into the record.
- Evidence that names its own technique stays verbatim in the record:
  Atomic Red Team paths such as `C:\AtomicRedTeam\atomics\T1218.005\...`
  in a command line, or a sysmon-modular `RuleName` such as
  `technique_id=T1003,technique_name=Credential Dumping`. The id tokens
  (`T####` with an optional `.###`, never glued to letters or digits)
  and the `technique_name=` values are masked (`[TECHNIQUE-ID]`,
  `[TECHNIQUE-NAME]`, keys and delimiters unchanged) only in
  model-bound payloads by `corvus/normalize/technique_ids.py`; the
  loader merely records per event whether such a reference is present.
  The name value also stops at a backslash, so masked serialized JSON
  still parses; structured payloads go through `mask_payload`, which
  masks string leaves without touching keys or other types.
- File-path ingestion fields (`log`, `path`, `log.file.path`,
  `@metadata`) are stripped from `raw_data` and from `unmapped` for the
  same reason. Every other input field ends up in a typed OCSF field or
  in `unmapped`.
- Times are parsed leniently into the strict shape above: naive
  timestamps are assumed UTC, epoch seconds are accepted, and offsets
  are converted. A record whose time cannot be parsed counts as unmapped
  under its own `(channel, event id)`.
- `iter_dataset_file` yields events one at a time and fills a caller-owned
  `WindowsReadStats`; `read_dataset_file` collects the same stream and is
  kept for tests. The replay loader uses the iterator so it never holds a
  whole dataset in memory.

## Canonicalization

Placeholders (`-`, `n/a`, `unknown`, case-insensitive) count as missing
everywhere.

- User: `EXAMPLE\JDoe`, `example\jdoe`, UPN `JDOE@EXAMPLE.COM` /
  `jdoe@example.com`, and bare `jdoe` with domain `example.com` all map to
  one key each (`example\jdoe`, `example.com\jdoe`). No domain means the
  bare lowercased name.
- Host: `WEB01`, `web01.example.com` and ` WEB01.EXAMPLE.COM ` all map to
  `web01`. A trailing `$` (machine account) is stripped. A value that
  parses as an IP address yields no host key; the address belongs in `ip`.
- IP: must be a valid address (IPv4-mapped IPv6 unwraps to IPv4);
  anything else yields no key.
