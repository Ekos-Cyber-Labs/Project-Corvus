# OCSF events in Corvus

Everything inside Corvus is OCSF at the version pinned by
`OCSF_SCHEMA_VERSION` in [ocsf.py](../corvus/normalize/ocsf.py)
(currently `1.9.0`). Field names and activity IDs match the OCSF 1.9.0
schema (schema.ocsf.io, `ocsf-schema` tag `1.9.0`). Classes, activity ids,
and attributes are verified against the pinned 1.9.0 schema files
(including extensions such as win) before use, never written from memory.
Every event's `metadata.version` defaults to that constant, so a version
bump is a one-line change. Events of a win extension class (201001,
201002, 201004) declare the extension in `metadata.extensions` (one entry:
name `win`, uid `"2"`, version `1.9.0`, from `extensions/windows/extension.json`
in the pinned tag); events of core classes carry no extensions entry.

Shared rules for all eleven classes:

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
- `entity_keys` is Corvus-internal, not an OCSF attribute: canonical,
  lowercased keys for deterministic correlation (`user` as `domain\user`,
  `host` as the short hostname, `ip` as the device address, plus
  `src_ip` / `dst_ip` from the endpoints). All classes compute them with
  the one shared `compute_entity_keys` function from the actor, device
  and endpoint fields, so a placeholder device address never hides an
  endpoint address. The keys travel as store columns and are derived on
  read; they are never serialized into the OCSF record.

## Classes and activity IDs

The Source column names the mapper that produces each class.
Detection Finding (2004) has no log mapper: `corvus/detect/findings.py`
builds one finding per rule match, with the matched event's context in
one top-level `evidences` entry (an attribute of the 2004 finding
itself, not of `finding_info`; the finding carries no actor or
endpoints).

| OCSF class | class_uid | category_uid | Activity IDs we use | Source |
|---|---|---|---|---|
| Authentication | 3002 | 3 | 1 Logon, 2 Logoff, 3 Authentication Ticket, 4 Service Ticket Request, 5 Service Ticket Renew, 6 Preauth | `windows.py` (Security 4624/4625); `wazuh.py` (sshd Accepted/Failed/Invalid user as Logon, disconnect/closed as Logoff; pam/su sessions; audit USER_AUTH/USER_START/LOGIN/USER_END) |
| Process Activity | 1007 | 1 | 1 Launch, 2 Terminate, 3 Open, 4 Inject, 5 Set User ID | `windows.py` (Sysmon 1, Sysmon 10 as Open); `wazuh.py` (audit execve with joined EXECVE/PROCTITLE, sudo, audit USER_CMD) |
| Network Activity | 4001 | 4 | 1 Open, 2 Close, 3 Reset, 4 Fail, 5 Refuse, 6 Traffic, 7 Listen | `windows.py` (Sysmon 3); `wazuh.py` (audit `connect` with decoded SADDR peer) |
| File System Activity | 1001 | 1 | 1 Create, 2 Read, 3 Update, 4 Delete, 5 Rename, 6 Set Attributes, 7 Set Security, 8 Get Attributes, 9 Get Security, 10 Encrypt, 11 Decrypt, 12 Mount, 13 Unmount, 14 Open | `windows.py` (Sysmon 11); `wazuh.py` (audit file syscalls with joined PATH, syscheck) |
| Scheduled Job Activity | 1006 | 1 | 1 Create, 2 Update, 3 Delete, 4 Enable, 5 Disable, 6 Start | `windows.py` (Security 4698, TaskScheduler 106) |
| Script Activity | 1009 | 1 | 1 Execute | `windows.py` (PowerShell 4104/4103, Windows PowerShell 800) |
| Module Activity | 1005 | 1 | 1 Load | `windows.py` (Sysmon 7; `events/system/module_activity.json`) |
| Registry Key Activity | 201001 | 1 | 1 Create, 4 Delete, 5 Rename | `windows.py` (Sysmon 12 CreateKey/DeleteKey, Sysmon 14 as Rename; `extensions/windows/events/registry_key_activity.json`) |
| Registry Value Activity | 201002 | 1 | 2 Set, 4 Delete | `windows.py` (Sysmon 13, Sysmon 12 DeleteValue; `extensions/windows/events/registry_value_activity.json`) |
| Windows Service Activity | 201004 | 1 | 1 Create | `windows.py` (Security 4697, System 7045; `extensions/windows/events/windows_service_activity.json`) |
| Detection Finding | 2004 | 2 | 1 Create, 2 Update, 3 Close |  |

Other activity IDs pass through unchanged; the table lists the schema
values Corvus mappers may emit.

## Class-specific fields

- Every mapper output declares the `host` profile in
  `metadata.profiles`: Windows records are host-observed and always
  carry `device` (with schema `type_id` 0 Unknown) and `actor` context,
  which the schema gates behind that profile. A record that cannot
  supply a required attribute (a script without text, a registry value
  without a target, a service without a name) is counted unmapped
  instead of emitted half-formed.
- Authentication carries the required top-level `user` subject (the same
  identity sits under `actor.user`), `status` (for example `Success` /
  `Failure`) and `status_id` (0 Unknown, 1 Success, 2 Failure, 99 Other),
  which feed the success-vs-attempt factor of the severity floor, plus
  `logon_type` / `logon_type_id` (Windows LogonType mapped to the pinned
  OCSF 1.9.0 enum: 0 Unknown, 1 System, 2 Interactive, 3 Network, 4 Batch,
  5 OS Service, 7 Unlock, 8 Network Cleartext, 9 New Credentials,
  10 Remote Interactive, 11 Cached Interactive, 12 Cached Remote
  Interactive, 13 Cached Unlock, 99 Other; Windows 0 becomes 1, 12 and
  13 pass straight through, and anything else without an OCSF counterpart
  becomes 99; the raw value stays in `unmapped`).
- Process Activity carries `process` (`pid`, `name`, `cmd_line`, `file`,
  `parent_process`, always emitted); the actor may additionally carry
  the process object for process events. For handle opens it also
  carries `actual_permissions`, the platform-native granted access mask
  parsed to an integer (`"0x1010"` becomes `4112`); an unparseable mask
  stays verbatim in `unmapped`.
- Script Activity carries `script` (`uid` holding the PowerShell
  `ScriptBlockId`, `script_content` as the schema `long_string` object
  with the text in `value`, `type_id` 2 / `type` `"PowerShell"`);
  `MessageNumber` / `MessageTotal` stay in `unmapped`, and the messages of
  a split block share the script `uid` for downstream grouping. Module
  logging (4103, content in `Payload`, falling back to the NXLog
  `Message` invocation detail) and classic pipeline execution
  (Windows PowerShell 800, content in `Message`) map to the same class
  with no block id; a script record with no text, and Windows
  PowerShell 600 (provider lifecycle), stay unmapped and counted.
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
  2 Denied, 99 Other) alongside the endpoints; records carrying an
  action declare the `security_control` profile the schema gates it
  behind.
- File System Activity carries `file` (`path`, `name` derived from
  `path`, schema `type_id` 1 Regular File; process images and loaded
  modules use 8 Executable File).
- Scheduled Job Activity carries `job` (`name`, `job_actions[]` with
  `cmd_line` plus `type_id` / `type`; `job.cmd_line` is deprecated since
  OCSF 1.9.0 and is never written). Security 4698 contributes the first
  Exec command parsed from the `TaskContentNew` XML as type 2 `Execute`;
  TaskScheduler 106 names no command.
- Module Activity carries `module` (`file` with `path`, `name` derived
  from `path`, `hashes` as fingerprint objects (`algorithm` caption,
  `algorithm_id`, `value`; object `objects/fingerprint.json`), `desc`,
  `company_name`, `product.name`, `internal_name`; object
  `objects/module.json`, file slots from `objects/file.json`).
  `Signed` / `Signature` / `SignatureStatus` have no typed slot
  (`file.signature` is deprecated since 1.8.0) and stay in `unmapped`,
  as do `FileVersion` and the remaining Sysmon fields. The loading
  process (`Image` / `ProcessId`) is `actor.process`.
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

## Linux archive normalizer (`wazuh.py`)

Raw Wazuh archive documents (one JSON object per line, `.json.gz` or
`.json`) map through `map_linux_doc`, sharing the alert/archive
mappers above. Audit companions (EXECVE/CWD/PATH/PROCTITLE) join
their SYSCALL by kernel serial — hex-encoded arguments decode as
UTF-8 with replacements counted — so one execution yields one
event; companions without a SYSCALL stay unmapped. `connect`
syscalls map with the decoded `SADDR` peer (`data.audit` drops the
`SOCKADDR` record, so the mapper reads `full_log`). PAM `session
opened/closed` and `su` invocations map to Authentication Logon /
Logoff; the pinned `authorize_session` activities are privilege
assignments, not sessions, so they are not used. Cron sessions
carry `unmapped["linux.cron"]` for later filtering. The ssh user
name is attacker-controlled: kept verbatim up to
`LINUX_USERNAME_CAP` (256), never sanitised. Event time comes from
the log line (kernel audit stamp, ISO-8601 auth.log, or journald
`Mon dd HH:MM:SS` with the manager year), never the manager receive
time. The same event arriving twice (auth.log and journald copies)
shares the dedupe key `agent + canonical body`; audit documents
share `agent + serial` (session records add their type).

## Sigma logsource mapping (`corvus/detect/mapping.py`)

Each Sigma `logsource` routes to one OCSF slice plus a Sigma field
to OCSF value map (the executable form of this table). `rules/windows`
only; `status` test and stable only; `rules-emerging-threats`,
`rules-threat-hunting` and other products are out of scope. A Sigma
field with no faithful source in its slice has no entry, and any rule
using it is skipped and counted with the field name, never evaluated
against null. `EventID`, `Channel` and `Provider_Name` are exposed
where the slice determines them exactly (`Provider_Name` is a
channel constant verified against stored `raw_data`).

| Sigma logsource | OCSF slice (class/activity, log) | Sigma field to OCSF value |
|---|---|---|
| `process_creation` | 1007/1, Sysmon | `Image` process.file.path, `CommandLine` process.cmd_line, `ParentImage` parent file.path, `ParentCommandLine`/`ParentUser`/`LogonId`/`OriginalFileName`/`Description`/`Product`/`Company`/`Hashes`/`IntegrityLevel`/`CurrentDirectory`/`FileVersion` unmapped, `User` actor (`DOMAIN\user`), `EventID` 1, `Channel` log_name, `Provider_Name` const |
| `process_access` | 1007/3, Sysmon | `SourceImage` actor process path, `TargetImage` process.file.path, `GrantedAccess` actual_permissions, `CallTrace`/`SourceUser` unmapped, `User` actor, `EventID` 10, `Channel`, `Provider_Name` const |
| `image_load` | 1005/1, Sysmon | `ImageLoaded` module.file.path, `Image` actor process path, `Signed`/`Signature`/`SignatureStatus` unmapped (no typed slot), `OriginalFileName` internal_name, `Description` desc, `Company` company_name, `Product` product.name, `Hashes` rebuilt `ALG=value` pair string, `RuleName` unmapped, `EventID` 7, `Channel`, `Provider_Name` const. `CommandLine` has no source: rules using it are skipped |
| `network_connection` | 4001/1, Sysmon | `Image` actor process path, `Initiated`/`DestinationHostname`/`Protocol`/`SourceHostname`/`SourceIsIpv6` unmapped, `DestinationIp`/`SourceIp` endpoints, `DestinationPort`/`SourcePort` endpoint ports, `User` actor, `EventID` 3, `Channel`, `Provider_Name` const. `CommandLine` and `ParentImage` have no source on Sysmon 3: skipped |
| `file_event` | 1001/1, Sysmon | `TargetFilename` file.path, `Image` actor process path, `EventID` 11, `Channel`, `Provider_Name` const. `CommandLine`, `ParentImage`, `ParentCommandLine` have no source on Sysmon 11: skipped |
| `registry_add` | 201001/1 + 201002/2, Sysmon | `TargetObject` key/value path, `EventType` unmapped, `Image` actor, `Details` value data, `Channel`, `Provider_Name` const (no `EventID`: a Set row cannot tell Sysmon 12 from 13) |
| `registry_set` | 201002/2, Sysmon | `TargetObject` value path, `Details` value data, `Image` actor, `User` actor, `EventType` unmapped, `Channel`, `Provider_Name` const (no `EventID`) |
| `registry_delete` | 201001/4 + 201002/4, Sysmon | same as `registry_add` on the delete activities |
| `registry_event` | 201001/1,4,5 + 201002/2,4, Sysmon | same as `registry_add`/`registry_set` plus `NewName` = key path on renames only (null otherwise), and rename-aware `TargetObject` (pre-rename path on activity 5). No `EventID` |
| `ps_script` | 1009/1, PowerShell-Operational, subtype 4104 | `ScriptBlockText` script content on 4104 rows only, `Path` unmapped, `EventID` 4103/4104 by subtype (markers, `raw_data` fallback), `Channel`, `Provider_Name` const |
| `ps_module` | 1009/1, PowerShell-Operational, subtype 4103 | `Payload` script content on 4103 rows only, `ContextInfo` unmapped, `EventID`/`Channel`/`Provider_Name` as above |
| `ps_classic_start`, `powershell-classic` | 1009/1, Windows PowerShell (EventID 800) | `Data` unmapped, `EventID` 800, `Channel`, `Provider_Name` const (`PowerShell`) |
| service `security` | 3002/1,2 + 1006/1 + 201004/1, Security | `EventID` derived per row (4624/4625/4698/4697), `Channel`, `Provider_Name` const; 4624/4625: `TargetUserName` actor name, `IpAddress`/`IpPort` endpoints, `LogonType`/`WorkstationName`/subjects/status fields unmapped; 4698: `TaskName` job name, subjects actor/`TaskContent*` unmapped; 4697: `ServiceName`/`ServiceFileName`/`ServiceAccount` service fields, subjects actor. `SubjectUserName`/`SubjectDomainName` read the actor on 4697/4698 rows and `unmapped` elsewhere |
| service `system` | 201004/1, System (EventID 7045) | `EventID` 7045, `ServiceName` name, `ImagePath` cmd_line, `ServiceType`/`StartType` unmapped raw, `AccountName` actor, `Channel`, `Provider_Name` const |
| taskscheduler | 1006/1, TaskScheduler (EventID 106) | `EventID` 106, `TaskName` job name, `User` actor, `Channel`, `Provider_Name` const |

Matching equals Sigma's: case-insensitive strings (`ILIKE` plus
`COLLATE NOCASE`, because DuckDB `LIKE` is case-sensitive), wildcards,
`contains`/`startswith`/`endswith`/`all`, `re` (validated per rule in
DuckDB; RE2 rejects Python-only constructs and the rule is skipped),
`cidr`, `windash`, `base64offset`, `|cased` (DuckDB `GLOB` with lone
backslashes doubled, since DuckDB `GLOB` unlike SQLite's treats `\` as
an escape), keyword search over the raw record, field references,
existence tests. Nulls follow Sigma: a field absent from the raw
record matches no value but satisfies `NOT` (the row is included).
There is one deliberate fidelity rule on top: when the normalizer
replaced a placeholder (`-`, empty, `n/a`, `unknown`) with null in a
typed slot, the Sigma row still carries the value the source logged,
re-read from the pre-mapper payload under the wire name (which is the
Sigma field name) — a field truly absent from the payload stays null.
The payload is rebuilt with the normalizer's own layout dispatch
(`wire_fields` in `windows.py`: trimmed EVTX `System`/`EventData`,
newer `winlog`, older winlogbeat `event_data`, flat JSON), so nested
layouts work exactly like flat ones: `IpAddress: '-'` matches a 4624
logon the source logged with `-` in any layout, and `NOT` over it
follows the logged value. `unmapped` values are
read verbatim (no normalization), so equality and wildcard tests
compare exactly what the record carried.

Built-in service rules route by their `EventID` selection: a rule
whose selected EventIDs lie fully outside the mapped set for that
service (for example `security` 4663 or `system` 104) is skipped and
counted per EventID; a rule mixing mapped and unmapped ids evaluates
on the mapped slice, where the unmapped ids simply never match.

Rules the detector never evaluates:

- other categories and services (DNS, pipes, drivers, WMI, WinDefend,
  threat-hunting and emerging-threats products): counted per logsource;
- `status` experimental, deprecated, unsupported: counted per status;
- service rules for unmapped EventIDs: counted per EventID;
- rules using an unmapped field (`CommandLine` on image-load,
  `Provider_Name` on ETW-provider rules, `EventID` on registry,
  `Data` where no record carries it): counted per field;
- rules whose conversion fails (legacy pipe conditions, rejected
  regex, correlation rules): counted per construct.

## Linux logsource mapping (`corvus/detect/mapping.py`)

The three Linux slices below route `product: linux` by category
(service must be unset), with the same `test` + `stable` status gate
as Windows. Field behaviour verified against the real normalized
Linux events (chain store, n=2245 process / 502 file / 253 network
events): a Sigma field with no faithful slot stays unmapped and the
rule is skipped and counted, never evaluated against null.

| Sigma logsource | OCSF slice (class/activity, log) | Sigma field to OCSF value |
|---|---|---|
| `linux/process_creation` | 1007/1, `auditd` + `sudo` | `Image` process.file.path, `CommandLine` process.cmd_line, `User` actor (`name`, no domain on Linux). `ParentImage`/`ParentCommandLine` have no slot (no `parent_process` in mapper output), nor do `CurrentDirectory`/`LogonId`: rules using them are skipped |
| `linux/file_event` | 1001 (all activities), `auditd` + the three `syscheck` decoders | `TargetFilename` file.path. `Image` has no slot (the actor process carries pid and name only): skipped |
| `linux/network_connection` | 4001/1 + 4001/4, `auditd` | `DestinationIp`/`DestinationPort` dst_endpoint, `User` actor. `Image`/`Initiated`/`DestinationHostname`/`Protocol`/source fields have no slot: skipped |

Out of scope and counted per logsource: the `auditd`-service rules
(raw `type`/`SYSCALL`/`aN` record shapes, evaluated against merged
one-event-per-serial rows that have no such fields) and the
syslog/sshd/cron keyword rules. Measured in
`eval/reports/linux_rules_measured.md` (producing script
`eval/linux_rules_measured.py`). Learned rules are judged by the
deterministic verifier in `corvus/learning/backtest.py` and stored
through `corvus/learning/rules.py` (`corvus rules backtest/add/list/show`).

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
