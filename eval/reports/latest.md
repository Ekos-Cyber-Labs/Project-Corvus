# Corvus eval — latest

Producing command: `corvus eval run --replay-dir data/replay --rules-dir data/sigma/rules --attack data/attack/enterprise.json --ground-truth data/ground_truth.json --benign-hosts 4 --benign-hours 24 --benign-seed 7` (n = 1 run, git commit `577d3fac4987bc44b3b887c3454631a3eed0c5b9`, generated 2026-10-28).
Data window: 2019-02-02T09:16:58.787000Z to 2023-07-19T12:25:28.432000Z (`time` min/max over n=798471 stored events). Runtime: 319.1 s wall (detect 115.8 s, correlate 4.2 s).
Gates: benign Critical gate pass, leakage gate pass.
Working tree: dirty at run start (n=6 changed paths, excluding eval/reports/latest.*); the commit recorded above is the parent of uncommitted work.

## Inputs

- Sigma rules: n=2240 files, n=2240 parsed, n=1792 evaluated (skipped {'logsource': 183, 'status': 145, 'event_id': 104, 'unmapped_field': 16}).
- Replay store: n=442 files, n=798471 events; ground truth n=445 files (sha256 `df5a74396c50fb2b…`).
- Benign (DECLARED SYNTHETIC): hosts=4, hours=24, seed=7, n=312 records.
- Correlation: session gap 30 min, max span 24 h, auth threshold 3.

## Benign false positives (DECLARED SYNTHETIC, gate: zero >= Critical)

- Records: n=312; events: n=312 (unmapped n=0); findings: n=4; incidents: n=4.

| severity | incidents (n) |
| --- | --- |
| 1 Informational | 0 |
| 2 Low | 0 |
| 3 Medium | 4 |
| 4 High | 0 |
| 5 Critical | 0 |
| 6 Fatal | 0 |

- Incidents at Critical or above: n=0 (gate).

## Chain detection (per step, never a lone boolean)

### apt29-day1 (n=10 steps, file `security-datasets/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip`)

- Best incident covers n=8 steps; all incidents together cover n=8 steps.

| step | window (UTC) | techniques | best | all | in-window (n) | window match |
| --- | --- | --- | --- | --- | --- | --- |
| 1 Initial Breach | 2020-05-02T02:55:57Z .. 2020-05-02T03:02:06Z | T1204.002, T1036.002, T1571, T1059.003, T1059.001 | yes | yes | 847 | yes |
| 2 Rapid Collection and Exfiltration | 2020-05-02T02:56:18Z .. 2020-05-02T03:03:16Z | T1083, T1119, T1005, T1560.001, T1074.001, T1041 | no | no | 850 | no |
| 3 Deploy Stealth Toolkit | 2020-05-02T02:57:01Z .. 2020-05-02T03:08:53Z | T1105, T1027, T1546.015, T1112, T1548.002, T1071.001, T1573 | yes | yes | 886 | yes |
| 4 Defense Evasion and Discovery | 2020-05-02T02:59:44Z .. 2020-05-02T03:18:22Z | T1059.001, T1140, T1057, T1070.004, T1083, T1033, T1082, T1016, T1518.001, T1069, T1106 | yes | yes | 1415 | yes |
| 5 Persistence | 2020-05-02T03:04:16Z .. 2020-05-02T03:04:24Z | T1543.003, T1547.001 | yes | yes | 2 | yes |
| 6 Credential Access | 2020-05-02T03:00:37Z .. 2020-05-02T03:05:20Z | T1552.001, T1555.003, T1003.001, T1036, T1552.004 | yes | yes | 562 | yes |
| 7 Collection and Exfiltration | 2020-05-02T03:05:46Z .. 2020-05-02T03:07:15Z | T1113, T1115, T1056.001, T1005, T1560.001, T1048 | yes | yes | 17 | yes |
| 8 Lateral Movement | 2020-05-02T03:00:26Z .. 2020-05-02T03:18:22Z | T1018, T1021.006, T1021.002, T1057, T1027.002, T1569.002, T1078.002 | yes | yes | 1414 | yes |
| 9 Collection | 2020-05-02T03:15:32Z .. 2020-05-02T03:17:43Z | T1105, T1059.001, T1083, T1119, T1005, T1560.001, T1074.001, T1041, T1070.004 | yes | yes | 434 | yes |
| 10 Persistence Execution | 2020-05-02T03:19:53Z .. 2020-05-02T03:28:20Z | T1543.003, T1547.001, T1569.002, T1106, T1134.001 | no | no | 44 | no |
- Step 2 Rapid Collection and Exfiltration uncovered: in-window findings exist (n=850), none technique-match.
- Step 10 Persistence Execution uncovered: in-window findings exist (n=44), none technique-match.

## Atomic technique coverage (OTRF otrf-metadata files only)

- Files with ground-truth techniques: n=144; 
n=110 with events in the store, n=34 without (network/pcap, never ingested: excluded, not counted as misses).
- n=90 with >= 1 finding; n=53 with a finding matching the ground truth at its own granularity (n=48 exact — stated technique equals a ground-truth technique or a sub-technique of a parent ground-truth technique, n=5 parent-only).

| file | findings (n) | match | matched techniques |
| --- | --- | --- | --- |
| security-datasets/datasets/atomic/windows/collection/host/msf_record_mic | 1 | none |  |
| security-datasets/datasets/atomic/windows/credential_access/host/cmd_dumping_ntds_dit_file_ntdsutil | 3 | exact | T1003.003 |
| security-datasets/datasets/atomic/windows/credential_access/host/cmd_lsass_memory_dumpert_syscalls | 6 | exact | T1003.001 |
| security-datasets/datasets/atomic/windows/credential_access/host/cmd_psexec_lsa_secrets_dump | 6 | exact | T1003.004 |
| security-datasets/datasets/atomic/windows/credential_access/host/cmd_sam_copy_esentutl | 39 | exact | T1003.002 |
| security-datasets/datasets/atomic/windows/credential_access/host/covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges | 0 | none |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_dcsync_dcerpc_drsuapi_DsGetNCChanges | 0 | none |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_mimikatz_backupkeys_dcerpc_smb_lsarpc | 3 | none |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_mimikatz_extract_keys | 1 | none |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords | 0 | none |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_mimikatz_lsadump_patch | 1 | exact | T1003.001 |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_mimikatz_sam_access | 0 | none |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_ninjacopy_dumping_ntds_dit_file | 5 | none |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_over_pth_patch_lsass | 166 | exact | T1550.002 |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_powerdump_sam_access | 3 | none |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_shell_reg_dump_sam | 1 | exact | T1003.002 |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_shell_rubeus_asktgt_createnetonly | 5 | parent-only | T1003 |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_shell_rubeus_asktgt_ptt | 2 | parent-only | T1003 |
| security-datasets/datasets/atomic/windows/credential_access/host/psh_input_capture_promptforcreds | 0 | none |  |
| security-datasets/datasets/atomic/windows/credential_access/host/psh_lsass_memory_dump_comsvcs | 7 | exact | T1003.001 |
| security-datasets/datasets/atomic/windows/credential_access/host/psh_windows_vault_web_credentials | 0 | none |  |
| security-datasets/datasets/atomic/windows/credential_access/host/rdp_interactive_taskmanager_lsass_dump | 5 | exact | T1003.001 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/auditpol_system_user_auditpolicy_modification | 6 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_bitsadmin_download_psh_script | 4 | exact | T1197 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_disable_eventlog_service_startuptype_modification_via_registry | 0 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_mshta_javascript_getobject_sct | 2 | exact | T1218.005 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_mshta_vbscript_execute_psh | 4 | exact | T1218.005 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_netsh_fw_mod_open_ports | 2 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_process_herpaderping_snippingtool | 1 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_psh_stop_netprofm_eventlog_after_reboot | 0 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_psh_stop_netprofm_eventlog_before_reboot | 0 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_stop_event_logging_controlset001_minint_key | 2 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_stop_event_logging_controlset_minint_key | 1 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_wevtutil_modify_security_eventlog_path | 3 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/covenant_installutil | 9 | parent-only | T1218 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/covenant_lolbin_wuauclt_createremotethread | 2 | exact | T1218 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_dllinjection_LoadLibrary_CreateRemoteThread | 427 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_enable_rdp.tar.gz | 19 | exact | T1112 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_launcher_sct_regsvr32 | 11 | exact | T1218.010 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_monologue_netntlm_downgrade | 77 | exact | T1112 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_powerview_ldap_ntsecuritydescriptor | 12 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_psinject_PEinjection | 102 | parent-only | T1055 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_wdigest_downgrade.tar.gz | 17 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_cmstp_execution_bypassuac | 7 | exact | T1218.003 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_control_panel_execution | 2 | exact | T1218.002 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_disable_eventlog_service_startuptype_modification | 24 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_hh_local_html_payload | 2 | exact | T1218.001 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_mavinject_dll_notepad | 3 | exact | T1055 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_metasploit_stop_netprofm_eventlog_after_reboot | 27 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_metasploit_stop_netprofm_eventlog_before_reboot | 25 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_mshta_html_application_execution | 7 | exact | T1218.005 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_register_cimprovider_execute_dll | 2 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_stop_event_logging_controlset001_minint_key | 27 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_stop_event_logging_controlset_minint_key | 26 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/purplesharp_pe_injection_createremotethread | 4 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/reg_cmd_process_commandline_logging_disabled | 0 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/reg_disable_eventlog_service_startuptype_modification_via_registry | 0 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/reg_meterpreter_process_commandline_logging_disabled | 0 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/reg_stop_event_logging_controlset001_minint_key | 1 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/reg_stop_event_logging_controlset_minint_key | 1 | none |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/wmic_remote_xsl_jscript | 3 | exact | T1220 |
| security-datasets/datasets/atomic/windows/discovery/host/cmd_discover_iexplorer_version_registry | 1 | exact | T1518 |
| security-datasets/datasets/atomic/windows/discovery/host/cmd_seatbelt_group_user | 1 | none |  |
| security-datasets/datasets/atomic/windows/discovery/host/covenant_getdomaingroup_ldap_searchrequest_domain_admins | 1 | none |  |
| security-datasets/datasets/atomic/windows/discovery/host/empire_find_localadmin_smb_svcctl_OpenSCManager | 67 | exact | T1069.001 |
| security-datasets/datasets/atomic/windows/discovery/host/empire_getsession_dcerpc_smb_srvsvc_NetSessEnum | 277 | none |  |
| security-datasets/datasets/atomic/windows/discovery/host/empire_shell_net_local_users | 0 | none |  |
| security-datasets/datasets/atomic/windows/discovery/host/empire_shell_net_localgroup_administrators | 2 | none |  |
| security-datasets/datasets/atomic/windows/discovery/host/empire_shell_rpc_samr_smb_group_domain_admins_standard_user | 2 | none |  |
| security-datasets/datasets/atomic/windows/discovery/host/empire_shell_samr_EnumDomainUsers | 0 | none |  |
| security-datasets/datasets/atomic/windows/execution/host/cmd_sharpview_pcre_net | 6 | exact | T1059 |
| security-datasets/datasets/atomic/windows/execution/host/empire_launcher_vbs | 6 | parent-only | T1059 |
| security-datasets/datasets/atomic/windows/execution/host/psh_powershell_httplistener | 0 | none |  |
| security-datasets/datasets/atomic/windows/execution/host/psh_python_webserver | 2 | none |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/aadinternals_export_adfsdatabaseconfig_remotely | 0 | none |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_copy_smb_CreateRequest | 0 | none |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_dcom_executeexcel4macro_allowed | 11 | none |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_dcom_iertutil_dll_hijack | 7 | exact | T1021.003 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_dcom_registerxll | 170 | none |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_psremoting_command | 98 | exact | T1021.006 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_sc_query_dcerpc_smb_svcctl | 0 | none |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_sharpsc_create_dcerpc_smb_svcctl | 0 | none |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_sharpsc_query_dcerpc_smb_svcctl | 0 | none |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_sharpsc_start_dcerpc_smb_svcctl | 177 | none |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_sharpsc_stop_dcerpc_smb_svcctl | 1 | none |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_sharpwmi_create_dcerpc_wmi | 2 | exact | T1047 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_wmi_remote_event_subscription_ActiveScriptEventConsumers | 5 | none |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_wmi_wbemcomn_dll_hijack | 185 | exact | T1047 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_dcom_shellwindows_stager | 9 | none |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_msbuild_dcerpc_wmi_smb | 11 | exact | T1047 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl | 19 | exact | T1021 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_psremoting_stager | 11 | exact | T1021.006 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_shell_dcerpc_smb_service_dll_hijack | 177 | exact | T1574.001 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_smbexec_dcerpc_smb_svcctl | 21 | exact | T1021.002 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod | 280 | exact | T1047 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_wmic_add_user_backdoor | 5 | exact | T1047 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/mimikatz_CVE-2020-1472_Unauthenticated_NetrServerAuthenticate2 | 3 | none |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/purplesharp_ad_playbook_I | 297 | exact | T1021.006 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/schtask_create | 5 | exact | T1053.005 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/schtask_modification | 2 | none |  |
| security-datasets/datasets/atomic/windows/other/aptsimulator_cobaltstrike | 9 | exact | T1134.001, T1134.002 |
| security-datasets/datasets/atomic/windows/persistence/host/cmd_userinitmprlogonscript_batch | 4 | exact | T1037.001 |
| security-datasets/datasets/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_elevated_user | 2 | exact | T1547.001 |
| security-datasets/datasets/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_standard_user | 189 | exact | T1547.001 |
| security-datasets/datasets/atomic/windows/persistence/host/empire_schtasks_creation_execution_elevated_user | 187 | exact | T1053.005 |
| security-datasets/datasets/atomic/windows/persistence/host/empire_schtasks_creation_standard_user | 3 | exact | T1053.005 |
| security-datasets/datasets/atomic/windows/persistence/host/empire_wmi_local_event_subscriptions_elevated_user | 254 | exact | T1546.003 |
| security-datasets/datasets/atomic/windows/persistence/host/proxylogon_ssrf_rce_poc | 7 | exact | T1505.003 |
| security-datasets/datasets/atomic/windows/privilege_escalation/host/cmd_service_mod_fax | 6 | exact | T1543.003 |
| security-datasets/datasets/atomic/windows/privilege_escalation/host/empire_uac_shellapi_fodhelper | 112 | exact | T1548.002 |

## Compression (events -> findings -> incidents per dataset)

| scope | events (n) | findings (n) | incidents (n) |
| --- | --- | --- | --- |
| whole store | 798471 | 6074 | 234 |
| dataset evtx-attack-samples | 3096 | 776 | 132 |
| dataset security-datasets | 795375 | 5298 | 102 |
| chain file security-datasets/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip | 152491 | 1483 | 3 |
| synthetic benign set | 312 | 4 | 4 |

## In-band technique ids (provenance flag, D18)

- Events carrying an in-band technique reference: n=130 in n=21 files.

## Anti-leakage

- Status: pass (checked rows carry no dataset, file, technique or anchor strings; finding attacks and incident techniques scrubbed as detector output; in-band rows exempt from the technique check; n=0 hits).

## Train/test split (OTRF recordings per technique)

- Techniques: n=55 (18 testable, 37 untestable); multi-label files: n=3; excluded non-ATT&CK ids: {'T0000': 2}.

| technique | train (n) | test (n) | untestable |
| --- | --- | --- | --- |
| T1003 | 2 | 0 | True |
| T1003.001 | 3 | 2 | False |
| T1003.002 | 2 | 2 | False |
| T1003.003 | 5 | 2 | False |
| T1003.004 | 1 | 1 | False |
| T1003.006 | 2 | 2 | False |
| T1012 | 1 | 0 | True |
| T1021 | 2 | 0 | True |
| T1021.002 | 8 | 5 | False |
| T1021.003 | 4 | 3 | False |
| T1021.006 | 4 | 0 | True |
| T1037.001 | 1 | 0 | True |
| T1047 | 5 | 6 | False |
| T1049 | 2 | 0 | True |
| T1053.005 | 2 | 4 | False |
| T1055 | 2 | 1 | False |
| T1055.001 | 1 | 0 | True |
| T1055.002 | 1 | 0 | True |
| T1055.003 | 1 | 0 | True |
| T1056.002 | 1 | 0 | True |
| T1059 | 1 | 1 | False |
| T1059.001 | 1 | 0 | True |
| T1059.005 | 1 | 0 | True |
| T1069.001 | 1 | 1 | False |
| T1069.002 | 2 | 2 | False |
| T1087.001 | 1 | 0 | True |
| T1087.002 | 2 | 0 | True |
| T1110.003 | 2 | 0 | True |
| T1112 | 2 | 1 | False |
| T1123 | 1 | 0 | True |
| T1134.001 | 1 | 0 | True |
| T1134.002 | 1 | 0 | True |
| T1135 | 2 | 0 | True |
| T1197 | 1 | 0 | True |
| T1210 | 2 | 0 | True |
| T1218 | 1 | 1 | False |
| T1218.001 | 1 | 0 | True |
| T1218.002 | 1 | 0 | True |
| T1218.003 | 1 | 0 | True |
| T1218.004 | 1 | 0 | True |
| T1218.005 | 2 | 1 | False |
| T1218.010 | 1 | 0 | True |
| T1220 | 1 | 0 | True |
| T1222.001 | 2 | 0 | True |
| T1505.003 | 1 | 0 | True |
| T1518 | 1 | 0 | True |
| T1543.003 | 1 | 0 | True |
| T1546.003 | 1 | 0 | True |
| T1547.001 | 1 | 1 | False |
| T1548.002 | 1 | 0 | True |
| T1550.002 | 1 | 0 | True |
| T1558.003 | 2 | 0 | True |
| T1562.002 | 9 | 8 | False |
| T1562.004 | 1 | 0 | True |
| T1574.001 | 2 | 0 | True |

## Deltas vs the committed baseline

- benign incidents: n=4 -> n=4 (+0)
- benign Critical+ incidents: n=0 -> n=0 (+0)
- atomic files with a technique match: n=53 -> n=53 (+0)
- findings: n=6074 -> n=6074 (+0)
- incidents: n=234 -> n=234 (+0)
- in-band events: n=130 -> n=130 (+0)
- chain apt29-day1 best: 8/10 -> 8/10 (+0 steps)
- chain apt29-day1 all: 8/10 -> 8/10 (+0 steps)

## Incidents per severity floor

| floor | incidents (n) |
| --- | --- |
| 2 | 7 |
| 3 | 115 |
| 4 | 87 |
| 5 | 25 |
