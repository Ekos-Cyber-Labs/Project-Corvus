# Day-2 replay detect

SigmaHQ rules over the OCSF replay store: counts and ids only,
no event content. Produced by `eval/detect_census.py`; inputs are
the pinned SigmaHQ release (`data/sigma/rules`), the replay store
(`data/replay`), `data/ground_truth.json`,
`eval/apt29_day1_ground_truth.json`, and
`data/attack/enterprise.json`. Date: 2026-10-28.

## Method

- Each Sigma logsource routes to one OCSF slice; each slice is
  scanned once per rule group. Slices, field maps and the null
  semantics (Sigma `NOT`; placeholders re-read from the
  pre-mapper payload in every raw layout) are documented in
  `docs/ocsf.md`.
- Technique ids resolve through the pinned ATT&CK dictionary v20.0 (`data/attack/enterprise.json`); tactic names below are its names (for example Defense Impairment, Stealth).
- A finding carries technique ids; matching below compares at
  the parent-or-self level on both sides: a finding technique,
  its parent when it is a sub-technique, and the same expansion
  of each ground-truth id. A tactic count names a finding once
  per tactic its attacks list.

## Null semantics delta (old vs new)

Old: strict nulls (a null field satisfies no condition, negated or not) with no raw fallback. New: stock Sigma semantics (an absent field satisfies `NOT`) plus the raw fallback (a nulled placeholder compares as the logged value). Before/after are matched-event counts per rule.

- changed rules: n=4 of n=1792 evaluated; 4 gain matches, 0 lose matches, 1788 unchanged

| rule id | before | after | delta |
| --- | --- | --- | --- |
| 5ef9853e-4d0e-4a70-846f-a9ca37d876da | 0 | 33 | +33 |
| 49f2f17b-b4c8-4172-a68b-d5bf95d05130 | 2 | 5 | +3 |
| d797268e-28a9-49a7-b9a8-2f5039011c5c | 0 | 1 | +1 |
| b655a06a-31c0-477a-95c2-3726b83d649d | 0 | 1 | +1 |

Rules whose count changes by more than 5, explained:

- `5ef9853e-4d0e-4a70-846f-a9ca37d876da`: LSASS credential-dumping rule (process_access): selection matches lsass.exe accesses with dumping masks and call-trace DLLs. All 33 gained rows carry no SourceUser key in the wire payload (Sysmon 10 logs none; flat, winlog and EVTX layouts, read with the normalizer's own extraction), so `not filter_main_system_user` is null over them under the old semantics (excluded) and true under Sigma NOT (included).
- `49f2f17b-b4c8-4172-a68b-d5bf95d05130`: UAC bypass via ICMLuaUtil (process_creation): selection is a dllhost parent with the COM Processid. The 2 pre-existing matches carry a non-WerFault OriginalFileName (Cmd.Exe, WinWord.exe). The 3 gained rows have Image cmd.exe but no OriginalFileName key in the wire payload, so the negated WerFault disjunction is null over them under the old semantics (excluded) and true under Sigma NOT (included).
- `d797268e-28a9-49a7-b9a8-2f5039011c5c`: WSReset UAC-bypass rule (process_creation): the gained row (EVTX layout, wire payload read) has ParentImage WSReset.exe and Image cmd.exe but no OriginalFileName key, so `not (Image conhost or OriginalFileName CONHOST)` is null over it under the old semantics (excluded) and true under Sigma NOT (included).
- `b655a06a-31c0-477a-95c2-3726b83d649d`: Suspicious userinit child (process_creation): the gained row (EVTX layout, wire payload read) parents userinit.exe to a randomly-named executable whose CommandLine matches none of the negated netlogon/explorer alternatives, with no OriginalFileName key, so the negated disjunction is null over it under the old semantics (excluded) and true under Sigma NOT (included).

## Rules

- rule files: n=2240; parsed rules: n=2240
- evaluated: n=1792; skipped: n=448

| reason | n | top details |
| --- | --- | --- |
| status | 145 | experimental (145) |
| logsource | 183 | product=windows category=None service=application (17), product=windows category=pipe_created service=None (16), product=windows category=None service=windefend (14), product=windows category=dns_query service=None (14), product=windows category=create_remote_thread service=None (11) |
| event_id | 104 | security EventID=[5145] (15), security EventID=[4656, 4663] (7), security EventID=[4662] (6), security EventID=[5136] (4), security EventID=[4661] (3) |
| unmapped_field | 16 | network_connection CommandLine (4), file_event CommandLine (3), security Workstation (2), file_event ParentImage (2), image_load CommandLine (2) |
| unsupported_construct | 0 |  |

Runtime conversion errors during evaluation: n=0.

## Findings

- findings total: n=5780 on n=5437 events
- findings on the APT29 day-1 file: n=1477
- findings with no ATT&CK tactic: n=0

| level | whole store (n) | APT29 day-1 (n) |
| --- | --- | --- |
| critical | 19 | 0 |
| high | 1370 | 132 |
| medium | 4391 | 1345 |
| low | 0 | 0 |
| informational | 0 | 0 |

| tactic | whole store (n) | APT29 day-1 (n) |
| --- | --- | --- |
| Collection | 9 | 6 |
| Command and Control | 124 | 2 |
| Credential Access | 209 | 10 |
| Defense Impairment | 352 | 113 |
| Discovery | 215 | 13 |
| Execution | 4430 | 995 |
| Exfiltration | 11 | 5 |
| Impact | 21 | 9 |
| Initial Access | 23 | 0 |
| Lateral Movement | 111 | 13 |
| Persistence | 425 | 295 |
| Privilege Escalation | 336 | 12 |
| Resource Development | 25 | 20 |
| Stealth | 419 | 13 |

## OTRF atomic files with techniques

- ground-truth files with techniques: n=144; n=110 have events in the replay store, n=34 do not (network/pcap datasets, never ingested: no findings possible, excluded below)

- all rules: n=110 files with techniques in the store; 86 have >=1 finding; 48 have a finding whose technique (parent) matches ground truth

| file | findings (n) | technique match | matched techniques |
| --- | --- | --- | --- |
| security-datasets/datasets/atomic/windows/collection/host/msf_record_mic | 1 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/cmd_dumping_ntds_dit_file_ntdsutil | 3 | yes | T1003, T1003.003 |
| security-datasets/datasets/atomic/windows/credential_access/host/cmd_lsass_memory_dumpert_syscalls | 6 | yes | T1003, T1003.001 |
| security-datasets/datasets/atomic/windows/credential_access/host/cmd_psexec_lsa_secrets_dump | 4 | yes | T1003, T1003.004 |
| security-datasets/datasets/atomic/windows/credential_access/host/cmd_sam_copy_esentutl | 2 | yes | T1003, T1003.002 |
| security-datasets/datasets/atomic/windows/credential_access/host/covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges | 0 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_dcsync_dcerpc_drsuapi_DsGetNCChanges | 0 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_mimikatz_backupkeys_dcerpc_smb_lsarpc | 3 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_mimikatz_extract_keys | 1 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords | 0 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_mimikatz_lsadump_patch | 1 | yes | T1003, T1003.001 |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_mimikatz_sam_access | 0 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_ninjacopy_dumping_ntds_dit_file | 5 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_over_pth_patch_lsass | 166 | yes | T1550, T1550.002 |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_powerdump_sam_access | 3 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_shell_reg_dump_sam | 1 | yes | T1003, T1003.002 |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_shell_rubeus_asktgt_createnetonly | 5 | yes | T1003 |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_shell_rubeus_asktgt_ptt | 2 | yes | T1003 |
| security-datasets/datasets/atomic/windows/credential_access/host/psh_input_capture_promptforcreds | 0 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/psh_lsass_memory_dump_comsvcs | 7 | yes | T1003, T1003.001 |
| security-datasets/datasets/atomic/windows/credential_access/host/psh_windows_vault_web_credentials | 0 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/rdp_interactive_taskmanager_lsass_dump | 5 | yes | T1003, T1003.001 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/auditpol_system_user_auditpolicy_modification | 6 | yes | T1685 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_bitsadmin_download_psh_script | 4 | yes | T1197 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_disable_eventlog_service_startuptype_modification_via_registry | 0 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_mshta_javascript_getobject_sct | 2 | yes | T1218, T1218.005 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_mshta_vbscript_execute_psh | 4 | yes | T1218, T1218.005 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_netsh_fw_mod_open_ports | 2 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_process_herpaderping_snippingtool | 1 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_psh_stop_netprofm_eventlog_after_reboot | 0 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_psh_stop_netprofm_eventlog_before_reboot | 0 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_stop_event_logging_controlset001_minint_key | 1 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_stop_event_logging_controlset_minint_key | 0 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_wevtutil_modify_security_eventlog_path | 2 | yes | T1685 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/covenant_installutil | 3 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/covenant_lolbin_wuauclt_createremotethread | 2 | yes | T1218 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_dllinjection_LoadLibrary_CreateRemoteThread | 424 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_enable_rdp.tar.gz | 17 | yes | T1112 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_launcher_sct_regsvr32 | 11 | yes | T1218, T1218.010 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_monologue_netntlm_downgrade | 74 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_powerview_ldap_ntsecuritydescriptor | 12 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_psinject_PEinjection | 101 | yes | T1055 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_wdigest_downgrade.tar.gz | 17 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_cmstp_execution_bypassuac | 5 | yes | T1218, T1218.003 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_control_panel_execution | 1 | yes | T1218, T1218.002 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_disable_eventlog_service_startuptype_modification | 23 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_hh_local_html_payload | 2 | yes | T1218, T1218.001 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_mavinject_dll_notepad | 3 | yes | T1055 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_metasploit_stop_netprofm_eventlog_after_reboot | 26 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_metasploit_stop_netprofm_eventlog_before_reboot | 24 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_mshta_html_application_execution | 7 | yes | T1218, T1218.005 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_register_cimprovider_execute_dll | 2 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_stop_event_logging_controlset001_minint_key | 25 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_stop_event_logging_controlset_minint_key | 24 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/purplesharp_pe_injection_createremotethread | 4 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/reg_cmd_process_commandline_logging_disabled | 0 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/reg_disable_eventlog_service_startuptype_modification_via_registry | 0 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/reg_meterpreter_process_commandline_logging_disabled | 0 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/reg_stop_event_logging_controlset001_minint_key | 0 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/reg_stop_event_logging_controlset_minint_key | 0 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/wmic_remote_xsl_jscript | 2 | yes | T1220 |
| security-datasets/datasets/atomic/windows/discovery/host/cmd_discover_iexplorer_version_registry | 1 | yes | T1518 |
| security-datasets/datasets/atomic/windows/discovery/host/cmd_seatbelt_group_user | 1 | no |  |
| security-datasets/datasets/atomic/windows/discovery/host/covenant_getdomaingroup_ldap_searchrequest_domain_admins | 1 | no |  |
| security-datasets/datasets/atomic/windows/discovery/host/empire_find_localadmin_smb_svcctl_OpenSCManager | 67 | yes | T1069, T1069.001 |
| security-datasets/datasets/atomic/windows/discovery/host/empire_getsession_dcerpc_smb_srvsvc_NetSessEnum | 277 | no |  |
| security-datasets/datasets/atomic/windows/discovery/host/empire_shell_net_local_users | 0 | no |  |
| security-datasets/datasets/atomic/windows/discovery/host/empire_shell_net_localgroup_administrators | 2 | no |  |
| security-datasets/datasets/atomic/windows/discovery/host/empire_shell_rpc_samr_smb_group_domain_admins_standard_user | 2 | no |  |
| security-datasets/datasets/atomic/windows/discovery/host/empire_shell_samr_EnumDomainUsers | 0 | no |  |
| security-datasets/datasets/atomic/windows/execution/host/cmd_sharpview_pcre_net | 3 | yes | T1059 |
| security-datasets/datasets/atomic/windows/execution/host/empire_launcher_vbs | 6 | yes | T1059 |
| security-datasets/datasets/atomic/windows/execution/host/psh_powershell_httplistener | 0 | no |  |
| security-datasets/datasets/atomic/windows/execution/host/psh_python_webserver | 2 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/aadinternals_export_adfsdatabaseconfig_remotely | 0 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_copy_smb_CreateRequest | 0 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_dcom_executeexcel4macro_allowed | 4 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_dcom_iertutil_dll_hijack | 3 | yes | T1021, T1021.003 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_dcom_registerxll | 170 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_psremoting_command | 97 | yes | T1021, T1021.006 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_sc_query_dcerpc_smb_svcctl | 0 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_sharpsc_create_dcerpc_smb_svcctl | 0 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_sharpsc_query_dcerpc_smb_svcctl | 0 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_sharpsc_start_dcerpc_smb_svcctl | 176 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_sharpsc_stop_dcerpc_smb_svcctl | 1 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_sharpwmi_create_dcerpc_wmi | 2 | yes | T1047 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_wmi_remote_event_subscription_ActiveScriptEventConsumers | 1 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_wmi_wbemcomn_dll_hijack | 181 | yes | T1047 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_dcom_shellwindows_stager | 8 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_msbuild_dcerpc_wmi_smb | 10 | yes | T1047 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl | 11 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_psremoting_stager | 11 | yes | T1021, T1021.006 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_shell_dcerpc_smb_service_dll_hijack | 175 | yes | T1574, T1574.001 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_smbexec_dcerpc_smb_svcctl | 13 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod | 280 | yes | T1047 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_wmic_add_user_backdoor | 5 | yes | T1047 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/mimikatz_CVE-2020-1472_Unauthenticated_NetrServerAuthenticate2 | 3 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/purplesharp_ad_playbook_I | 295 | yes | T1021, T1021.006 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/schtask_create | 5 | yes | T1053, T1053.005 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/schtask_modification | 2 | no |  |
| security-datasets/datasets/atomic/windows/other/aptsimulator_cobaltstrike | 6 | yes | T1134, T1134.001, T1134.002 |
| security-datasets/datasets/atomic/windows/persistence/host/cmd_userinitmprlogonscript_batch | 1 | yes | T1037, T1037.001 |
| security-datasets/datasets/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_elevated_user | 0 | no |  |
| security-datasets/datasets/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_standard_user | 186 | no |  |
| security-datasets/datasets/atomic/windows/persistence/host/empire_schtasks_creation_execution_elevated_user | 186 | yes | T1053, T1053.005 |
| security-datasets/datasets/atomic/windows/persistence/host/empire_schtasks_creation_standard_user | 3 | yes | T1053, T1053.005 |
| security-datasets/datasets/atomic/windows/persistence/host/empire_wmi_local_event_subscriptions_elevated_user | 239 | no |  |
| security-datasets/datasets/atomic/windows/persistence/host/proxylogon_ssrf_rce_poc | 7 | yes | T1505, T1505.003 |
| security-datasets/datasets/atomic/windows/privilege_escalation/host/cmd_service_mod_fax | 5 | yes | T1543, T1543.003 |
| security-datasets/datasets/atomic/windows/privilege_escalation/host/empire_uac_shellapi_fodhelper | 108 | yes | T1548, T1548.002 |

- without disclosed rules: n=110 files with techniques in the store; 86 have >=1 finding; 48 have a finding whose technique (parent) matches ground truth

| file | findings (n) | technique match | matched techniques |
| --- | --- | --- | --- |
| security-datasets/datasets/atomic/windows/collection/host/msf_record_mic | 1 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/cmd_dumping_ntds_dit_file_ntdsutil | 3 | yes | T1003, T1003.003 |
| security-datasets/datasets/atomic/windows/credential_access/host/cmd_lsass_memory_dumpert_syscalls | 6 | yes | T1003, T1003.001 |
| security-datasets/datasets/atomic/windows/credential_access/host/cmd_psexec_lsa_secrets_dump | 4 | yes | T1003, T1003.004 |
| security-datasets/datasets/atomic/windows/credential_access/host/cmd_sam_copy_esentutl | 2 | yes | T1003, T1003.002 |
| security-datasets/datasets/atomic/windows/credential_access/host/covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges | 0 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_dcsync_dcerpc_drsuapi_DsGetNCChanges | 0 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_mimikatz_backupkeys_dcerpc_smb_lsarpc | 3 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_mimikatz_extract_keys | 1 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords | 0 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_mimikatz_lsadump_patch | 1 | yes | T1003, T1003.001 |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_mimikatz_sam_access | 0 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_ninjacopy_dumping_ntds_dit_file | 5 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_over_pth_patch_lsass | 166 | yes | T1550, T1550.002 |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_powerdump_sam_access | 3 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_shell_reg_dump_sam | 1 | yes | T1003, T1003.002 |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_shell_rubeus_asktgt_createnetonly | 5 | yes | T1003 |
| security-datasets/datasets/atomic/windows/credential_access/host/empire_shell_rubeus_asktgt_ptt | 2 | yes | T1003 |
| security-datasets/datasets/atomic/windows/credential_access/host/psh_input_capture_promptforcreds | 0 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/psh_lsass_memory_dump_comsvcs | 7 | yes | T1003, T1003.001 |
| security-datasets/datasets/atomic/windows/credential_access/host/psh_windows_vault_web_credentials | 0 | no |  |
| security-datasets/datasets/atomic/windows/credential_access/host/rdp_interactive_taskmanager_lsass_dump | 5 | yes | T1003, T1003.001 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/auditpol_system_user_auditpolicy_modification | 6 | yes | T1685 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_bitsadmin_download_psh_script | 4 | yes | T1197 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_disable_eventlog_service_startuptype_modification_via_registry | 0 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_mshta_javascript_getobject_sct | 2 | yes | T1218, T1218.005 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_mshta_vbscript_execute_psh | 4 | yes | T1218, T1218.005 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_netsh_fw_mod_open_ports | 2 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_process_herpaderping_snippingtool | 1 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_psh_stop_netprofm_eventlog_after_reboot | 0 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_psh_stop_netprofm_eventlog_before_reboot | 0 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_stop_event_logging_controlset001_minint_key | 1 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_stop_event_logging_controlset_minint_key | 0 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/cmd_wevtutil_modify_security_eventlog_path | 2 | yes | T1685 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/covenant_installutil | 3 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/covenant_lolbin_wuauclt_createremotethread | 2 | yes | T1218 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_dllinjection_LoadLibrary_CreateRemoteThread | 424 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_enable_rdp.tar.gz | 17 | yes | T1112 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_launcher_sct_regsvr32 | 11 | yes | T1218, T1218.010 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_monologue_netntlm_downgrade | 74 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_powerview_ldap_ntsecuritydescriptor | 12 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_psinject_PEinjection | 101 | yes | T1055 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/empire_wdigest_downgrade.tar.gz | 17 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_cmstp_execution_bypassuac | 5 | yes | T1218, T1218.003 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_control_panel_execution | 1 | yes | T1218, T1218.002 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_disable_eventlog_service_startuptype_modification | 23 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_hh_local_html_payload | 2 | yes | T1218, T1218.001 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_mavinject_dll_notepad | 3 | yes | T1055 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_metasploit_stop_netprofm_eventlog_after_reboot | 26 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_metasploit_stop_netprofm_eventlog_before_reboot | 24 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_mshta_html_application_execution | 6 | yes | T1218, T1218.005 |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_register_cimprovider_execute_dll | 2 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_stop_event_logging_controlset001_minint_key | 25 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/psh_stop_event_logging_controlset_minint_key | 24 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/purplesharp_pe_injection_createremotethread | 4 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/reg_cmd_process_commandline_logging_disabled | 0 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/reg_disable_eventlog_service_startuptype_modification_via_registry | 0 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/reg_meterpreter_process_commandline_logging_disabled | 0 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/reg_stop_event_logging_controlset001_minint_key | 0 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/reg_stop_event_logging_controlset_minint_key | 0 | no |  |
| security-datasets/datasets/atomic/windows/defense_evasion/host/wmic_remote_xsl_jscript | 2 | yes | T1220 |
| security-datasets/datasets/atomic/windows/discovery/host/cmd_discover_iexplorer_version_registry | 1 | yes | T1518 |
| security-datasets/datasets/atomic/windows/discovery/host/cmd_seatbelt_group_user | 1 | no |  |
| security-datasets/datasets/atomic/windows/discovery/host/covenant_getdomaingroup_ldap_searchrequest_domain_admins | 1 | no |  |
| security-datasets/datasets/atomic/windows/discovery/host/empire_find_localadmin_smb_svcctl_OpenSCManager | 67 | yes | T1069, T1069.001 |
| security-datasets/datasets/atomic/windows/discovery/host/empire_getsession_dcerpc_smb_srvsvc_NetSessEnum | 277 | no |  |
| security-datasets/datasets/atomic/windows/discovery/host/empire_shell_net_local_users | 0 | no |  |
| security-datasets/datasets/atomic/windows/discovery/host/empire_shell_net_localgroup_administrators | 2 | no |  |
| security-datasets/datasets/atomic/windows/discovery/host/empire_shell_rpc_samr_smb_group_domain_admins_standard_user | 2 | no |  |
| security-datasets/datasets/atomic/windows/discovery/host/empire_shell_samr_EnumDomainUsers | 0 | no |  |
| security-datasets/datasets/atomic/windows/execution/host/cmd_sharpview_pcre_net | 3 | yes | T1059 |
| security-datasets/datasets/atomic/windows/execution/host/empire_launcher_vbs | 6 | yes | T1059 |
| security-datasets/datasets/atomic/windows/execution/host/psh_powershell_httplistener | 0 | no |  |
| security-datasets/datasets/atomic/windows/execution/host/psh_python_webserver | 2 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/aadinternals_export_adfsdatabaseconfig_remotely | 0 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_copy_smb_CreateRequest | 0 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_dcom_executeexcel4macro_allowed | 4 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_dcom_iertutil_dll_hijack | 3 | yes | T1021, T1021.003 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_dcom_registerxll | 170 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_psremoting_command | 97 | yes | T1021, T1021.006 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_sc_query_dcerpc_smb_svcctl | 0 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_sharpsc_create_dcerpc_smb_svcctl | 0 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_sharpsc_query_dcerpc_smb_svcctl | 0 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_sharpsc_start_dcerpc_smb_svcctl | 176 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_sharpsc_stop_dcerpc_smb_svcctl | 1 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_sharpwmi_create_dcerpc_wmi | 2 | yes | T1047 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_wmi_remote_event_subscription_ActiveScriptEventConsumers | 1 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/covenant_wmi_wbemcomn_dll_hijack | 181 | yes | T1047 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_dcom_shellwindows_stager | 8 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_msbuild_dcerpc_wmi_smb | 10 | yes | T1047 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl | 11 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_psremoting_stager | 11 | yes | T1021, T1021.006 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_shell_dcerpc_smb_service_dll_hijack | 175 | yes | T1574, T1574.001 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_smbexec_dcerpc_smb_svcctl | 13 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_wmi_dcerpc_wmi_IWbemServices_ExecMethod | 280 | yes | T1047 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/empire_wmic_add_user_backdoor | 5 | yes | T1047 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/mimikatz_CVE-2020-1472_Unauthenticated_NetrServerAuthenticate2 | 3 | no |  |
| security-datasets/datasets/atomic/windows/lateral_movement/host/purplesharp_ad_playbook_I | 295 | yes | T1021, T1021.006 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/schtask_create | 5 | yes | T1053, T1053.005 |
| security-datasets/datasets/atomic/windows/lateral_movement/host/schtask_modification | 2 | no |  |
| security-datasets/datasets/atomic/windows/other/aptsimulator_cobaltstrike | 6 | yes | T1134, T1134.001, T1134.002 |
| security-datasets/datasets/atomic/windows/persistence/host/cmd_userinitmprlogonscript_batch | 1 | yes | T1037, T1037.001 |
| security-datasets/datasets/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_elevated_user | 0 | no |  |
| security-datasets/datasets/atomic/windows/persistence/host/empire_persistence_registry_modification_run_keys_standard_user | 186 | no |  |
| security-datasets/datasets/atomic/windows/persistence/host/empire_schtasks_creation_execution_elevated_user | 186 | yes | T1053, T1053.005 |
| security-datasets/datasets/atomic/windows/persistence/host/empire_schtasks_creation_standard_user | 3 | yes | T1053, T1053.005 |
| security-datasets/datasets/atomic/windows/persistence/host/empire_wmi_local_event_subscriptions_elevated_user | 239 | no |  |
| security-datasets/datasets/atomic/windows/persistence/host/proxylogon_ssrf_rce_poc | 7 | yes | T1505, T1505.003 |
| security-datasets/datasets/atomic/windows/privilege_escalation/host/cmd_service_mod_fax | 5 | yes | T1543, T1543.003 |
| security-datasets/datasets/atomic/windows/privilege_escalation/host/empire_uac_shellapi_fodhelper | 108 | yes | T1548, T1548.002 |

## APT29 day-1 steps

Step windows overlap, so per-step finding counts do not sum to
the file total.

### all rules

| step | window (UTC) | findings in window (n) | technique match | matched techniques |
| --- | --- | --- | --- | --- |
| 1 Initial Breach | 2020-05-02T02:55:57Z .. 2020-05-02T03:02:06Z | 847 | yes | T1059, T1059.001 |
| 2 Rapid Collection and Exfiltration | 2020-05-02T02:56:18Z .. 2020-05-02T03:03:16Z | 850 | no |  |
| 3 Deploy Stealth Toolkit | 2020-05-02T02:57:01Z .. 2020-05-02T03:08:53Z | 880 | yes | T1027, T1112, T1548, T1548.002 |
| 4 Defense Evasion and Discovery | 2020-05-02T02:59:44Z .. 2020-05-02T03:18:22Z | 1409 | yes | T1059, T1059.001, T1069 |
| 5 Persistence | 2020-05-02T03:04:16Z .. 2020-05-02T03:04:24Z | 2 | yes | T1547, T1547.001 |
| 6 Credential Access | 2020-05-02T03:00:37Z .. 2020-05-02T03:05:20Z | 562 | yes | T1003, T1003.001, T1036, T1552, T1552.004 |
| 7 Collection and Exfiltration | 2020-05-02T03:05:46Z .. 2020-05-02T03:07:15Z | 11 | yes | T1056, T1056.001, T1113, T1115 |
| 8 Lateral Movement | 2020-05-02T03:00:26Z .. 2020-05-02T03:18:22Z | 1408 | yes | T1021, T1021.002, T1021.006, T1027, T1569, T1569.002 |
| 9 Collection | 2020-05-02T03:15:32Z .. 2020-05-02T03:17:43Z | 434 | yes | T1059, T1059.001, T1560, T1560.001 |
| 10 Persistence Execution | 2020-05-02T03:19:53Z .. 2020-05-02T03:28:20Z | 44 | no |  |

### without disclosed rules

| step | window (UTC) | findings in window (n) | technique match | matched techniques |
| --- | --- | --- | --- | --- |
| 1 Initial Breach | 2020-05-02T02:55:57Z .. 2020-05-02T03:02:06Z | 844 | yes | T1059, T1059.001 |
| 2 Rapid Collection and Exfiltration | 2020-05-02T02:56:18Z .. 2020-05-02T03:03:16Z | 847 | no |  |
| 3 Deploy Stealth Toolkit | 2020-05-02T02:57:01Z .. 2020-05-02T03:08:53Z | 873 | yes | T1027, T1548, T1548.002 |
| 4 Defense Evasion and Discovery | 2020-05-02T02:59:44Z .. 2020-05-02T03:18:22Z | 1402 | yes | T1059, T1059.001, T1069 |
| 5 Persistence | 2020-05-02T03:04:16Z .. 2020-05-02T03:04:24Z | 1 | yes | T1547, T1547.001 |
| 6 Credential Access | 2020-05-02T03:00:37Z .. 2020-05-02T03:05:20Z | 561 | yes | T1003, T1003.001, T1036, T1552, T1552.004 |
| 7 Collection and Exfiltration | 2020-05-02T03:05:46Z .. 2020-05-02T03:07:15Z | 10 | yes | T1056, T1056.001, T1113 |
| 8 Lateral Movement | 2020-05-02T03:00:26Z .. 2020-05-02T03:18:22Z | 1401 | yes | T1021, T1021.002, T1021.006, T1027, T1569, T1569.002 |
| 9 Collection | 2020-05-02T03:15:32Z .. 2020-05-02T03:17:43Z | 434 | yes | T1059, T1059.001, T1560, T1560.001 |
| 10 Persistence Execution | 2020-05-02T03:19:53Z .. 2020-05-02T03:28:20Z | 44 | no |  |

## Disclosure: rules referencing the measured datasets

In-scope rules whose `references` cite OTRF / Security-Datasets,
Mordor, the APT29 evaluations, or EVTX-ATTACK-SAMPLES. A rule
written from the dataset being measured detects it by
construction, so the OTRF and APT29 numbers above are repeated
without these rules.

- disclosed rules: n=9 of n=1792 evaluated

| rule id | markers |
| --- | --- |
| 1070db9a-3e5d-412e-8e7b-7183b616e1b3 | apt29 |
| 18249279-932f-45e2-b37a-8925f2597670 | apt29 |
| 2aa0a6b4-a865-495b-ab51-c28249537b75 | apt29, otrf |
| 2dbd9d3d-9e27-42a8-b8df-f13825c6c3d5 | apt29, otrf |
| 40f9af16-589d-4984-b78d-8c2aec023197 | apt29, otrf |
| 4cbd4f12-2e22-43e3-882f-bff3247ffb78 | apt29, otrf |
| 96f697b0-b499-4e5d-9908-a67bec11cdb6 | apt29, otrf |
| b9aeac14-2ffd-4ad3-b967-1354a4e628c3 | apt29, otrf |
| da2738f2-fadb-4394-afa7-0a0674885afa | apt29, otrf |

## Runtime

- full replay store: 73.6s evaluate (7190666 rows scanned across group passes), 166.7s end to end including rule load, the legacy measurement pass for the delta above, finding writes, and the report join
- peak RSS: 5531 MiB (process max resident set)

