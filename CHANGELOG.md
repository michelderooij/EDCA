# Changelog

## v1.0.2.0

- Added scored Best Practice controls:
  - `EDCA-SEC-046`: detect exact wildcard accepted domains.
  - `EDCA-SEC-047`: assess AMSI request-body scanning.
  - `EDCA-SEC-048`: detect conflicting setting overrides.
  - `EDCA-RES-016`: report potential Exchange maintenance state as Unknown.
  - `EDCA-MON-015`: assess Exchange IIS HTTPS certificate bindings.
  - `EDCA-MON-016`: assess Exchange IIS application-pool recycling.
  - `EDCA-MON-017`: detect active transport back pressure.
- Excluded Unknown findings from weighted scores. Scores with no assessable weight are now null in analysis data and shown as N/A in reports; detected maintenance is reported as Unknown.

## v1.0.1.2

- Updated the bundled Exchange 2016, 2019, and SE build baselines.
- Framework currency review (November 2026):
  - Exchange lifecycle: added Microsoft's explicit 2016/2019 end-of-support and migration-to-SE guidance to `EDCA-GOV-002`; confirmed the control warns on out-of-support product lines even when current on updates.
  - BSI: corrected the transition timeline. BSI Standard 300-1 v1.0 (Grundschutz++) was published in October 2026 and is certifiable from 2027; classic IT-Grundschutz certification ends 30 November 2031. Retained the current Exchange-specific APP.5.2 Edition 2023 mapping because the new requirements catalog is solution-independent.
  - NIS2: confirmed NCSC-NL TLS Guidelines 2025-05 remain current with March 2026 errata; updated the README version/date.
  - NIS2: added explicit Commission Implementing Regulation (EU) 2024/2690 references, carrying the Annex section numbers already cited:
    - `EDCA-DATA-001`, `EDCA-DATA-002`, `EDCA-DATA-003`, `EDCA-DATA-005`, `EDCA-DATA-006`, `EDCA-DATA-007`, `EDCA-DATA-008`, `EDCA-DATA-010`, `EDCA-DATA-011`, `EDCA-DATA-012`, `EDCA-DATA-013`, `EDCA-GOV-002`.
    - `EDCA-IAC-003`, `EDCA-IAC-004`, `EDCA-IAC-005`, `EDCA-IAC-008`, `EDCA-IAC-009`, `EDCA-IAC-010`, `EDCA-IAC-026`, `EDCA-IAC-027`, `EDCA-MON-001`, `EDCA-RES-001`, `EDCA-RES-003`.
    - `EDCA-SEC-014`, `EDCA-SEC-022`, `EDCA-SEC-023`, `EDCA-SEC-025`, `EDCA-SEC-043`, `EDCA-TLS-003`, `EDCA-TLS-011`, `EDCA-TLS-014`, `EDCA-TLS-021`, `EDCA-TLS-023`, `EDCA-TLS-024`, `EDCA-TLS-025`, `EDCA-TLS-026`, `EDCA-TLS-036`.
  - CIS: reference versions updated to current benchmark releases — Windows Server 2022 Benchmark v5.1.0 (`EDCA-DATA-005`, `EDCA-DATA-006`), Windows Server 2019 Benchmark v5.0.0 (`EDCA-MON-002`), Exchange Server 2019 Benchmark v1.0.1 (`EDCA-SEC-014`). CIS Controls v8.1 remains current.
  - ISM September 2026: `ISM-1448` was merged into `ISM-1372`; removed the merged identifier from `EDCA-DATA-018` and `EDCA-DATA-013`.
  - CISA: replaced the retired 2021 `CSI_MS_Exchange_Security_Best_Practices_Final.pdf` reference (URL now returns 404) in `EDCA-IAC-004` and the README framework table with the joint CISA/NSA Microsoft Exchange Server Security Best Practices guide (October 2025). Added the guide to `EDCA-DATA-004`, `EDCA-DATA-005`, `EDCA-DATA-006`, `EDCA-DATA-009`, `EDCA-GOV-002`, `EDCA-GOV-003`, `EDCA-IAC-003`, `EDCA-IAC-007`, `EDCA-IAC-008`, `EDCA-IAC-009`, `EDCA-IAC-010`, `EDCA-SEC-012`, `EDCA-SEC-014`, `EDCA-SEC-019`, `EDCA-SEC-020`, `EDCA-SEC-023`, `EDCA-SEC-032`, `EDCA-SEC-034`, `EDCA-TLS-011`, `EDCA-TLS-021`, `EDCA-TLS-024`, `EDCA-TLS-025`, and `EDCA-TLS-036`.
  - CISA: consolidated superseded AA21-062A citations with section-specific references to the October 2025 guide in `EDCA-DATA-004`, `EDCA-DATA-009`, `EDCA-GOV-003`, `EDCA-IAC-008`, `EDCA-IAC-009`, `EDCA-IAC-010`, `EDCA-SEC-012`, `EDCA-SEC-014`, `EDCA-SEC-019`, `EDCA-SEC-020`, and `EDCA-SEC-032`. Updated the corresponding Mapping.md cells and retained AA21-062A for distinct recommendations in `EDCA-IAC-007` and `EDCA-IAC-011`.
  - DISA: the 2026-09-30 STIG releases (Exchange 2019 Mailbox V2R4, Exchange 2019 Edge V2R3, Exchange 2016 Mailbox V2R7) contain wording-only changes to cited rules; stigviewer.com reference URLs still resolve to the cited revisions and remain unchanged.
  - DISA: added Edge Transport rule V-288847 to `EDCA-SEC-038`.
  - NIS2: added Implementing Regulation (EU) 2024/2690 references to `EDCA-TLS-011`, `EDCA-TLS-021`, and `EDCA-TLS-036`.
  - Added manual-review controls `EDCA-SEC-044` for the Defender webshell ASR rule and `EDCA-SEC-045` for kernel-mode driver restrictions.
  - Updated README framework versions for CIS, DISA, ISM, and NIS2; documented the BSI IT-Grundschutz++ transition and refreshed the ISM changes-document link.
  - Replaced the retired CISA PDF link in `report_sample.html`; updated the generated mapping matrix for affected framework references and IDs.

## v1.0.1.1

- Fixed categorizing DAG-related controls `EDCA-RES-013` through `EDCA-RES-015`, which resulted in `Control evaluator not implemented`.
- Updated DAG resilience controls (`EDCA-RES-012` through `EDCA-RES-015`) to report with DAG entities.
- In environments without DAG deployment, `EDCA-RES-012` through `EDCA-RES-015` now consistently return **Skipped**.

## v1.0.1.0

- Added or normalized Preferred Architecture (PA) guidance references for `EDCA-DATA-017`, `EDCA-GOV-002`, `EDCA-RES-003`, `EDCA-RES-004`, `EDCA-RES-005`, `EDCA-RES-010`, `EDCA-RES-011`, `EDCA-RES-012`, `EDCA-SEC-001`, `EDCA-SEC-038`, and `EDCA-SEC-040`.
- Added three new Best Practice, PA-based DAG resilience controls:
  - `EDCA-RES-013`: DAG SHOULD not span more than two Active Directory sites.
  - `EDCA-RES-014`: DAG SHOULD have symmetrical member distribution across sites.
  - `EDCA-RES-015`: DAG MUST have witness server settings configured.
- Added organization-level DAG topology collection (`Get-DatabaseAvailabilityGroup`) to support automated DAG topology and witness checks.
- The new DAG-scoped controls `EDCA-RES-013` through `EDCA-RES-015` show as **Skipped** when no DAG is deployed.
- README updated with requirement-term nomenclature (`MUST`, `SHOULD`, `SHALL`).

## v1.0.0.7

- Expanded and normalized NIS2 mappings for `EDCA-GOV-002`, `EDCA-IAC-003`, `EDCA-IAC-004`, `EDCA-IAC-005`, `EDCA-IAC-008`, `EDCA-IAC-009`, `EDCA-IAC-010`, `EDCA-IAC-026`, `EDCA-IAC-027`, `EDCA-SEC-014`, `EDCA-SEC-022`, `EDCA-SEC-023`, `EDCA-SEC-043`, `EDCA-TLS-023`, `EDCA-TLS-025`, and `EDCA-TLS-026`.
- Added EDCA control to security control framework table in mapping.md

## v1.0.0.6

- Updated ISM framework to June 2026:
	- `EDCA-GOV-002`, `EDCA-SEC-038`: added `ISM-2110` (system management and patch currency alignment).
	- `EDCA-MON-001`: added `ISM-2108` (system monitoring alignment).
	- `EDCA-IAC-003`, `EDCA-IAC-004`, `EDCA-IAC-005`: added `ISM-1403`, `ISM-1467`, `ISM-1470` (system hardening/authentication alignment).
	- `EDCA-TLS-027`: added `ISM-2116`, `ISM-2117` (email security alignment).
- Exchange Edge Transport server discovery via Active Directory, resulting in notice on how to run and incorporate them.

## v1.0.0.5
- `-ControlsPath` parameter renamed to `-ControlPath`.
- New switch `-InstallControls`: copies built-in control JSON files from the module's `Controls/` folder to the directory specified by `-ControlPath`. `-ControlPath` is mandatory when using this switch and must point to an existing directory. When `-Framework` is also specified, only controls tagged with at least one of the supplied frameworks are copied.
- Verified against CIS Controls framework v8.1 (EDCA-SEC-023, EDCA-SEC-026, EDCA-TLS-023, EDCA-TLS-026). Reference URLs updated to `https://www.cisecurity.org/controls/v8-1`.

## v1.0.0.4
- Fixed an issue where running `Invoke-EDCA` from a management server (with Exchange Management Tools installed but no Exchange server role) was incorrectly detected as an Edge Transport server. EDCA now correctly falls through to Active Directory discovery on machines where Exchange services are not running.

## v1.0.0.3
- Fixed an error in EDCA-DATA-001 that occurred when a certificate on an Exchange server had no services assigned to it.
- Fixed an error when running `Invoke-EDCA -Report` with no data files in the Data folder. The error message now clearly tells you to run `-Collect` first.

## v1.0.0.0
- First stable release — published to the PowerShell Gallery. Install with `Install-Module -Name EDCA`.
- EDCA-SEC-032, EDCA-DATA-016: SettingOverride server loops now skip Edge Transport servers. When every server in the collection is an Edge Transport server, the control is reported as **Skipped** (Edge Transport servers do not support `Get-SettingOverride`).
- EDCA-SEC-006: Added Edge Transport early-exit guard alongside the existing non-Exchange-server guard.
- Fixed `ConvertFrom-Json` error when a JSON data file contains duplicate case-variant keys (e.g. `value` / `Value` produced by serialised `EnhancedTimeSpan` objects). On PS 7+ the parser falls back to `-AsHashtable`; on PS 5.1 it falls back to `JavaScriptSerializer`, which silently absorbs duplicate keys.

## v0.9.4.0
- EDCA is now distributed as a PowerShell module (`EDCA.psm1` / `EDCA.psd1`). Import with `Import-Module .\EDCA\EDCA.psd1`.
- New cmdlet: `Invoke-EDCA` — single exported public function; accepts the same parameters as the previous `EDCA.ps1` script.
- `EDCA.ps1` is now a thin wrapper that imports the module and delegates to `Invoke-EDCA`; all existing usages of `.\EDCA.ps1` continue to work unchanged.

## v0.93 Preview
- Controls library split into individual JSON files: `Config/controls.json` has been replaced by a `Controls/` directory containing one JSON file per control, named after the control ID (e.g. `EDCA-DATA-001.json`). This makes individual controls easier to manage, review, and contribute to.
- `-ControlFile` parameter renamed to `-ControlsPath`; it now accepts a directory path (default: `.\Controls`). EDCA loads all `*.json` files from that directory at startup.

## v0.92 Preview
- Added ASD ISM mappings and references to existing controls:
  - `EDCA-DATA-005`, `EDCA-DATA-006`, `EDCA-DATA-010`, `EDCA-DATA-011`, `EDCA-DATA-012`, `EDCA-DATA-013`, `EDCA-DATA-014`, `EDCA-DATA-016`, `EDCA-DATA-017`, `EDCA-DATA-018`, `EDCA-GOV-002`.
  - `EDCA-IAC-003`, `EDCA-IAC-004`, `EDCA-IAC-005`, `EDCA-IAC-008`, `EDCA-IAC-009`, `EDCA-IAC-010`, `EDCA-IAC-026`, `EDCA-MON-001`, `EDCA-MON-002`, `EDCA-MON-013`, `EDCA-MON-014`.
  - `EDCA-SEC-038`, `EDCA-SEC-039`, `EDCA-TLS-011`, `EDCA-TLS-014`, `EDCA-TLS-021`, `EDCA-TLS-023`, `EDCA-TLS-025`, `EDCA-TLS-026`, `EDCA-TLS-027`.
- You can now select multiple frameworks, multiple RAG states, categories or targets in the report.
- Controls quality pass: updated descriptions for:
  - `EDCA-DATA-001`, `EDCA-DATA-002`, `EDCA-DATA-003`, `EDCA-DATA-004`, `EDCA-DATA-008`, `EDCA-DATA-009`, `EDCA-DATA-010`, `EDCA-DATA-014`, `EDCA-DATA-015`, `EDCA-DATA-019`.
  - `EDCA-GOV-003`, `EDCA-GOV-004`, `EDCA-GOV-005`, `EDCA-GOV-006`, `EDCA-GOV-007`, `EDCA-GOV-008`, `EDCA-GOV-009`, `EDCA-GOV-011`, `EDCA-GOV-012`.
  - `EDCA-IAC-002`, `EDCA-IAC-003`, `EDCA-IAC-005`, `EDCA-IAC-006`, `EDCA-IAC-007`, `EDCA-IAC-011`, `EDCA-IAC-012`, `EDCA-IAC-013`, `EDCA-IAC-026`, `EDCA-IAC-027`, `EDCA-IAC-028`.
  - `EDCA-MON-001`, `EDCA-MON-002`, `EDCA-MON-004`, `EDCA-MON-005`, `EDCA-MON-006`, `EDCA-MON-007`, `EDCA-MON-008`, `EDCA-MON-009`, `EDCA-MON-012`.
  - `EDCA-PERF-001`, `EDCA-PERF-003`, `EDCA-PERF-004`, `EDCA-PERF-005`, `EDCA-PERF-007`, `EDCA-PERF-009`, `EDCA-PERF-010`, `EDCA-PERF-011`.
  - `EDCA-RES-002`, `EDCA-RES-004`, `EDCA-RES-005`, `EDCA-RES-006`, `EDCA-RES-007`, `EDCA-RES-008`, `EDCA-RES-010`, `EDCA-RES-011`.
  - `EDCA-SEC-001`, `EDCA-SEC-006`, `EDCA-SEC-007`, `EDCA-SEC-011`, `EDCA-SEC-012`, `EDCA-SEC-014`, `EDCA-SEC-015`, `EDCA-SEC-017`, `EDCA-SEC-018`, `EDCA-SEC-020`, `EDCA-SEC-027`, `EDCA-SEC-029`, `EDCA-SEC-030`, `EDCA-SEC-031`, `EDCA-SEC-032`, `EDCA-SEC-033`, `EDCA-SEC-037`, `EDCA-SEC-042`, `EDCA-SEC-043`.
  - `EDCA-TLS-001`, `EDCA-TLS-002`, `EDCA-TLS-003`, `EDCA-TLS-004`, `EDCA-TLS-005`, `EDCA-TLS-006`, `EDCA-TLS-010`, `EDCA-TLS-011`, `EDCA-TLS-014`, `EDCA-TLS-015`, `EDCA-TLS-016`, `EDCA-TLS-017`, `EDCA-TLS-018`, `EDCA-TLS-019`, `EDCA-TLS-020`, `EDCA-TLS-023`, `EDCA-TLS-024`, `EDCA-TLS-025`, `EDCA-TLS-026`, `EDCA-TLS-030`, `EDCA-TLS-045`.


## v0.91 Preview
- EDCA-TLS-041 (SMTP banner — Edge server false Pass): fixed a false Pass result on Edge Transport servers.
- Added sample Report and Remediation script to repo

## v0.9 Preview
- Standalone Edge auto-detection: when running `-Collect` without `-Servers` on a standalone Edge Transport server that cannot reach Active Directory, EDCA now automatically falls back to collecting from the local server (`$env:COMPUTERNAME`) instead of terminating with an AD connectivity error. A warning is printed and logged so the override is visible in the output. If Exchange is not installed locally and AD is unreachable, the original error is still thrown.
- EDCA-RES-001 (Required Exchange services running): fixed "Test-ServiceHealth via endpoint failed: The syntax is not supported by this runspace" warning on Mailbox and Edge servers. The `Select-Object` call passed a calculated property script block to the remote Exchange PSSession endpoint, which runs in ConstrainedLanguage mode and does not allow script blocks in calculated properties. Fixed by using plain property selection (`Select-Object -Property Role, RequiredServicesRunning, ServicesNotRunning`) and relying on normal WinRM deserialization; Analysis.ps1 already iterates `ServicesNotRunning` with `[string]$_` so no downstream change is needed.
- EDCA-SEC-013 (Credential Guard): added remediation script template to disable Credential Guard by clearing the `LsaCfgFlags` and `EnableVirtualizationBasedSecurity` registry values, with an explanatory note that a reboot is required.
- EDCA-SEC-033 (Transport pickup directory): control is now scoped to Mailbox servers only; Edge Transport servers are excluded.
- EDCA-SEC-037 (SMTP banner / software disclosure): removed as a standalone Platform Security control. The check is now merged into EDCA-TLS-041 (see below), which already assessed SMTP banners on Edge servers. The control ID `EDCA-SEC-037` is reused for the LDAP client signing control (formerly `EDCA-SEC-044`).
- EDCA-SEC-037 (LDAP client signing, formerly EDCA-SEC-044): renumbered from `EDCA-SEC-044` to fill the gap left by the removed banner control. Group Policy remediation reference added: *Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options — Network security: LDAP client signing requirements = Require signing*.
- EDCA-TLS-039 (Internal receive connector — RequireTLS): fixed "No internal Receive connectors identified" being incorrectly reported on Edge Transport servers. The previous filter excluded connectors that bind to `0.0.0.0:25` — which is the binding used by the EdgeSync-created internal connector. The fix uses `AuthMechanism -match '\bExchangeServer\b'` to distinguish internal connectors (added by EdgeSync, which include `ExchangeServer` in their AuthMechanism) from internet-facing ones (which do not).
- EDCA-TLS-040 (Internal receive connector — anonymous connections): same root cause and fix as EDCA-TLS-039.
- EDCA-TLS-041 (SMTP banner): extended to cover both Mailbox and Edge servers. For Mailbox servers, internet-facing connectors are identified by `AnonymousUsers` in PermissionGroups and `Tls/None` AuthMechanism. For Edge servers, internet-facing connectors are those without `ExchangeServer` in AuthMechanism. Banner evaluation uses improved logic: missing banner → Unknown; banner matching `exchange` or `15.x.x` → Fail; custom non-revealing banner → Pass.
- Group Policy remediation references added to remediation script templates for: EDCA-SEC-018 (LLMNR/DNS Client), EDCA-SEC-022 (PowerShell execution policy), EDCA-SEC-023 (SMBv1), EDCA-SEC-025 (Windows Firewall), EDCA-SEC-026 (Defender real-time protection), EDCA-SEC-037/formerly-SEC-044 (LDAP signing), EDCA-SEC-041 (LAPS), EDCA-SEC-042 (NetBIOS), EDCA-SEC-043 (SMB signing).
- Server-scoped remediation scripts: all remediation script templates that call server-level cmdlets now target `$env:COMPUTERNAME` explicitly (e.g. `Set-TransportService -Identity $env:COMPUTERNAME`, `Get-ReceiveConnector -Server $env:COMPUTERNAME`) instead of using all-server pipes or placeholder tokens.
- Database-scoped remediation scripts: all remediation script templates that call `Set-MailboxDatabase` now target a single database via `-Identity 'DatabaseName'` instead of piping from `Get-MailboxDatabase`.
- EDCA-MON-010 (Audit log directory ACL): fixed "AuditLogPathAcl data not available" being reported when the Exchange audit log path was set to the default `<InstallPath>\Logging` folder. Two collection bugs caused `AuditLogPathAcl` to always be empty: (1) a `Where-Object` filter that incorrectly discarded all ACE entries from `FileSystemAccessRule` objects, and (2) the enrichment phase using `Invoke-Command` to retrieve a `DirectorySecurity` object whose `Access` collection is lost during WinRM serialization. Both are fixed: the filter is removed (matching the working `InstallPathAcl` pattern), and ACL entries are now processed inside the remote scriptblock before being returned.
- Copy button added to remediation script blocks in the HTML report — click it to copy the script to the clipboard.
- EDCA-DATA-003 (Internal transport certificate baseline): control is now skipped for Edge Transport servers.
- EDCA-GOV-004 (Exchange Hybrid Application baseline): fixed "Hybrid application telemetry unavailable" being reported incorrectly in environments with Edge Transport servers. The analysis now skips Edge servers (which never collect hybrid application data) and uses the first Mailbox server with collected data.
- EDCA-IAC-011 (Dedicated hybrid app EvoSTS AuthServer): fixed "Hybrid application telemetry unavailable" being reported incorrectly in environments with Edge Transport servers. Same root cause as EDCA-GOV-004 — the server loop now skips servers where `HybridApplication` is `$null`.
- EDCA-IAC-010 (Administrative access to EAC and remote PowerShell): converted from a manual-verification control to an automated org-level check. Now evaluates two sub-checks: (1) whether Client Access Rules are configured that restrict the `RemotePowerShell` or `ExchangeAdminCenter` protocol, and (2) whether any non-Exchange-administrative users (users not in any Exchange RBAC role group) have `RemotePowerShellEnabled` set to `$true` on their Exchange user object.
- EDCA-IAC-009 (Basic Authentication baseline): fixed "Basic Authentication properties unavailable" being reported incorrectly. Organisation-level collection now prefers a Mailbox server over an Edge Transport server when selecting the organisation source server.
- Added Show skipped toggle to the report header (enabled by default). Turn it off to hide all skipped controls from the findings list.
- The control count shown in each category header in the HTML report no longer includes skipped controls.


## v0.8 Preview
- Controls that don't apply to a server's role are now marked Skipped when that server could not be reached, rather than showing a connectivity failure as evidence.
- The control count shown in each category header in the HTML report no longer includes skipped controls.
- The server connectivity pre-check is now more reliable and accurate across all server configurations.
- Fixed an error that occurred when collecting certificate information from remote servers.
- Date labels removed from the compliance trend chart x-axis; dates remain visible on hover.
- Fixed an error that occurred when running collection without immediately generating a report.

## v0.7 Preview
- `-Framework ENISA` renamed to `-Framework NIS2` — use `-Framework NIS2` where you previously used `-Framework ENISA`. The framework was already exclusively based on the NIS2 Directive and the NCSC-NL TLS Guidelines; the ENISA label was a misnomer.
- NIS2 coverage expanded — `EDCA-TLS-011`, `EDCA-TLS-014`, and `EDCA-TLS-021` gained the NIS2 tag, bringing the total to 27.
- Edge Transport control IDs corrected — the 7 Edge-specific controls have been renumbered into the Transport Security category (`EDCA-TLS-030`–`036`) to be consistent with similar controls.
- Edge Transport server support — EDCA can now collect data from and assess Edge Transport servers, in addition to Mailbox servers. EDCA can be run directly on an Edge server. An `EDGE` badge is shown next to Edge server names in the report. Controls `EDCA-TLS-030` through `EDCA-TLS-036` cover subscription health, anti-spam agents, recipient validation, blank sender blocking, send connector TLS enforcement, protocol logging, and SMTP certificate assignment.
- Trend chart dates — hover tooltip dates are now shown in a readable format (e.g. `21 Apr 2026`).

## v0.6 Preview
- EDCA-RES-011 (Single Item Recovery): fixed an inflated mailbox count caused by counting the same data once per server instead of once per organisation.
- EDCA-RES-011 remediation script updated to filter by mailbox type more efficiently.
- EDCA-SEC-041 (LAPS deployment): a missing LAPS policy now correctly reports as Fail instead of Unknown.
- EDCA-SEC-042 (NetBIOS over TCP/IP): removed remediation instructions from the failure evidence — they are already in the remediation section.
- Controls reordered by control ID throughout.
- Compliance Trend chart added to the Framework Scoreboard. When generating a report, EDCA loads up to 10 previous analyses and renders a colour-coded stacked bar chart (Pass / Unknown / Fail / Skipped) with a date hover tooltip.

## v0.5 Preview
- EDCA-SEC-041 (LAPS): Pass when legacy or Windows LAPS is configured via Group Policy; Fail when neither is detected.
- EDCA-SEC-042 (NetBIOS over TCP/IP): Pass when NetBIOS is disabled on all interfaces; Fail when any interface has it enabled or DHCP-controlled.
- EDCA-SEC-043 (SMB packet signing): Pass when both the SMB server and client require signing; Fail when either does not.
- EDCA-SEC-044 (LDAP client signing): Pass when LDAP signing is required; Fail when disabled or set to negotiate only; Unknown when not configured.
- EDCA-RES-011 (Single Item Recovery): fixed a routing issue that prevented the evaluator from running.
- EDCA-SEC-040 (ReFS volumes): Pass evidence now lists each volume on its own line instead of a comma-separated string.
- EDCA-TLS-027 (DKIM): fixed an error that could occur when DNS lookup results contained unexpected data.
- EDCA-IAC-028 (domain object WriteDACL ACEs): fixed incorrect ACE detection logic. Absent WriteDACL ACEs are now correctly treated as compliant. Control description and remediation guidance updated accordingly.
- EDCA-IAC-027 (unconstrained Kerberos delegation): Pass when the Exchange server is not trusted for unconstrained Kerberos delegation; Fail when it is.
- Controls quality pass: expanded descriptions for `EDCA-GOV-004`, `EDCA-SEC-028`, and `EDCA-SEC-031`; corrected `EDCA-IAC-003` grammar and `EDCA-SEC-003` and `EDCA-SEC-004` considerations; improved `EDCA-SEC-031` remediation guidance; added functional remediation scripts for `EDCA-GOV-011`, `EDCA-SEC-035`, `EDCA-SEC-036`, `EDCA-IAC-007`, and `EDCA-DATA-003`; and removed an expired deadline from `EDCA-DATA-008`.

## v0.4 Preview
- EDCA-TLS-029 (hybrid receive connector TLS): new control — checks that at least one Frontend receive connector is correctly configured for Exchange hybrid mail flow security.
- EDCA-TLS-003 (hybrid send connector TLS): evaluator rewritten to correctly check all relevant TLS properties.
- EDCA-TLS-027 (DKIM): selector evidence now groups results by platform and filters false positives from self-referential DNS loops.
- EDCA-TLS-025 (MTA-STS): evidence now includes the policy mode, maximum age, and MX entries from the published policy.
- Controls reordered by category, then subject, then related group.
- Generated remediation scripts now include a disclaimer header and use a consistent `Invoke-EDCA-{ID}` function naming convention.

## v0.3 Preview
- HTML report follows the system dark/light mode preference when no override is set.
- Markdown formatting in control descriptions and evidence is now rendered as HTML in the report.
- Report findings sorted by category, then by control ID.
- `EDCA-SEC-008`: the volume block-size check now works for volumes mounted as directory paths, not just drive letters.
- Exchange build number is also read from the registry, improving accuracy when Exchange cmdlets are unavailable.
- `EDCA-MON-002`: absent script block logging now results in Fail (previously Unknown).
- `EDCA-DATA-016`: IRM not configured results in Skipped (previously Fail).
- Startup banner displayed when EDCA begins execution.
