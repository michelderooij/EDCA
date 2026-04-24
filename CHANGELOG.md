# Changelog

## v0.91 Preview
- **EDCA-TLS-041** (SMTP banner — Edge server false Pass): fixed a false Pass result on Edge Transport servers.
- Added sample Report and Remediation script to Docs

## v0.9 Preview
- **Standalone Edge auto-detection**: when running `-Collect` without `-Servers` on a standalone Edge Transport server that cannot reach Active Directory, EDCA now automatically falls back to collecting from the local server (`$env:COMPUTERNAME`) instead of terminating with an AD connectivity error. A warning is printed and logged so the override is visible in the output. If Exchange is not installed locally and AD is unreachable, the original error is still thrown.
- **EDCA-RES-001** (Required Exchange services running): fixed "Test-ServiceHealth via endpoint failed: The syntax is not supported by this runspace" warning on Mailbox and Edge servers. The `Select-Object` call passed a calculated property script block to the remote Exchange PSSession endpoint, which runs in ConstrainedLanguage mode and does not allow script blocks in calculated properties. Fixed by using plain property selection (`Select-Object -Property Role, RequiredServicesRunning, ServicesNotRunning`) and relying on normal WinRM deserialization; Analysis.ps1 already iterates `ServicesNotRunning` with `[string]$_` so no downstream change is needed.
- **EDCA-SEC-013** (Credential Guard): added remediation script template to disable Credential Guard by clearing the `LsaCfgFlags` and `EnableVirtualizationBasedSecurity` registry values, with an explanatory note that a reboot is required.
- **EDCA-SEC-033** (Open relay prevention): control is now scoped to Mailbox servers only. Edge Transport servers are excluded because their Receive connector permission model is different and they are already covered by dedicated Edge controls.
- **EDCA-SEC-037** (SMTP banner / software disclosure): removed as a standalone Platform Security control. The check is now merged into **EDCA-TLS-041** (see below), which already assessed SMTP banners on Edge servers. The control ID `EDCA-SEC-037` is reused for the LDAP client signing control (formerly `EDCA-SEC-044`).
- **EDCA-SEC-037** (LDAP client signing, formerly EDCA-SEC-044): renumbered from `EDCA-SEC-044` to fill the gap left by the removed banner control. Group Policy remediation reference added: *Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options — Network security: LDAP client signing requirements = Require signing*.
- **EDCA-TLS-039** (Internal receive connector — RequireTLS): fixed "No internal Receive connectors identified" being incorrectly reported on Edge Transport servers. The previous filter excluded connectors that bind to `0.0.0.0:25` — which is the binding used by the EdgeSync-created internal connector. The fix uses `AuthMechanism -match '\bExchangeServer\b'` to distinguish internal connectors (added by EdgeSync, which include `ExchangeServer` in their AuthMechanism) from internet-facing ones (which do not).
- **EDCA-TLS-040** (Internal receive connector — anonymous connections): same root cause and fix as EDCA-TLS-039.
- **EDCA-TLS-041** (SMTP banner): extended to cover both Mailbox and Edge servers. For Mailbox servers, internet-facing connectors are identified by `AnonymousUsers` in PermissionGroups and `Tls/None` AuthMechanism. For Edge servers, internet-facing connectors are those without `ExchangeServer` in AuthMechanism. Banner evaluation uses improved logic: missing banner → Unknown; banner matching `exchange` or `15.x.x` → Fail; custom non-revealing banner → Pass.
- **Group Policy remediation references** added to remediation script templates for: EDCA-SEC-018 (LLMNR/DNS Client), EDCA-SEC-022 (PowerShell script block logging), EDCA-SEC-023 (SMBv1), EDCA-SEC-025 (Windows Firewall), EDCA-SEC-026 (Defender real-time protection), EDCA-SEC-037/formerly-SEC-044 (LDAP signing), EDCA-SEC-041 (LAPS), EDCA-SEC-042 (NetBIOS), EDCA-SEC-043 (SMB signing).
- **Server-scoped remediation scripts**: all remediation script templates that call server-level cmdlets now target `$env:COMPUTERNAME` explicitly (e.g. `Set-TransportService -Identity $env:COMPUTERNAME`, `Get-ReceiveConnector -Server $env:COMPUTERNAME`) instead of using all-server pipes or placeholder tokens.
- **Database-scoped remediation scripts**: all remediation script templates that call `Set-MailboxDatabase` now target a single database via `-Identity 'DatabaseName'` instead of piping from `Get-MailboxDatabase`.
- **EDCA-MON-010** (Audit log directory ACL): fixed "AuditLogPathAcl data not available" being reported when the Exchange audit log path was set to the default `<InstallPath>\Logging` folder. Two collection bugs caused `AuditLogPathAcl` to always be empty: (1) a `Where-Object` filter that incorrectly discarded all ACE entries from `FileSystemAccessRule` objects, and (2) the enrichment phase using `Invoke-Command` to retrieve a `DirectorySecurity` object whose `Access` collection is lost during WinRM serialization. Both are fixed: the filter is removed (matching the working `InstallPathAcl` pattern), and ACL entries are now processed inside the remote scriptblock before being returned.
- **Copy button** added to remediation script blocks in the HTML report — click it to copy the script to the clipboard.
- **EDCA-DATA-003** (Internal transport certificate baseline): control is now skipped for Edge Transport servers.
- **EDCA-GOV-004** (Exchange Hybrid Application baseline): fixed "Hybrid application telemetry unavailable" being reported incorrectly in environments with Edge Transport servers. The analysis now skips Edge servers (which never collect hybrid application data) and uses the first Mailbox server with collected data.
- **EDCA-IAC-011** (Dedicated hybrid app EvoSTS AuthServer): fixed "Hybrid application telemetry unavailable" being reported incorrectly in environments with Edge Transport servers. Same root cause as EDCA-GOV-004 — the server loop now skips servers where `HybridApplication` is `$null`.
- **EDCA-IAC-010** (Administrative access to EAC and remote PowerShell): converted from a manual-verification control to an automated org-level check. Now evaluates two sub-checks: (1) whether Client Access Rules are configured that restrict the `RemotePowerShell` or `ExchangeAdminCenter` protocol, and (2) whether any non-Exchange-administrative users (users not in any Exchange RBAC role group) have `RemotePowerShellEnabled` set to `$true` on their Exchange user object.
- **EDCA-IAC-009** (Basic Authentication baseline): fixed "Basic Authentication properties unavailable" being reported incorrectly. Organisation-level collection now prefers a Mailbox server over an Edge Transport server when selecting the organisation source server.
- Added **Show skipped** toggle to the report header (enabled by default). Turn it off to hide all skipped controls from the findings list.
- The control count shown in each category header in the HTML report no longer includes skipped controls.


## v0.8 Preview
- Controls that don't apply to a server's role are now marked **Skipped** when that server could not be reached, rather than showing a connectivity failure as evidence.
- The control count shown in each category header in the HTML report no longer includes skipped controls.
- The server connectivity pre-check is now more reliable and accurate across all server configurations.
- Fixed an error that occurred when collecting certificate information from remote servers.
- Date labels removed from the compliance trend chart x-axis; dates remain visible on hover.
- Fixed an error that occurred when running collection without immediately generating a report.

## v0.7 Preview
- **`-Framework ENISA` renamed to `-Framework NIS2`** — use `-Framework NIS2` where you previously used `-Framework ENISA`. The framework was already exclusively based on the NIS2 Directive and the NCSC-NL TLS Guidelines; the ENISA label was a misnomer.
- **NIS2 coverage expanded** — 3 additional transport security controls now carry the NIS2 tag, bringing the total to 27.
- **Edge Transport control IDs corrected** — the 7 Edge-specific controls have been renumbered into the Transport Security category (`EDCA-TLS-030`–`036`) to be consistent with similar controls.
- **Edge Transport server support** — EDCA can now collect data from and assess Edge Transport servers, in addition to Mailbox servers. EDCA can be run directly on an Edge server. An `EDGE` badge is shown next to Edge server names in the report. 7 new controls are included, covering subscription health, anti-spam agents, recipient validation, blank sender blocking, send connector TLS enforcement, protocol logging, and SMTP certificate assignment.
- **Trend chart dates** — hover tooltip dates are now shown in a readable format (e.g. `21 Apr 2026`).

## v0.6 Preview
- **EDCA-RES-011** (Single Item Recovery): fixed an inflated mailbox count caused by counting the same data once per server instead of once per organisation.
- **EDCA-RES-011** remediation script updated to filter by mailbox type more efficiently.
- **EDCA-SEC-041** (LAPS deployment): a missing LAPS policy now correctly reports as **Fail** instead of **Unknown**.
- **EDCA-SEC-042** (NetBIOS over TCP/IP): removed remediation instructions from the failure evidence — they are already in the remediation section.
- Controls reordered by control ID throughout.
- **Compliance Trend chart** added to the Framework Scoreboard. When generating a report, EDCA loads up to 10 previous analyses and renders a colour-coded stacked bar chart (Pass / Unknown / Fail / Skipped) with a date hover tooltip.

## v0.5 Preview
- **EDCA-SEC-041** (LAPS): Pass when legacy or Windows LAPS is configured via Group Policy; Fail when neither is detected.
- **EDCA-SEC-042** (NetBIOS over TCP/IP): Pass when NetBIOS is disabled on all interfaces; Fail when any interface has it enabled or DHCP-controlled.
- **EDCA-SEC-043** (SMB packet signing): Pass when both the SMB server and client require signing; Fail when either does not.
- **EDCA-SEC-044** (LDAP client signing): Pass when LDAP signing is required; Fail when disabled or set to negotiate only; Unknown when not configured.
- **EDCA-RES-011** (Single Item Recovery): fixed a routing issue that prevented the evaluator from running.
- **EDCA-SEC-040** (ReFS volumes): Pass evidence now lists each volume on its own line instead of a comma-separated string.
- **EDCA-TLS-027** (DKIM): fixed an error that could occur when DNS lookup results contained unexpected data.
- **EDCA-IAC-028** (domain object WriteDACL ACEs): fixed incorrect ACE detection logic. Absent WriteDACL ACEs are now correctly treated as compliant. Control description and remediation guidance updated accordingly.
- **EDCA-IAC-027** (unconstrained Kerberos delegation): Pass when the Exchange server is not trusted for unconstrained Kerberos delegation; Fail when it is.
- Controls quality pass: descriptions, remediation guidance, and remediation script templates improved across 12 controls.

## v0.4 Preview
- **EDCA-TLS-029** (hybrid receive connector TLS): new control — checks that at least one Frontend receive connector is correctly configured for Exchange hybrid mail flow security.
- **EDCA-TLS-003** (hybrid send connector TLS): evaluator rewritten to correctly check all relevant TLS properties.
- **EDCA-TLS-027** (DKIM): selector evidence now groups results by platform and filters false positives from self-referential DNS loops.
- **EDCA-TLS-025** (MTA-STS): evidence now includes the policy mode, maximum age, and MX entries from the published policy.
- Controls reordered by category, then subject, then related group.
- Generated remediation scripts now include a disclaimer header and use a consistent `Invoke-EDCA-{ID}` function naming convention.

## v0.3 Preview
- HTML report follows the system dark/light mode preference when no override is set.
- Markdown formatting in control descriptions and evidence is now rendered as HTML in the report.
- Report findings sorted by category, then by control ID.
- Volume block-size check now works for volumes mounted as directory paths, not just drive letters.
- Exchange build number is also read from the registry, improving accuracy when Exchange cmdlets are unavailable.
- Script block logging absent now results in **Fail** (previously **Unknown**).
- IRM not configured results in **Skipped** (previously **Fail**).
- Startup banner displayed when EDCA begins execution.
