# Changelog

## v0.7 Preview
- **ENISA framework renamed to NIS2**: the `ENISA` framework tag has been renamed to `NIS2` across all controls, code, and documentation. The framework was already exclusively backed by the NIS2 Directive (EU) 2022/2555 and the NCSC-NL TLS Guidelines 2025-05 — the ENISA label was a misnomer. Use `-Framework NIS2` where you previously used `-Framework ENISA`.
- **NIS2 framework expanded**: 3 additional Transport Security controls now carry the `NIS2` tag — `EDCA-TLS-011` (external send connector STARTTLS), `EDCA-TLS-014` (domain security / mutual TLS), and `EDCA-TLS-021` (internal receive connectors require encryption). Total NIS2-tagged controls: 27.
- **Edge Transport control IDs corrected**: the 7 Edge-specific controls were previously labelled `EDCA-EDGE-001` through `EDCA-EDGE-007`. They have been renamed to `EDCA-TLS-030` through `EDCA-TLS-036` to match their category (Transport Security). Duplicate entries introduced during a manual edit were also removed.
- **Edge Transport server support**: EDCA now can collect and assesses Edge Transport servers in addition to Mailbox servers.
  - **Collection** (`Collection.ps1`): Edge servers are detected by their `ServerRole` property. Collection runs in-process locally (no WinRM session) when the target is the local machine, allowing EDCA to be invoked directly on the Edge server. An Edge-specific endpoint block collects anti-spam configuration, Edge subscriptions, send connectors, and certificates.
  - **Analysis** (`Analysis.ps1`): Role-aware skip logic skips controls not applicable to the server role being evaluated (e.g. IIS/OWA/DAG controls are skipped on Edge servers; Edge-specific controls are skipped on Mailbox servers). All 173 existing controls now carry a `roles` field in `Config/controls.json`.
  - **New controls**: 7 Edge-specific controls added (`EDCA-EDGE-001` through `EDCA-EDGE-007`), all categorised under **Transport Security**, covering Edge subscription health, anti-spam agent enablement, recipient validation, blank sender blocking, send connector TLS enforcement, protocol logging, and SMTP certificate assignment.
  - **Reporting** (`Reporting.ps1`): An `EDGE` role badge is displayed next to Edge server names in the control evidence tables. The environment notices section now distinguishes between Edge servers that were collected and assessed, and Edge servers detected in the organisation topology but not collected.
- **Trend chart tooltip date** (`Reporting.ps1`, `Analysis.ps1`): `AnalysisTimestamp` is now stored as ISO 8601 (`'o'` format) instead of relying on `[datetime]` serialisation. The report parses both ISO 8601 and the PS5.1 `/Date(ms)/` legacy format, and formats dates as `d MMM yyyy` (e.g. `21 Apr 2026`) in the trend chart tooltip.

## v0.6 Preview
- **EDCA-RES-011** (Single Item Recovery): fixed double-counting — `Get-Mailbox -ResultSize Unlimited` is org-scoped and stored identically on every server; the analysis now takes the value from the first available server instead of summing across all servers (which multiplied the count by the server count).
- **EDCA-RES-011** remediation `scriptTemplate` updated to use `-RecipientTypeDetails UserMailbox` as a native server-side parameter instead of a `Where-Object` post-filter on `RecipientTypeDetails`.
- **EDCA-SEC-041** (LAPS deployment): absent LAPS registry policy keys now result in **Fail** ("LAPS is not implemented") instead of **Unknown**.
- **EDCA-SEC-042** (NetBIOS over TCP/IP): removed remediation instructions from Fail evidence (instructions are in the remediation section).
- `Config/controls.json`: controls re-ordered by control ID (alphabetical category, then numeric within category).
- **HTML report**: added **Compliance Trend** stacked bar chart to the Framework Scoreboard section. When `-Report` is used, EDCA loads the last 10 `analysis_*.json` files from the `Data/` folder and renders a colour-coded bar chart (Pass/Unknown/Fail/Skip) with date labels and a hover tooltip. The chart card spans three gauge widths and is rendered in pure Canvas (no external libraries).

## v0.5 Preview
- **EDCA-SEC-041** (LAPS deployment): evaluator implemented. Collection reads `AdmPwdEnabled` from `HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd` (legacy LAPS) and `BackupDirectory` from `HKLM:\SOFTWARE\Microsoft\Policies\LAPS` (Windows LAPS). Reports Pass when either legacy LAPS or Windows LAPS is configured via Group Policy, Fail when neither is detected.
- **EDCA-SEC-042** (NetBIOS over TCP/IP): evaluator implemented. Collection enumerates `NetbiosOptions` for all interfaces under `HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces`. Reports Pass when all interfaces have `NetbiosOptions=2` (disabled), Fail when any interface has a DHCP-controlled (0) or explicitly enabled (1) value.
- **EDCA-SEC-043** (SMB packet signing): evaluator implemented. Collection reads `RequireSecuritySignature` from `HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` (SMB server) and `LanmanWorkstation\Parameters` (SMB client). Reports Pass when both server and client require signing (value=1), Fail when either does not.
- **EDCA-SEC-044** (LDAP client signing): evaluator implemented. Collection reads `LdapClientIntegrity` from `HKLM:\SYSTEM\CurrentControlSet\Services\LDAP`. Reports Pass when value=2 (require signing), Fail when value=0 (disabled) or value=1 (negotiate only), Unknown when the value is absent.
- **EDCA-RES-011** (Single Item Recovery): evaluator routing fix — control ID added to the organisation-scoped guard list so the existing evaluator (implemented in a prior session) is now correctly reached.
- **EDCA-SEC-040** (ReFS volumes): evidence formatting — Pass branch now lists each volume on a separate bullet line using `Format-EDCAEvidenceWithElements` instead of a comma-joined string.
- **EDCA-TLS-027** (DKIM): fixed "The property 'Name' cannot be found on this object" error caused by unguarded property access on domain result objects; added null guard at top of ForEach-Object body, guarded `Dane`/`Dane.MxHosts`, `Dkim.Status`, `Dkim.Evidence`, and added `[PSCustomObject]` type check on `DetectedSelectors` before iterating its properties.
- **EDCA-IAC-028** (domain object DACL WriteDACL ACEs): fixed incorrect ACE matching — Exchange WriteDACL ACEs carry `ObjectType = [Guid]::Empty` and the class GUID in `InheritedObjectType`; collection was previously matching `ObjectType` against the class GUID and never found the ACEs. Analysis updated so that absent ACEs are treated as compliant (no WriteDACL right on the domain object = safe state). Removed dead "cannot determine state" evidence branches. Control description, `scriptTemplate`, and `considerations` updated to reflect the correct ACE structure and absent = compliant semantics.
- **EDCA-IAC-027** (unconstrained Kerberos delegation): evaluator implemented. Collection extended to read `userAccountControl` from the Exchange server computer account in AD (via the existing `ExchangeComputerMembership` AD searcher query) and store `TrustedForDelegation` (`0x80000` flag). Analysis reports Fail when the flag is set and Pass when it is absent.
- **Controls quality pass** (`Config/controls.json`): 13 quality improvements across 12 controls — descriptions expanded for EDCA-GOV-004, EDCA-SEC-028, EDCA-SEC-031; broken grammar fixed in EDCA-IAC-003; wrong copy-pasted considerations replaced in EDCA-SEC-003 (domain FL) and EDCA-SEC-004 (forest FL); actionable remediation guidance added to EDCA-SEC-031; scriptTemplates upgraded from comment stubs to functional PowerShell for EDCA-GOV-011, EDCA-SEC-035, EDCA-SEC-036, EDCA-IAC-007, EDCA-DATA-003; expired deadline removed from EDCA-DATA-008.

## v0.4 Preview
- Added control **EDCA-TLS-029**: hybrid receive connector TLS integrity — checks that at least one `FrontendTransport` receive connector has `TlsDomainCapabilities` set to `mail.protection.outlook.com:AcceptCloudServicesMail` (Exchange 2016 CU3+/Exchange 2019/SE) or `AcceptOorgProtocol` (older deployments), is enabled, and includes `Tls` in `AuthMechanism`.
- **EDCA-TLS-003** (hybrid send connector TLS integrity) evaluation rewritten to check `RequireTLS`, `TlsAuthLevel`, `TlsDomain`, and `TlsCertificateName` on the hybrid send connector rather than the previous incorrect property set.
- **EDCA-TLS-027** (DKIM) evidence now groups detected selectors by platform (e.g. Exchange Online, Google) and filters self-referential CNAME loops to avoid false positives.
- **EDCA-TLS-025** (MTA-STS) evidence now includes the MTA-STS policy `mode`, `max_age`, and `mx` entries collected from the policy file.
- **EDCA-TLS-029** analysis correctly accepts both `AcceptCloudServicesMail` and `AcceptOorgProtocol` as valid `TlsDomainCapabilities` values.
- `Config/controls.json` entries reordered: controls are now grouped by category (Governance → Identity and Access Control → Platform Security → Data Security → Transport Security → Monitoring → Resilience → Performance), with Organization-scoped controls preceding Server/Database/Mailbox within each category, and related controls grouped together.
- Generated remediation scripts now include an all-caps sample-script disclaimer header above `#requires`.
- Generated remediation script function names changed from `InvokeFix_EDCA_GOV_009` style to `Invoke-EDCA-GOV-009` (verb-noun with full control ID).
- Module files (`Common.ps1`, `Collection.ps1`, `Analysis.ps1`, `Reporting.ps1`, `Remediation.ps1`) now include a synopsis header identifying the script name, EDCA, and the GitHub repository URL.
- `Resources/Sort-Controls.ps1` added: utility script to re-sort `Config/controls.json` by category, subject, and logical group after adding new controls.

## v0.3 Preview
- HTML report now follows the system colour-scheme preference (`prefers-color-scheme: dark`) when no manual override is stored.
- Markdown syntax in control descriptions and evidence text is rendered as HTML in the report.
- Findings in the HTML report are sorted by category then by control ID.
- Exchange database/log volume block-size check now supports volumes mounted as directory paths (not just drive letters).
- Exchange build number read from the registry in addition to `Get-ExchangeServer`, improving accuracy on servers where Exchange cmdlets are unavailable.
- Server inventory collection migrated from `Get-WmiObject` to `Get-CimInstance`.
- Script block logging absent now results in **Fail** (previously **Unknown**).
- IRM not configured results in **Skipped** (previously **Fail**).
- Startup banner displayed when EDCA begins execution.
