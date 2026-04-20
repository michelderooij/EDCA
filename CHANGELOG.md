# Changelog

## v0.5 Preview
- README updated
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
