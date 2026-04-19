# Changelog

## v0.5 Preview
- README updated
- **EDCA-TLS-027** (DKIM): fixed "The property 'Name' cannot be found on this object" error caused by unguarded property access on domain result objects; added null guard at top of ForEach-Object body, guarded `Dane`/`Dane.MxHosts`, `Dkim.Status`, `Dkim.Evidence`, and added `[PSCustomObject]` type check on `DetectedSelectors` before iterating its properties.
- **EDCA-IAC-028** (domain object DACL WriteDACL ACEs): fixed incorrect ACE matching — Exchange WriteDACL ACEs carry `ObjectType = [Guid]::Empty` and the class GUID in `InheritedObjectType`; collection was previously matching `ObjectType` against the class GUID and never found the ACEs. Analysis updated so that absent ACEs are treated as compliant (no WriteDACL right on the domain object = safe state). Removed dead "cannot determine state" evidence branches. Control description, `scriptTemplate`, and `considerations` updated to reflect the correct ACE structure and absent = compliant semantics.
- **EDCA-IAC-027** (unconstrained Kerberos delegation): evaluator implemented. Collection extended to read `userAccountControl` from the Exchange server computer account in AD (via the existing `ExchangeComputerMembership` AD searcher query) and store `TrustedForDelegation` (`0x80000` flag). Analysis reports Fail when the flag is set and Pass when it is absent.

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
