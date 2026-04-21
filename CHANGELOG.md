# Changelog

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
