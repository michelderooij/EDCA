# EDCA — Exchange Deployment & Compliance Assessment

PowerShell 5.1 tool to collect Exchange on-prem deployment data (Exchange 2016, Exchange 2019, and Exchange SE), evaluate it against externalized best-practice and compliance controls, and produce an interactive HTML report.

## Features

- Collection mode for one or multiple servers in one Exchange organization.
- Reporting mode that imports a prior JSON collection export (single file, multiple files, or a folder).
- Interactive HTML dashboard with scores for Best Practice, ENISA/NIS2, CIS, DISA, and CISA.
- External controls catalog in `Config/controls.json` with per-control `verify` flag.
- Optional remediation script generation for all failed controls.
- No external PowerShell module dependency.
- Product-line detection and support checks for Exchange 2016, Exchange 2019, and Exchange SE.
- Collection output split into per-server files (`<fqdn>_<timestamp>.json`) and a shared organization file (`<OrganizationId>_<timestamp>.json`).
- `-Update` switch to download the latest Exchange build catalog from GitHub before running.

## Requirements

- PowerShell 5.1
- Execution under an account that has Exchange and AD administrative access as required.
- Exchange Management Shell cmdlets are not required on the machine running the tool; Exchange-specific checks run remotely via Invoke-Command.

## Required Permissions

The account running EDCA needs the following access rights. Rights marked **required** affect core collection; rights marked **needed for** affect specific controls only and will cause those controls to report **Fail** if missing.

| Permission | Scope | Required for |
|---|---|---|
| Exchange **Organization Management** or **View-Only Organization Management** role | Exchange organization | Core collection — Exchange cmdlets (`Get-ExchangeServer`, `Get-OrganizationConfig`, `Get-Mailbox`, and all other Exchange management commands). |
| **Local Administrator** | Each Exchange server | Core collection — WMI queries for OS, hardware, volume/disk, BitLocker state, network configuration; reading local registry values (TLS, update metadata). |
| **Active Directory read** (Domain User is sufficient) | AD forest/domain | Core collection — LDAP RootDSE queries for forest and domain functional level; AD site enumeration (`EX-BP-009`); Exchange server AD site lookup. |
| **Local Administrator** | Each Domain Controller / Global Catalog in the Exchange AD site | `EX-BP-159` (Exchange-to-DC/GC core ratio) — WMI `Win32_Processor` on domain controller servers. |

> **Note:** If the required permissions are not in place, affected controls will report **Fail** rather than *Unknown* so that missing access is surfaced as a finding rather than silently skipped.

## Usage

From the `EDCA` folder:

```powershell
# Update exchange build catalog, then collect + analyse + HTML (default Both mode)
.\EDCA.ps1 -Update -Servers EXCH01,EXCH02

# Collect + analysis + HTML (Both mode is the default)
.\EDCA.ps1 -Servers EXCH01,EXCH02

# Collect with detailed execution trace
.\EDCA.ps1 -Servers EXCH01,EXCH02 -Verbose

# Collect + analysis + HTML for all Exchange servers in current environment
.\EDCA.ps1

# Collect only (no report), limit parallel collection jobs
.\EDCA.ps1 -Mode Collect -Servers EXCH01,EXCH02 -ThrottleLimit 2

# Collect with remediation script generation
.\EDCA.ps1 -Servers EXCH01,EXCH02 -GenerateRemediationScript

# Collect, skip HTML output (analysis JSON still written)
.\EDCA.ps1 -Servers EXCH01,EXCH02 -SkipHtml

# Report mode — import a single previously collected server file
.\EDCA.ps1 -Mode Report -ImportPath .\Data\ex01.contoso.com_20260410_120000.json

# Report mode — import multiple server files
.\EDCA.ps1 -Mode Report -ImportPath .\Data\ex01.contoso.com_20260410_120000.json,.\Data\ex02.contoso.com_20260410_120000.json

# Report mode — import all JSON files in the Data folder (server + org files auto-detected)
.\EDCA.ps1 -Mode Report -ImportPath .\Data
```

## Output

Collection files are written to `Data/`:

- `<fqdn>_<timestamp>.json`: Per-server collected data (machine-readable).
- `<OrganizationId>_<timestamp>.json`: Organization-wide collected data shared across all servers in the run.

Analysis and remediation files are written to `Output/`:

- `analysis_*.json`: Control evaluation output.
- `remediation_*.ps1`: Optional generated remediation script.

HTML reports are written to `Reports/`:

- `report_*.html`: Interactive assessment report.

## Screenshots

**Report dashboard** — framework scores (Total, Best Practice, CIS, CISA, ENISA, DISA) with colour-coded donut charts, and findings grouped by category with RAG indicators, search, and filters:

![EDCA report dashboard](Assets/EDCA_capture1.jpg)

**Control detail panel** — per-control description, evidence table (subject, status, evidence text), remediation guidance, and optional script template:

![EDCA control detail panel](Assets/EDCA_capture2.jpg)

## Frameworks

EDCA evaluates controls against the following compliance frameworks. Each control in `Config/controls.json` is tagged with one or more framework identifiers; the HTML report displays a separate score for each.

| Framework | Full name
|---|---|
| **Best Practice** | Exchange Server best practices |
| **CIS** | [CIS Microsoft Exchange Server Benchmark](https://www.cisecurity.org/benchmark/microsoft_exchange_server) |
| **CISA** | [CISA Microsoft Exchange Server Security Best Practices Guide](https://www.cisa.gov/resources-tools/resources/microsoft-exchange-server-security-best-practices-guide) |
| **DISA** | [DISA STIG for Microsoft Exchange 2019 Mailbox Server](https://public.cyber.mil/stigs/downloads/) |
| **ENISA** | [ENISA / NIS2 Directive (EU) 2022/2555](https://www.enisa.europa.eu/topics/cybersecurity-policy/nis-directive-new) — including [NCSC-NL TLS Guidelines](https://www.ncsc.nl/documenten/publicaties/2021/januari/19/ict-beveiligingsrichtlijnen-voor-transport-layer-security-2.1) |

## Notes

- Controls with `verify: false` are documented but excluded from scoring.
- Some controls are marked manual remediation only.
