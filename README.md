# EDCA — Exchange Deployment & Compliance Assessment

PowerShell 5.1 tool to collect Exchange on-prem deployment data (Exchange 2016, Exchange 2019, and Exchange SE), evaluate it against externalized best-practice and compliance controls, and produce an interactive HTML report.

## Features in this MVP

- Collection mode for one or multiple servers in one Exchange organization.
- Reporting mode that imports a prior JSON collection export.
- Interactive HTML dashboard with scores for BestPractice, NIS2, CIS, DISA, and CISA.
- External controls catalog in `Config/controls.json` with per-control `verify` flag.
- Optional remediation script generation for all failed controls.
- No external PowerShell module dependency.
- Product-line detection and support checks for Exchange 2016, Exchange 2019, and Exchange SE.

## Requirements

- PowerShell 5.1
- Execution under an account that has Exchange and AD administrative access as required.
- Exchange Management Shell cmdlets are not required on the machine running the tool; Exchange-specific checks run remotely via Invoke-Command.

## Usage

From the `EDCA` folder:

```powershell
# Collection + analysis + HTML
.\EDCA.ps1 -Mode Collect -Servers EXCH01,EXCH02

# Collection with detailed execution trace
.\EDCA.ps1 -Mode Collect -Servers EXCH01,EXCH02 -Verbose

# Collection + analysis + HTML for all Exchange servers in current environment
.\EDCA.ps1 -Mode Collect

# Collection with remediation script generation
.\EDCA.ps1 -Mode Collect -Servers EXCH01,EXCH02 -GenerateRemediationScript

# Report mode (import existing collection JSON)
.\EDCA.ps1 -Mode Report -ImportJson .\Data\collection_20260410_120000.json
```

## Output

Files are written to `Data/`:

- `collection_*.json`: Raw collected data (machine-readable).
- `analysis_*.json`: Control evaluation output.
- `remediation_*.ps1`: Optional generated remediation script.

HTML reports are written to `Reports/`:

- `report_*.html`: Interactive assessment report.

## Notes

- Controls with `verify: false` are documented but excluded from scoring.
- Some controls are marked manual remediation only.
- Word output is intentionally deferred from this MVP.
