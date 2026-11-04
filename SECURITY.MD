# Security Policy

## Supported Versions

Security fixes are applied to the **latest published version** of EDCA only. Older snapshots or forks are not maintained.

| EDCA Version | Supported |
|---|---|
| Latest (PowerShell Gallery / GitHub main) | ✅ |
| Older versions | ❌ |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report them privately via one of:

- **GitHub private vulnerability reporting**: [Security Advisories](../../security/advisories/new)
- **Email**: *security@eightwone.com*

Please include as much of the following information as possible to help understand the nature and scope of the issue:

- **Type of issue** (e.g. sensitive data exposure, arbitrary code execution, privilege escalation, etc.)
- **Full path(s) of the source file(s)** related to the manifestation of the issue
- **Location of the affected source code** (tag, branch, commit, or direct URL)
- **Any special configuration required to reproduce the issue**
- **Step-by-step instructions to reproduce the issue**
- **Proof-of-concept or exploit code** (if possible)
- **Impact of the issue**, including how an attacker might exploit it

This information will help triage your report more quickly.

You can expect an acknowledgement within **5 business days** and a resolution or status update within **30 days**.

## Security Considerations for Users

EDCA runs in a **read-only, assessment-only** capacity — it does not make any configuration changes to Exchange or Active Directory. However, it requires broad administrative access and produces output files containing detailed Exchange configuration data. Review the following before use:

### Privilege model

- EDCA requires **Exchange Organization Management** (or View-Only Organization Management), **Local Administrator** on each Exchange server and assessed domain controller, and **Domain User** read access to Active Directory.
- Use a **dedicated service account** with these permissions scoped to the assessment period. Revoke or disable the account when the assessment is complete.
- On an Exchange Mailbox server, run EDCA from an **elevated PowerShell session** (Run as Administrator). UAC token filtering blocks remote PowerShell over port 80 for non-elevated sessions.

### Data files and report output

- The `Data\` folder contains per-server and organization-wide JSON files with Exchange configuration details (transport settings, TLS configuration, mailbox policies, etc.). These files are **sensitive** — protect them with appropriate file-system ACLs and delete them when no longer needed.
- The `Output\` folder contains the HTML report and an optional remediation script. The report embeds the assessment evidence inline. Treat both files as sensitive and distribute them only to authorized personnel.
- Do not store collected data files in publicly accessible locations (e.g., public repositories, unprotected file shares).

### Remediation script

- EDCA can generate a PowerShell remediation script (`-RemediationScript`). **Review all generated commands** before executing them in any environment. The script is provided as guidance only; apply changes in a test environment first.

### Network connections

- EDCA connects to Exchange servers over **HTTP port 80** (remote PowerShell), **LDAPS port 3269** (Global Catalog), and **WS-MAN port 5985** (WMI/CPU data). Ensure these paths are access-controlled and not exposed beyond the management network.

### Module integrity

- Always install EDCA from the **official PowerShell Gallery** (`Install-Module -Name EDCA`) or from the official [GitHub repository](https://github.com/michelderooij/EDCA). Verify the module publisher and, where possible, the commit signature before importing in a production environment.
- If downloaded as a ZIP, unblock all files before importing (`Get-ChildItem -Recurse | Unblock-File`) and confirm the archive matches the expected release hash.

### Exchange build catalog update

- The `-Update` switch downloads the Exchange build catalog from GitHub over HTTPS. Ensure your management host can reach GitHub, or use an internal mirror if your environment restricts external access.

## Scope

The following are **in scope** for vulnerability reports:

- Sensitive configuration data exposed or leaked by the tool or its output files
- Arbitrary code execution via module parameters, control definitions, or collected data files
- Privilege escalation beyond what is documented
- Insecure download behavior (missing integrity checks for the `-Update` switch)
- Injection vulnerabilities in the generated HTML report or remediation script

The following are **out of scope**:

- Vulnerabilities in Exchange Server, Windows Server, Active Directory, or IIS
- Findings surfaced by EDCA controls (these are Exchange configuration issues, not EDCA vulnerabilities)
- Issues that require physical access to the machine

## Preferred Languages

We prefer all communications to be in English.
