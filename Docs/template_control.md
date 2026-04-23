# EDCA Control Specification Template

Use this template when proposing or implementing a new EDCA control. Complete every section before
submitting. Incomplete submissions will be returned.

---

## 1. Identity

| Field | Value |
|---|---|
| **ID** | `EDCA-<CATEGORY>-<NNN>` |
| **Title** | One imperative noun phrase, no trailing period |
| **Subject** | `Organization` or `Server` |
| **Category** | See [§ Category values](#category-values) |
| **Severity** | `Critical` / `High` / `Medium` / `Low` |
| **Severity weight** | Integer 1–10; see [§ Severity calibration](#severity-calibration) |
| **Automatable** | `true` if the scriptTemplate fully remediates without manual steps; `false` otherwise |
| **Verify** | `true` (default for all controls that evaluate a state) |

### ID format

```
EDCA-<CATEGORY>-<NNN>
```

`<NNN>` is the next sequential number within the category. Check `controls.json` for the highest
existing number before assigning.

### Category values

| Code | Category string |
|---|---|
| `DATA` | `Data Security` |
| `GOV` | `Governance` |
| `IAC` | `Identity and Access Control` |
| `MON` | `Monitoring` |
| `PERF` | `Performance` |
| `RES` | `Resilience` |
| `SEC` | `Platform Security` |
| `TLS` | `Transport Security` |

### Severity calibration

| Severity | Weight range | Meaning |
|---|---|---|
| Critical | 9–10 | Direct path to privilege escalation, data exfiltration, or service outage |
| High | 7–8 | Significantly weakens defence-in-depth; exploitable without chained preconditions |
| Medium | 4–6 | Degrades security posture; requires additional conditions or attacker access to exploit |
| Low | 1–3 | Hardening or compliance alignment; no direct exploitability |

---

## 2. Frameworks

List every framework that mandates or explicitly recommends this control. Use only the strings
already present in `controls.json`.

```
"ANSSI" | "Best Practice" | "BSI" | "CIS" | "CISA" | "DISA" | "NIS2"
```

Include `"Best Practice"` for every control that represents sound Exchange hardening regardless of
any formal framework requirement.

---

## 3. Description

**Rules:**

- State what the control requires before explaining why.
- Use `MUST` for mandatory requirements. Use `SHOULD` for recommended but non-mandatory requirements.
  Do not use `MAY`, `MIGHT`, or `COULD` to express requirements.
- Use `SHALL` for normative statements about system or tool behaviour (what the system does),
  not for operator obligations.
- Write in the active voice. Say "Exchange Server exposes X" not "X is exposed by Exchange Server".
  Say "The tool evaluates Y" not "Y is evaluated by the tool".
- Do not use adverbs to qualify security statements: not "simply disable", not "easily exploited",
  not "quickly remediated". State facts directly.
- Do not hedge with "note that", "please be aware", or "it should be noted". State the fact.
- Use present tense throughout. Avoid "will be", "would be", "should be".
- For multi-line descriptions, separate logical sections with `\n\n` in the JSON value.

**Template:**

```
<Setting or feature name> MUST <required state> on <scope>.

<Technical explanation of what the setting controls and why the required state matters.>

<If version or edition constraints apply, state them here. State the constraint first, then the
reason. Example: "Exchange Server 2016 does not support X; upgrade to Exchange 2019 CU13 or later.">

<Reference the specific framework clause that requires this control, e.g.:
"BSI APP.5.2.A16 requires …" or "CISA BOD 18-01 requires ….">
```

**Example (well-formed):**

> `OAuth2ClientProfileEnabled` MUST be set to `True` on the Exchange organization.
> Modern Authentication (OAuth 2.0) enables token-based client authentication and is required
> before enabling Hybrid Modern Authentication or AD FS-based authentication.
> Exchange Server 2016 CU8 and later, Exchange 2019 RTM and later, and Exchange SE RTM and later
> support this setting.

**Example (poorly formed — do not copy):**

> ~~It is recommended that administrators simply enable OAuth2ClientProfileEnabled so that Modern
> Authentication will be supported by the server.~~

---

## 4. References

Each reference MUST have a `name` and a `url`. Follow this naming convention:

| Source type | Name format | Example |
|---|---|---|
| RFC | `RFC <number> - <title>` | `RFC 6376 - DomainKeys Identified Mail (DKIM) Signatures` |
| Microsoft Learn | Short descriptive title | `Configure Exchange Server on-premises to use Hybrid Modern Authentication` |
| BSI | `BSI IT-Grundschutz Kompendium <year> - <requirement ID>: <German title> (<tier>)` | `BSI IT-Grundschutz Kompendium 2023 - APP.5.2.A16: Umgang mit Spam (Standard)` |
| CIS Benchmark | `CIS <section> (<level>): <description>` | `CIS 2.2.4 (L1): Ensure Maximum send size Connector level is set to 25` |
| DISA STIG | `DISA STIG <product> <STIGid>: <description> (<Vuln-ID>)` | `DISA STIG EX19-MB-000128: Exchange message size restrictions must be controlled on send connectors (V-259681)` |
| CISA directive | `CISA BOD <number> (<year>): <title> - <section>` | `CISA BOD 18-01 (2017): Enhance Email and Web Security - §d(2): Deploy DKIM for all domains` |

Include the primary standard reference first, then framework references, then tool/implementation
references last.

---

## 5. Remediation

### 5a. Description

One to three sentences. State what the operator MUST do. Do not repeat the full description.
Do not include PowerShell in this field — that belongs in `scriptTemplate`.

**Example:**

> Set `MaxMessageSize` to 25 MB or less on all send connectors.

### 5b. Script template

Structure every script template in two clearly labelled sections using `# === DIAGNOSTICS ===`
and `# === REMEDIATION ===`. The diagnostics section MUST run read-only and MUST always be present.
The remediation section MUST be commented out by default. It should demonstrate how to implement the
control for the organization, one database, one server or one domain.

```powershell
# === DIAGNOSTICS ===
# <Description of what the diagnostic commands show>
<read-only cmdlets here>

# === REMEDIATION ===
# <Description of what these commands change; note any service impact>
# Uncomment to apply:
# <remediation cmdlets here, commented out>
```

**Rules:**
- The diagnostics section uses `Select-Object`, `Format-List`, `Write-Host` — never `Set-*`,
  `Enable-*`, `Disable-*`, `New-*`, or `Remove-*`.
- The remediation section MUST be commented out. A reader runs the diagnostics to confirm the
  finding, then deliberately uncomments to remediate.
- If remediation requires manual steps that PowerShell cannot perform (DNS changes, GUI-only
  configuration, third-party tooling), add a `# NOTE:` comment in the remediation section that
  states this explicitly. Do not pretend the step is automatable.
- If a cmdlet does not exist in the Exchange Management Shell (e.g., Exchange Online-only cmdlets),
  do not include it. Add a `# NOTE:` explaining which shell or product the cmdlet belongs to.
- Reference the exact parameter name as documented: `Set-OrganizationConfig -OAuth2ClientProfileEnabled $true`,
  not `-Oauth2ClientProfileEnabled` or `-oAuth2ClientProfileEnabled`.

---

## 6. Considerations

Free-form prose or bullet list (`•` prefix). Include:

- Version or edition constraints that affect applicability.
- Operational impact of remediation (service interruptions, client behaviour changes).
- Dependencies between this control and others (cross-reference by `EDCA-<ID>`).
- Rollback procedure if remediation is reversible.
- Anything that qualifies the Pass/Fail verdict that the analysis logic cannot express.

**Rules:**
- Do not repeat information already in the description.
- Use `MUST`, `SHOULD`, and `SHALL` consistently — see § 3.
- Use active voice and present tense.
- Keep each bullet to one or two sentences.

---

## 7. Analysis logic specification

This section describes the evaluation logic for `Modules/Analysis.ps1`. The implementer translates
this into a PowerShell `switch` case.

### 7a. Subject

State whether this control is evaluated once at organization level, once per server, or both.

- **Organization**: the switch case appears in the org-level `switch` block
  (search for `# === ORGANIZATION-LEVEL CONTROLS ===` in Analysis.ps1).
  Reads from `$CollectionData.Organization`, `$CollectionData.EmailAuthentication`, or
  loops `$CollectionData.Servers` to aggregate across all servers.
- **Server**: the switch case appears in the server-level `switch` block
  (search for `# === SERVER-LEVEL CONTROLS ===` in Analysis.ps1).
  Reads from the per-server `$Exchange` object.

### 7b. Data path

State which property path(s) in the collection data contain the evidence. Use dot notation.

Examples:
```
$CollectionData.Organization.OAuth2ClientProfileEnabled
$CollectionData.Servers[n].Exchange.SendConnectors[].MaxMessageSizeBytes
$CollectionData.EmailAuthentication.DomainResults[].Dkim.Status
```

For server-level controls, the equivalent per-server path is available as `$Exchange.<Property>`.

### 7c. Status values

Use exactly these strings:

| Status | When to use |
|---|---|
| `'Pass'` | All checks succeeded |
| `'Fail'` | One or more checks failed with a concrete finding |
| `'Unknown'` | Required data is absent or the tool could not collect it |
| `'Skipped'` | The control is not applicable to this target (e.g., non-routable domain, unsupported version) |

Prefer `'Unknown'` over `'Fail'` when the setting value is genuinely unavailable.
Only use `'Skipped'` when a documented applicability condition excludes the target.

### 7d. Evidence string rules

- Use present tense: "`OAuth2ClientProfileEnabled` is `False`", not "was False".
- Provide the remediation cmdlet inline in Fail evidence strings where the fix is a single cmdlet:
  `"SSLOffloading is True — run: Set-OutlookAnywhere -SSLOffloading $false"`.
- Separate multiple issues with `Format-EDCAEvidenceWithElements -Summary '...' -Elements $issues`.
- For per-item breakdowns (connectors, domains, servers), populate `$domainServerResults` as an
  array of `[pscustomobject]@{ Server = ...; Status = ...; Evidence = ... }` and let the outer
  aggregation logic derive the overall status.

### 7e. Pseudocode

Write the evaluation logic in plain English before translating to PowerShell. Be explicit about
every branch.

```
1. Read <property> from <data path>.
2. If data is absent or null → status = Unknown; evidence = '<reason>'.
3. If <condition A> → add issue '<issue text>'.
4. If <condition B> → add issue '<issue text>'.
5. If issues.Count = 0 → status = Pass; evidence = '<pass summary>'.
6. Else → status = Fail; evidence = Format-EDCAEvidenceWithElements(...).
```

---

## 8. Collection logic specification

This section describes any collection-side changes required in `Modules/Collection.ps1`.

### 8a. Is new collection required?

If the data this control needs is already collected and present in the JSON data files, state that
here and skip §§ 8b–8d.

If the required property is not yet collected, describe it below.

### 8b. Cmdlet

State the Exchange Management Shell cmdlet and the properties to retrieve.

```powershell
Get-<Noun> | Select-Object Identity, <Property1>, <Property2>
```

Confirm the cmdlet exists in the Exchange Management Shell (not Exchange Online PowerShell) before
specifying it. If the cmdlet is Exchange Online-only, state this and propose an alternative.

### 8c. Data path in collection output

State where in the collection object the new property will be stored. Follow the existing pattern:

- Server-level data: `$serverObject.Exchange.<NewProperty>`
- Organization-level data: `$collectionData.Organization.<NewProperty>`
- Email authentication data: `$collectionData.EmailAuthentication.DomainResults[].<NewProperty>`

### 8d. Failure handling

State how the collection function behaves when the cmdlet fails, returns no results, or is not
available on the target Exchange version. The collection layer MUST NOT throw; it MUST return a
structured object or `$null` that the analysis layer can test.

---

## 9. JSON entry (filled)

Replace every `<placeholder>` with the actual value. Delete unused optional fields.

```json
{
  "id": "EDCA-<CATEGORY>-<NNN>",
  "title": "<Imperative noun phrase>",
  "description": "<Description following § 3 rules>",
  "verify": true,
  "subject": "<Organization|Server>",
  "category": "<Category string>",
  "severity": "<Critical|High|Medium|Low>",
  "severityWeight": 0,
  "frameworks": [
    "Best Practice"
  ],
  "references": [
    {
      "name": "<Name per § 4 convention>",
      "url": "<URL>"
    }
  ],
  "remediation": {
    "automatable": false,
    "description": "<Remediation description per § 5a>",
    "scriptTemplate": "<PowerShell per § 5b, escaped for JSON>"
  },
  "considerations": "<Considerations per § 6>"
}
```

---

## 10. JSON Schema

The schema below is the authoritative machine-readable specification of a control object. Use it to
validate generated controls before submitting. Every field listed as `"required"` MUST be present;
every enum field MUST use exactly one of the listed string values.

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://github.com/michelderooij/EDCA/blob/main/Config/controls.schema.json",
  "title": "EDCA Control",
  "type": "object",
  "required": [
    "id",
    "title",
    "description",
    "verify",
    "subject",
    "category",
    "severity",
    "severityWeight",
    "frameworks",
    "references",
    "remediation",
    "considerations"
  ],
  "additionalProperties": false,
  "properties": {
    "id": {
      "type": "string",
      "pattern": "^EDCA-(DATA|GOV|IAC|MON|PERF|RES|SEC|TLS)-\\d{3}$",
      "description": "Unique control identifier. Format: EDCA-<CATEGORY>-<NNN> (zero-padded to 3 digits)."
    },
    "title": {
      "type": "string",
      "maxLength": 80,
      "description": "Short imperative noun phrase. No trailing period."
    },
    "description": {
      "type": "string",
      "description": "Full prose. Use MUST/SHOULD/SHALL. Active voice. Present tense. \\n\\n for paragraph breaks."
    },
    "verify": {
      "type": "boolean",
      "description": "true if the tool evaluates this control automatically."
    },
    "subject": {
      "type": "string",
      "enum": ["Organization", "Server"],
      "description": "Evaluation scope. Organization = evaluated once; Server = evaluated per server."
    },
    "category": {
      "type": "string",
      "enum": [
        "Data Security",
        "Governance",
        "Identity and Access Control",
        "Monitoring",
        "Performance",
        "Platform Security",
        "Resilience",
        "Transport Security"
      ]
    },
    "severity": {
      "type": "string",
      "enum": ["Critical", "High", "Medium", "Low"]
    },
    "severityWeight": {
      "type": "integer",
      "minimum": 1,
      "maximum": 10,
      "description": "Low: 1–3; Medium: 4–6; High: 7–8; Critical: 9–10."
    },
    "frameworks": {
      "type": "array",
      "minItems": 1,
      "uniqueItems": true,
      "items": {
        "type": "string",
        "enum": ["ANSSI", "Best Practice", "BSI", "CIS", "CISA", "DISA", "ENISA"]
      },
      "description": "Always include Best Practice for any sound hardening control."
    },
    "references": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "required": ["name", "url"],
        "additionalProperties": false,
        "properties": {
          "name": {
            "type": "string",
            "description": "Follow the naming convention in § 4."
          },
          "url": {
            "type": "string",
            "format": "uri"
          }
        }
      }
    },
    "remediation": {
      "type": "object",
      "required": ["automatable", "description", "scriptTemplate"],
      "additionalProperties": false,
      "properties": {
        "automatable": {
          "type": "boolean",
          "description": "false if any step requires manual action or DNS changes."
        },
        "description": {
          "type": "string",
          "description": "1–3 sentences. Active voice. No PowerShell cmdlets in prose."
        },
        "scriptTemplate": {
          "type": "string",
          "description": "PowerShell with DIAGNOSTICS and REMEDIATION sections. \\n line breaks, \\\" for embedded quotes. Remediation block MUST be commented out."
        }
      }
    },
    "considerations": {
      "type": "string",
      "description": "Version constraints, operational impact, cross-references (EDCA-XYZ-NNN), rollback notes. Bullets use \\n•."
    }
  }
}
```

---

## 11. Checklist

Before submitting, confirm every item:

- [ ] ID is unique and follows the `EDCA-<CATEGORY>-<NNN>` format
- [ ] Title is an imperative phrase with no trailing period
- [ ] Description uses `MUST`/`SHOULD`/`SHALL` correctly and consistently
- [ ] Description uses active voice throughout
- [ ] Description contains no adverbs qualifying security statements
- [ ] All framework references are verified against the source document
- [ ] All references use the naming convention in § 4
- [ ] scriptTemplate has a DIAGNOSTICS section (read-only) and a REMEDIATION section (commented out)
- [ ] scriptTemplate contains no Exchange Online-only cmdlets without a `# NOTE:` disclaimer
- [ ] Analysis pseudocode covers all data-absent and not-applicable branches
- [ ] Severity and severityWeight are consistent with the calibration table
- [ ] `automatable` is `false` if any remediation step requires manual action or DNS changes
- [ ] `subject` matches where the evaluation logic reads its data from
- [ ] `considerations` does not repeat the description
- [ ] JSON is valid (run `Get-Content controls.json | ConvertFrom-Json` to verify)

---

## Appendix: Language reference

### Modal verbs

| Word | Use for | Example |
|---|---|---|
| `MUST` | Operator obligation; non-compliance is a finding | `OAuth2ClientProfileEnabled MUST be True` |
| `MUST NOT` | Operator prohibition; violation is a finding | `SSLOffloading MUST NOT be enabled` |
| `SHOULD` | Recommended; non-compliance is advisory, not a finding | `The maximum message size SHOULD be 10 MB` |
| `SHALL` | Normative tool or system behaviour | `The tool SHALL report Unknown when data is unavailable` |
| `MAY` | Optional; not used for requirements | Not used in control text |

### Voice and tense

| Do | Do not |
|---|---|
| `Exchange Server stores credentials in …` | ~~`Credentials are stored in … by Exchange Server`~~ |
| `The tool reads the connector list from …` | ~~`The connector list is read by the tool from …`~~ |
| `SSLOffloading is True` | ~~`SSLOffloading has been found to be True`~~ |
| `Disable SSL Offloading before enabling …` | ~~`SSL Offloading should simply be disabled prior to …`~~ |

### Banned words in control text

Do not use: `simply`, `easily`, `quickly`, `just`, `obviously`, `note that`, `please be aware`,
`it should be noted`, `it is recommended`, `in order to`, `leverage`, `utilize`.

### Evidence string patterns

```
# Single finding
"OAuth2ClientProfileEnabled is False — run: Set-OrganizationConfig -OAuth2ClientProfileEnabled $true"

# Scoped finding
"SSLOffloading is enabled on 2 Outlook Anywhere connector(s): ex1\RPC (Default Web Site), ex2\RPC (Default Web Site)"

# Data unavailable
"Send connector data unavailable."

# Pass summary
"OAuth2ClientProfileEnabled is True; EvoSTS auth server configured (HMA); SSL Offloading disabled; OAuth enabled on all 6 checked virtual directory(s)."
```
