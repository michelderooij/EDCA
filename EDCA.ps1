<#
.SYNOPSIS
    EDCA — Exchange Deployment & Compliance Assessment.

    Version: 0.3 Preview
    Author:  Michel de Rooij
    Source:  https://github.com/michelderooij/EDCA
    Website: https://eightwone.com

.DESCRIPTION
    EDCA (Exchange Deployment & Compliance Assessment) collects configuration data from Exchange 2016,
    Exchange 2019, and Exchange SE servers, evaluates each server against a library of best-practice
    and security controls, and produces a detailed HTML report with pass/fail findings, severity
    ratings, and remediation guidance.

    Use -Collect to run the collection phase only, -Report to run the report phase only, or both
    switches together to run collection and reporting in a single run. When neither switch is
    specified, both phases run by default (equivalent to specifying -Collect -Report).

.PARAMETER Collect
    Runs the collection phase only. Connects to the target Exchange servers, gathers configuration
    telemetry, and writes per-server and organization JSON files to the Data folder (-DataPath).
    Cannot be combined with -Report; -Servers and -ThrottleLimit are not available in -Report mode.

.PARAMETER Report
    Runs the report phase only. Reads all *.json files from the Data folder (-DataPath), runs the
    analysis engine against the controls library, and generates an HTML report. Cannot be combined
    with -Collect; -Servers and -ThrottleLimit are not available in this mode. When neither -Collect
    nor -Report is specified, both phases run sequentially (equivalent to specifying both switches).

.PARAMETER Servers
    List of Exchange server names to target during the collection phase.

.PARAMETER ThrottleLimit
    Maximum number of parallel collection jobs (default: 4; range 1–128).

.PARAMETER ControlFile
    Path to the JSON controls library (default: .\Config\controls.json).

.PARAMETER OutputPath
    Directory for analysis JSON and remediation script output files (default: .\Output).

.PARAMETER DataPath
    Directory for JSON data files (default: .\Data). During collection, per-server and
    organization JSON files are written here. During reporting, all *.json files in this
    directory are read as input for analysis.

.PARAMETER RemediationScript
    When specified, generates a PowerShell remediation script alongside the HTML report.

.PARAMETER Framework
    One or more framework names to include in the analysis. When specified, only controls tagged
    with at least one of the supplied frameworks are evaluated. Valid values are:
    Best Practice, CIS, CISA, DISA, ENISA.
    When omitted, all controls are evaluated regardless of framework.

.PARAMETER Update
    When specified, downloads the latest exchange.builds.json from GitHub and saves it to
    the Config directory, then continues with the requested operation.

.EXAMPLE
    .\EDCA.ps1 -Update

.EXAMPLE
    .\EDCA.ps1 -Servers EX01,EX02

.EXAMPLE
    .\EDCA.ps1 -Collect -Servers EX01,EX02

.EXAMPLE
    .\EDCA.ps1 -Report

.EXAMPLE
    .\EDCA.ps1 -Report -DataPath .\CustomData

.EXAMPLE
    .\EDCA.ps1 -Servers EX01,EX02 -Framework ENISA

.EXAMPLE
    .\EDCA.ps1 -Report -Framework 'Best Practice'
#>
#requires -version 5.1
[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    [Parameter(ParameterSetName = 'Collect', Mandatory = $true)]
    [switch]$Collect,

    [Parameter(ParameterSetName = 'Report', Mandatory = $true)]
    [switch]$Report,

    [Parameter(ParameterSetName = 'Default')]
    [Parameter(ParameterSetName = 'Collect')]
    [string[]]$Servers = @(),

    [Parameter(ParameterSetName = 'Default')]
    [Parameter(ParameterSetName = 'Collect')]
    [ValidateRange(1, 128)]
    [int]$ThrottleLimit = 4,

    [string]$ControlFile = '.\Config\controls.json',

    [Parameter(ParameterSetName = 'Default')]
    [Parameter(ParameterSetName = 'Report')]
    [string]$OutputPath = '.\Output',

    [string]$DataPath = '.\Data',

    [Parameter(ParameterSetName = 'Default')]
    [Parameter(ParameterSetName = 'Report')]
    [switch]$RemediationScript,

    [switch]$Update,

    [ValidateSet('Best Practice', 'CIS', 'CISA', 'DISA', 'ENISA')]
    [string[]]$Framework
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$EDCAVersion = 'v0.3 Preview'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

. (Join-Path -Path $scriptRoot -ChildPath 'Modules\Common.ps1')
. (Join-Path -Path $scriptRoot -ChildPath 'Modules\Collection.ps1')
. (Join-Path -Path $scriptRoot -ChildPath 'Modules\Analysis.ps1')
. (Join-Path -Path $scriptRoot -ChildPath 'Modules\Reporting.ps1')
. (Join-Path -Path $scriptRoot -ChildPath 'Modules\Remediation.ps1')

# Derive phase flags from the active parameter set.
$doCollect = $PSCmdlet.ParameterSetName -in @('Collect', 'Default')
$doReport = $PSCmdlet.ParameterSetName -in @('Report', 'Default')

Write-Host ('=============================================================' )
Write-Host ('EXCHANGE DEPLOYMENT & COMPLIANCE ASSESSMENT {0}' -f $EDCAVersion)
Write-Host ('=============================================================' )

$resolvedDataPath = Resolve-EDCAPath -Path $DataPath -BasePath $scriptRoot
$resolvedOutputPath = Resolve-EDCAPath -Path $OutputPath -BasePath $scriptRoot
$resolvedControlFile = Resolve-EDCAPath -Path $ControlFile -BasePath $scriptRoot
New-EDCADirectoryIfMissing -Path $resolvedDataPath

Write-Verbose ('Collect: {0}; Report: {1}' -f $doCollect, $doReport)
Write-Verbose ('Resolved control file: {0}' -f $resolvedControlFile)
Write-Verbose ('Resolved data path: {0}' -f $resolvedDataPath)
Write-Verbose ('Resolved output path: {0}' -f $resolvedOutputPath)
Write-Verbose ('Collection throttle limit: {0}' -f $ThrottleLimit)

if (-not (Test-Path -Path $resolvedControlFile)) {
    throw ('Control file not found: {0}' -f $resolvedControlFile)
}

$controls = Get-Content -Path $resolvedControlFile -Raw | ConvertFrom-Json
if ($null -eq $controls -or @($controls).Count -eq 0) {
    throw 'No controls loaded from control file.'
}
Write-Verbose ('Loaded {0} control definition(s).' -f @($controls).Count)

if ($Framework -and $Framework.Count -gt 0) {
    $filteredForOutput = @($controls | Where-Object {
            $ctrl = $_
            @($ctrl.frameworks) | Where-Object { $Framework -contains $_ }
        })
    if ($filteredForOutput.Count -eq 0) {
        throw ('No controls match the specified framework(s): {0}' -f ($Framework -join ', '))
    }
    Write-Verbose ('Framework filter [{0}] will be applied to report and remediation output: {1} control(s) match.' -f ($Framework -join ', '), $filteredForOutput.Count)
    Write-EDCALog -Message ('Framework filter: {0} — {1} control(s) will appear in report and remediation output.' -f ($Framework -join ', '), $filteredForOutput.Count)
}

if ($Update) {
    Write-EDCALog -Message 'Updating build information.'
    $buildsUrl = 'https://raw.githubusercontent.com/michelderooij/EDCA/refs/heads/main/Config/exchange.builds.json'
    $buildsPath = Join-Path -Path $scriptRoot -ChildPath 'Config\exchange.builds.json'
    try {
        $content = (Invoke-WebRequest -Uri $buildsUrl -UseBasicParsing -ErrorAction Stop).Content
        $null = $content | ConvertFrom-Json
        [System.IO.File]::WriteAllText($buildsPath, $content, [System.Text.UTF8Encoding]::new($false))
        Write-EDCALog -Message 'exchange.builds.json updated successfully.'
    }
    catch {
        Write-Warning ('Failed to update exchange.builds.json: {0}' -f $_.Exception.Message)
    }
    if ($doCollect -and @($Servers).Count -eq 0) {
        Write-EDCALog -Message 'Execution completed.'
        return
    }
}

$collectionData = $null

if ($doCollect) {
    Write-EDCALog -Message 'Starting collection mode.'
    Write-Verbose ('Collect mode target count from parameters: {0}' -f @($Servers).Count)
    $collectionData = Invoke-EDCACollection -Servers $Servers -ThrottleLimit $ThrottleLimit -ToolVersion $EDCAVersion

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $exportedFiles = [System.Collections.Generic.List[string]]::new()

    foreach ($serverRecord in @($collectionData.Servers)) {
        $serverFqdn = if ($serverRecord.PSObject.Properties.Name -contains 'Server') { [string]$serverRecord.Server } else { 'unknown' }
        $safeName = $serverFqdn -replace '[^\w\.\-]', '_'
        $jsonOut = Join-Path -Path $resolvedDataPath -ChildPath ('{0}_{1}.json' -f $safeName, $stamp)

        $perServerMetadata = [pscustomobject]@{
            FileType            = 'Server'
            ToolName            = $collectionData.Metadata.ToolName
            ToolVersion         = $collectionData.Metadata.ToolVersion
            CollectionTimestamp = $collectionData.Metadata.CollectionTimestamp
            ExecutedBy          = $collectionData.Metadata.ExecutedBy
            ServerName          = $serverFqdn
        }

        $perServerData = [pscustomobject]@{
            Metadata = $perServerMetadata
            Servers  = @($serverRecord)
        }

        ConvertTo-EDCAJson -InputObject $perServerData | Set-Content -Path $jsonOut -Encoding UTF8
        $exportedFiles.Add($jsonOut)
        Write-Verbose ('Server JSON exported: {0}' -f $jsonOut)
    }

    # Write the organization-wide JSON file (separate from per-server files).
    $rawOrgId = $null
    if (($collectionData.Organization.PSObject.Properties.Name -contains 'OrganizationIdentity') -and
        -not [string]::IsNullOrWhiteSpace([string]$collectionData.Organization.OrganizationIdentity)) {
        $rawOrgId = [string]$collectionData.Organization.OrganizationIdentity
    }
    $safeOrgId = if ($null -ne $rawOrgId) { $rawOrgId -replace '[^\w\.\-]', '_' } else { 'organization' }
    $orgJsonOut = Join-Path -Path $resolvedDataPath -ChildPath ('{0}_{1}.json' -f $safeOrgId, $stamp)

    $orgMetadata = [pscustomobject]@{
        FileType            = 'Organization'
        ToolName            = $collectionData.Metadata.ToolName
        ToolVersion         = $collectionData.Metadata.ToolVersion
        CollectionTimestamp = $collectionData.Metadata.CollectionTimestamp
        ExecutedBy          = $collectionData.Metadata.ExecutedBy
        OrganizationId      = $rawOrgId
    }

    $orgData = [pscustomobject]@{
        Metadata            = $orgMetadata
        Organization        = $collectionData.Organization
        EmailAuthentication = $collectionData.EmailAuthentication
    }

    ConvertTo-EDCAJson -InputObject $orgData | Set-Content -Path $orgJsonOut -Encoding UTF8
    $exportedFiles.Add($orgJsonOut)
    Write-Verbose ('Organization JSON exported: {0}' -f $orgJsonOut)

    Write-EDCALog -Message ('Collection complete: {0} server JSON file(s) and 1 organization JSON file written to {1}' -f ($exportedFiles.Count - 1), $resolvedDataPath)
    if ($doCollect -and -not $doReport) {
        Write-EDCALog -Message 'Execution completed.'
        return
    }
}

if ($doReport -and -not $doCollect) {
    $jsonFiles = [string[]](Get-ChildItem -Path $resolvedDataPath -Filter '*.json' -File |
        Select-Object -ExpandProperty FullName)
    if ($jsonFiles.Count -eq 0) {
        throw ('No JSON files found in data folder: {0}' -f $resolvedDataPath)
    }

    Write-EDCALog -Message ('Found {0} JSON file(s) to evaluate.' -f $jsonFiles.Count)

    # Parse all files. Organization files (FileType='Organization') are separated from server files.
    $allParsed = [System.Collections.Generic.List[pscustomobject]]::new()
    $allOrgFiles = [System.Collections.Generic.List[pscustomobject]]::new()
    $latestBaseMetadata = $null
    $latestBaseTimestamp = [datetime]::MinValue

    foreach ($jsonFile in $jsonFiles) {
        $parsed = Get-Content -Path $jsonFile -Raw | ConvertFrom-Json

        $fileTimestamp = [datetime]::MinValue
        if ($parsed.PSObject.Properties.Name -contains 'Metadata' -and
            $parsed.Metadata.PSObject.Properties.Name -contains 'CollectionTimestamp') {
            $ts = $parsed.Metadata.CollectionTimestamp
            if ($null -ne $ts) {
                try {
                    if ($ts -is [datetime]) {
                        $fileTimestamp = $ts
                    }
                    else {
                        $fileTimestamp = [datetime]::Parse([string]$ts)
                    }
                }
                catch { }
            }
        }

        # Skip non-collection files (e.g., analysis_*.json exports written by this tool).
        $hasCollectionContent = ($parsed.PSObject.Properties.Name -contains 'Servers') -or
        ($parsed.PSObject.Properties.Name -contains 'Organization') -or
        ($parsed.PSObject.Properties.Name -contains 'EmailAuthentication')
        if (-not $hasCollectionContent) {
            Write-Verbose ('Discarding non-collection file: {0}' -f (Split-Path $jsonFile -Leaf))
            continue
        }

        # Detect organization file: explicit FileType or has Organisation/EmailAuth but no Servers.
        $fileType = ''
        if ($parsed.PSObject.Properties.Name -contains 'Metadata' -and
            $parsed.Metadata.PSObject.Properties.Name -contains 'FileType') {
            $fileType = [string]$parsed.Metadata.FileType
        }
        $isOrgFile = ($fileType -eq 'Organization') -or
        ($parsed.PSObject.Properties.Name -notcontains 'Servers' -and
        ($parsed.PSObject.Properties.Name -contains 'Organization' -or
        $parsed.PSObject.Properties.Name -contains 'EmailAuthentication'))

        if ($isOrgFile) {
            $allOrgFiles.Add([pscustomobject]@{
                    Timestamp = $fileTimestamp
                    Parsed    = $parsed
                    FilePath  = $jsonFile
                })
            continue
        }

        # Server file — track base metadata from the most recent file seen so far.
        if ($fileTimestamp -gt $latestBaseTimestamp) {
            if ($parsed.PSObject.Properties.Name -contains 'Metadata') {
                $latestBaseMetadata = $parsed.Metadata
            }
            $latestBaseTimestamp = $fileTimestamp
        }

        $serverName = ''
        if ($parsed.PSObject.Properties.Name -contains 'Metadata' -and
            $parsed.Metadata.PSObject.Properties.Name -contains 'ServerName') {
            $serverName = [string]$parsed.Metadata.ServerName
        }

        foreach ($srv in @($parsed.Servers)) {
            $allParsed.Add([pscustomobject]@{
                    Timestamp  = $fileTimestamp
                    ServerName = $serverName
                    Record     = $srv
                    FilePath   = $jsonFile
                })
        }

        # Legacy server files may still carry Organization/EmailAuthentication — treat as org candidate too.
        if ($parsed.PSObject.Properties.Name -contains 'Organization' -or
            $parsed.PSObject.Properties.Name -contains 'EmailAuthentication') {
            $allOrgFiles.Add([pscustomobject]@{
                    Timestamp = $fileTimestamp
                    Parsed    = $parsed
                    FilePath  = $jsonFile
                })
        }

        Write-Verbose ('Parsed server file {0}: server={1}, timestamp={2}' -f $jsonFile, $serverName, $fileTimestamp)
    }

    # Deduplicate server records: for each ServerName keep the most recent file's record.
    $deduplicatedServers = [System.Collections.Generic.List[object]]::new()
    $namedGroups = $allParsed | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ServerName) } |
    Group-Object -Property ServerName

    foreach ($group in $namedGroups) {
        $best = $group.Group | Sort-Object -Property Timestamp -Descending | Select-Object -First 1
        $deduplicatedServers.Add($best.Record)
        if ($group.Group.Count -gt 1) {
            $skipped = $group.Group.Count - 1
            Write-Verbose ('Server "{0}": {1} older file(s) skipped; using data from {2}' -f $group.Name, $skipped, $best.FilePath)
            Write-EDCALog -Message ('Server "{0}": {1} duplicate(s) found; using most recent collection ({2}).' -f $group.Name, $skipped, $best.Timestamp)
        }
    }

    # Append records without a ServerName in Metadata (legacy / unknown — always include).
    foreach ($entry in @($allParsed | Where-Object { [string]::IsNullOrWhiteSpace($_.ServerName) })) {
        $deduplicatedServers.Add($entry.Record)
    }

    # Pick organization data from the most recently collected org file.
    $latestOrganization = $null
    $latestEmailAuth = $null
    $latestOrgTimestamp = [datetime]::MinValue

    foreach ($orgEntry in $allOrgFiles) {
        if ($orgEntry.Timestamp -gt $latestOrgTimestamp) {
            if ($orgEntry.Parsed.PSObject.Properties.Name -contains 'Organization') {
                $latestOrganization = $orgEntry.Parsed.Organization
            }
            if ($orgEntry.Parsed.PSObject.Properties.Name -contains 'EmailAuthentication') {
                $latestEmailAuth = $orgEntry.Parsed.EmailAuthentication
            }
            $latestOrgTimestamp = $orgEntry.Timestamp
        }
    }

    if ($allOrgFiles.Count -gt 1) {
        $skippedOrg = $allOrgFiles.Count - 1
        $bestOrgFile = ($allOrgFiles | Sort-Object { $_.Timestamp } -Descending | Select-Object -First 1).FilePath
        Write-EDCALog -Message ('Organization data: {0} file(s) found; using most recent ({1}).' -f $allOrgFiles.Count, $bestOrgFile)
    }

    # Assemble merged collection object.
    $collectionData = [pscustomobject]@{
        Metadata            = $latestBaseMetadata
        Servers             = $deduplicatedServers.ToArray()
        Organization        = $latestOrganization
        EmailAuthentication = $latestEmailAuth
    }

    Write-Verbose ('Total collection data contains {0} server record(s) after deduplication.' -f @($collectionData.Servers).Count)
}

Write-Verbose 'Starting analysis phase.'
$analysis = Invoke-EDCAAnalysis -CollectionData $collectionData -Controls $controls

$analysisStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$analysisOut = Join-Path -Path $resolvedDataPath -ChildPath ('analysis_{0}.json' -f $analysisStamp)
ConvertTo-EDCAJson -InputObject $analysis | Set-Content -Path $analysisOut -Encoding UTF8
Write-EDCALog -Message ('Analysis JSON exported: {0}' -f $analysisOut)
Write-Verbose ('Analysis produced {0} finding(s).' -f @($analysis.Findings).Count)

$outputAnalysis = $analysis
if ($Framework -and $Framework.Count -gt 0) {
    $filteredFindings = @($analysis.Findings | Where-Object {
            $f = $_
            @($f.Frameworks) | Where-Object { $Framework -contains $_ }
        })
    $filteredScores = @($analysis.Scores | Where-Object { $_.Framework -eq 'All' -or $Framework -contains $_.Framework })
    $outputAnalysis = [pscustomobject]@{
        Metadata = $analysis.Metadata
        Scores   = $filteredScores
        Findings = $filteredFindings
    }
    Write-Verbose ('Framework filter applied to output: {0} finding(s) included in report and remediation.' -f $filteredFindings.Count)
}

New-EDCADirectoryIfMissing -Path $resolvedOutputPath
Write-Verbose 'Starting HTML report generation phase.'
$reportOut = Join-Path -Path $resolvedOutputPath -ChildPath ('report_{0}.html' -f $analysisStamp)
$reportPath = New-EDCAHtmlReport -CollectionData $collectionData -AnalysisData $outputAnalysis -OutputFile $reportOut
Write-EDCALog -Message ('HTML report generated: {0}' -f $reportPath)

if ($RemediationScript) {
    Write-Verbose 'Starting remediation script generation phase.'
    $remediationOut = Join-Path -Path $resolvedOutputPath -ChildPath ('remediation_{0}.ps1' -f $analysisStamp)
    $remediationPath = New-EDCARemediationScript -AnalysisData $outputAnalysis -OutputFile $remediationOut
    Write-EDCALog -Message ('Remediation script generated: {0}' -f $remediationPath)
}

Write-EDCALog -Message 'Execution completed.'

