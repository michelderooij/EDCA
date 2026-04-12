<#
.SYNOPSIS
    EDCA — Exchange Deployment & Compliance Assessment.

    Version: 0.1 Preview
    Author:  Michel de Rooij
    Website: https://eightwone.com


.DESCRIPTION
    EDCA (Exchange Deployment & Compliance Assessment) collects configuration data from Exchange 2016,
    Exchange 2019, and Exchange SE servers, evaluates each server against a library of best-practice
    and security controls, and produces a detailed HTML report with pass/fail findings, severity
    ratings, and remediation guidance.

    Two modes are supported:
      Collect — connects to one or more Exchange servers, gathers configuration telemetry, and
                exports the raw data to a timestamped JSON file in the Output folder.
      Report  — imports a previously collected JSON file, runs the analysis engine against the loaded
                controls library, generates an HTML report, and optionally outputs a PowerShell
                remediation script.

.PARAMETER Mode
    Operating mode: Collect (default) or Report.

.PARAMETER Servers
    List of Exchange server names to target during collection (Collect mode only).

.PARAMETER ThrottleLimit
    Maximum number of parallel collection jobs (default: 4; range 1–128).

.PARAMETER ControlFile
    Path to the JSON controls library (default: .\Config\controls.json).

.PARAMETER OutputPath
    Directory for analysis JSON and remediation script output files (default: .\Output).

.PARAMETER DataPath
    Directory for collected JSON data files (default: .\Data). One JSON file is written per
    server, named <fqdn>_<timestamp>.json.

.PARAMETER ImportJson
    One or more paths to previously collected per-server JSON files, or a folder path whose
    JSON files are all processed (Report mode only). Multiple values may be comma-separated
    or passed via the pipeline. When a folder is supplied every *.json file it contains is
    included and the server records are merged before analysis.

.PARAMETER GenerateRemediationScript
    When specified, generates a PowerShell remediation script alongside the HTML report.

.PARAMETER SkipHtml
    When specified, skips HTML report generation (analysis JSON is still written).

.EXAMPLE
    .\EDCA.ps1 -Mode Collect -Servers EX01,EX02

.EXAMPLE
    .\EDCA.ps1 -Mode Report -ImportJson .\Data\ex01.contoso.com_20250101_120000.json

.EXAMPLE
    .\EDCA.ps1 -Mode Report -ImportJson .\Data\ex01.contoso.com_20250101_120000.json,.\Data\ex02.contoso.com_20250101_120000.json

.EXAMPLE
    .\EDCA.ps1 -Mode Report -ImportJson .\Data
#>
#requires -version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Collect', 'Report')]
    [string]$Mode = 'Collect',
    [string[]]$Servers = @(),
    [ValidateRange(1, 128)]
    [int]$ThrottleLimit = 4,
    [string]$ControlFile = '.\Config\controls.json',
    [string]$OutputPath = '.\Output',
    [string]$DataPath = '.\Data',
    [string[]]$ImportJson,
    [switch]$GenerateRemediationScript,
    [switch]$SkipHtml
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

. (Join-Path -Path $scriptRoot -ChildPath 'Modules\Common.ps1')
. (Join-Path -Path $scriptRoot -ChildPath 'Modules\Collection.ps1')
. (Join-Path -Path $scriptRoot -ChildPath 'Modules\Analysis.ps1')
. (Join-Path -Path $scriptRoot -ChildPath 'Modules\Reporting.ps1')
. (Join-Path -Path $scriptRoot -ChildPath 'Modules\Remediation.ps1')

$resolvedOutputPath = Resolve-EDCAPath -Path $OutputPath -BasePath $scriptRoot
$resolvedDataPath = Resolve-EDCAPath -Path $DataPath -BasePath $scriptRoot
$resolvedReportPath = Join-Path -Path $scriptRoot -ChildPath 'Reports'
$resolvedControlFile = Resolve-EDCAPath -Path $ControlFile -BasePath $scriptRoot
New-EDCADirectoryIfMissing -Path $resolvedOutputPath
New-EDCADirectoryIfMissing -Path $resolvedDataPath
New-EDCADirectoryIfMissing -Path $resolvedReportPath

Write-Verbose ('Execution mode: {0}' -f $Mode)
Write-Verbose ('Resolved control file: {0}' -f $resolvedControlFile)
Write-Verbose ('Resolved output path: {0}' -f $resolvedOutputPath)
Write-Verbose ('Resolved data path: {0}' -f $resolvedDataPath)
Write-Verbose ('Resolved report path: {0}' -f $resolvedReportPath)
Write-Verbose ('Collection throttle limit: {0}' -f $ThrottleLimit)

if (-not (Test-Path -Path $resolvedControlFile)) {
    throw ('Control file not found: {0}' -f $resolvedControlFile)
}

$controls = Get-Content -Path $resolvedControlFile -Raw | ConvertFrom-Json
if ($null -eq $controls -or @($controls).Count -eq 0) {
    throw 'No controls loaded from control file.'
}
Write-Verbose ('Loaded {0} control definition(s).' -f @($controls).Count)

$collectionData = $null

if ($Mode -eq 'Collect') {
    Write-EDCALog -Message 'Starting collection mode.'
    Write-Verbose ('Collect mode target count from parameters: {0}' -f @($Servers).Count)
    $collectionData = Invoke-EDCACollection -Servers $Servers -ThrottleLimit $ThrottleLimit

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $exportedFiles = [System.Collections.Generic.List[string]]::new()

    foreach ($serverRecord in @($collectionData.Servers)) {
        $serverFqdn = if ($serverRecord.PSObject.Properties.Name -contains 'Server') { [string]$serverRecord.Server } else { 'unknown' }
        $safeName = $serverFqdn -replace '[^\w\.\-]', '_'
        $jsonOut = Join-Path -Path $resolvedDataPath -ChildPath ('{0}_{1}.json' -f $safeName, $stamp)

        $perServerMetadata = [pscustomobject]@{
            ToolName            = $collectionData.Metadata.ToolName
            ToolVersion         = $collectionData.Metadata.ToolVersion
            CollectionTimestamp = $collectionData.Metadata.CollectionTimestamp
            ExecutedBy          = $collectionData.Metadata.ExecutedBy
            ServerName          = $serverFqdn
        }

        $perServerData = [pscustomobject]@{
            Metadata            = $perServerMetadata
            Servers             = @($serverRecord)
            Organization        = $collectionData.Organization
            EmailAuthentication = $collectionData.EmailAuthentication
        }

        ConvertTo-EDCAJson -InputObject $perServerData | Set-Content -Path $jsonOut -Encoding UTF8
        $exportedFiles.Add($jsonOut)
        Write-Verbose ('Server JSON exported: {0}' -f $jsonOut)
    }

    Write-EDCALog -Message ('Collection complete: {0} server JSON file(s) written to {1}' -f $exportedFiles.Count, $resolvedDataPath)
    Write-Verbose ('Collection output includes {0} server record(s).' -f @($collectionData.Servers).Count)
}
else {
    if ($null -eq $ImportJson -or $ImportJson.Count -eq 0) {
        throw 'Report mode requires -ImportJson.'
    }

    # Expand each entry: folders become their contained *.json files, files are used as-is.
    $jsonFiles = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in $ImportJson) {
        $resolved = Resolve-EDCAPath -Path $entry -BasePath $scriptRoot
        if (Test-Path -Path $resolved -PathType Container) {
            $found = @(Get-ChildItem -Path $resolved -Filter '*.json' -File | Select-Object -ExpandProperty FullName)
            if ($found.Count -eq 0) {
                throw ('No JSON files found in folder: {0}' -f $resolved)
            }
            $jsonFiles.AddRange($found)
        }
        elseif (Test-Path -Path $resolved -PathType Leaf) {
            $jsonFiles.Add($resolved)
        }
        else {
            throw ('Import JSON not found: {0}' -f $resolved)
        }
    }

    Write-EDCALog -Message ('Loading {0} collection JSON file(s).' -f $jsonFiles.Count)

    # Parse all files and track metadata alongside each server record.
    # Each parsed file contributes: its file-level CollectionTimestamp (from Metadata), its
    # ServerName (from Metadata.ServerName), and the actual server data record.
    $allParsed = [System.Collections.Generic.List[pscustomobject]]::new()
    $latestOrganization = $null
    $latestEmailAuth = $null
    $latestOrgTimestamp = [datetime]::MinValue
    $latestBaseMetadata = $null

    foreach ($jsonFile in $jsonFiles) {
        $parsed = Get-Content -Path $jsonFile -Raw | ConvertFrom-Json

        $fileTimestamp = [datetime]::MinValue
        if ($parsed.PSObject.Properties.Name -contains 'Metadata') {
            $ts = $parsed.Metadata.CollectionTimestamp
            if ($null -ne $ts) {
                try { $fileTimestamp = [datetime]$ts } catch { }
            }

            if ($null -eq $latestBaseMetadata -or $fileTimestamp -gt $latestOrgTimestamp) {
                $latestBaseMetadata = $parsed.Metadata
            }
        }

        # Track the most recently collected Organization / EmailAuthentication as the shared baseline.
        if ($fileTimestamp -gt $latestOrgTimestamp) {
            if ($parsed.PSObject.Properties.Name -contains 'Organization') { $latestOrganization = $parsed.Organization }
            if ($parsed.PSObject.Properties.Name -contains 'EmailAuthentication') { $latestEmailAuth = $parsed.EmailAuthentication }
            $latestOrgTimestamp = $fileTimestamp
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

        Write-Verbose ('Parsed file {0}: server={1}, timestamp={2}' -f $jsonFile, $serverName, $fileTimestamp)
    }

    # Deduplicate: for each unique ServerName, keep only the record from the most recent file.
    # Files without a ServerName in Metadata are always kept (legacy format / unknown).
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

    # Append records that had no ServerName in Metadata (always include, no dedup possible).
    foreach ($entry in @($allParsed | Where-Object { [string]::IsNullOrWhiteSpace($_.ServerName) })) {
        $deduplicatedServers.Add($entry.Record)
    }

    # Assemble a merged collection object using the most recently collected baseline data.
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
$analysisOut = Join-Path -Path $resolvedOutputPath -ChildPath ('analysis_{0}.json' -f $analysisStamp)
ConvertTo-EDCAJson -InputObject $analysis | Set-Content -Path $analysisOut -Encoding UTF8
Write-EDCALog -Message ('Analysis JSON exported: {0}' -f $analysisOut)
Write-Verbose ('Analysis produced {0} finding(s).' -f @($analysis.Findings).Count)

if (-not $SkipHtml) {
    Write-Verbose 'Starting HTML report generation phase.'
    $htmlOut = Join-Path -Path $resolvedReportPath -ChildPath ('report_{0}.html' -f $analysisStamp)
    $resultPath = New-EDCAHtmlReport -CollectionData $collectionData -AnalysisData $analysis -OutputFile $htmlOut
    Write-EDCALog -Message ('HTML report generated: {0}' -f $resultPath)
}

if ($GenerateRemediationScript) {
    Write-Verbose 'Starting remediation script generation phase.'
    $remediationOut = Join-Path -Path $resolvedOutputPath -ChildPath ('remediation_{0}.ps1' -f $analysisStamp)
    $remediationPath = New-EDCARemediationScript -AnalysisData $analysis -OutputFile $remediationOut
    Write-EDCALog -Message ('Remediation script generated: {0}' -f $remediationPath)
}

Write-EDCALog -Message 'Execution completed.'

