[CmdletBinding()]
param(
    [string]$ControlsPath,
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptRoot = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) { $PSScriptRoot } else { (Get-Location).Path }
if ([string]::IsNullOrWhiteSpace($ControlsPath)) {
    $ControlsPath = Join-Path $scriptRoot 'Controls'
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $scriptRoot 'Mapping.md'
}

function ConvertTo-MarkdownCellText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    $escaped = $Text -replace '\|', '\|'
    $escaped = $escaped -replace "`r`n|`n|`r", '<br>'
    return $escaped.Trim()
}

function Get-ShortReferenceLabel {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return 'Reference'
    }

    $label = $Name.Trim()
    if ($label.Length -gt 110) {
        $label = $label.Substring(0, 107) + '...'
    }

    return $label
}

function Get-ReferenceTokens {
    param(
        [string]$Framework,
        [string]$ReferenceName
    )

    $name = [string]$ReferenceName
    $tokens = New-Object System.Collections.Generic.List[string]

    switch ($Framework) {
        'DISA' {
            foreach ($m in [regex]::Matches($name, 'EX\d{2}-[A-Z]{2}-\d{6}')) {
                if (-not $tokens.Contains($m.Value)) { $tokens.Add($m.Value) }
            }
            foreach ($m in [regex]::Matches($name, 'V-\d{6}')) {
                if (-not $tokens.Contains($m.Value)) { $tokens.Add($m.Value) }
            }
        }
        'BSI' {
            foreach ($m in [regex]::Matches($name, '(?:APP|SYS)\.\d+(?:\.\d+)?\.A\d+')) {
                if (-not $tokens.Contains($m.Value)) { $tokens.Add($m.Value) }
            }
        }
        'CIS' {
            foreach ($m in [regex]::Matches($name, 'CIS\s+([0-9]+(?:\.[0-9]+)*(?:\s*\([^)]+\))?)')) {
                $value = $m.Groups[1].Value.Trim()
                if (-not [string]::IsNullOrWhiteSpace($value) -and -not $tokens.Contains($value)) {
                    $tokens.Add($value)
                }
            }
        }
        'ISM' {
            foreach ($m in [regex]::Matches($name, 'ISM-\d{4}')) {
                if (-not $tokens.Contains($m.Value)) { $tokens.Add($m.Value) }
            }
        }
        'CISA' {
            foreach ($m in [regex]::Matches($name, 'AA\d{2}-\d{3}[A-Z]?')) {
                if (-not $tokens.Contains($m.Value)) { $tokens.Add($m.Value) }
            }
            foreach ($m in [regex]::Matches($name, 'BOD\s*\d{2}-\d{2}')) {
                $value = ($m.Value -replace '\s+', ' ').Trim()
                if (-not $tokens.Contains($value)) { $tokens.Add($value) }
            }
            if ($name -match 'Known Exploited Vulnerabilities|KEV') {
                if (-not $tokens.Contains('KEV')) { $tokens.Add('KEV') }
            }
        }
        'NIS2' {
            foreach ($m in [regex]::Matches($name, 'Article\s+\d+(?:\(\d+\))?(?:\([a-z]\))?')) {
                if (-not $tokens.Contains($m.Value)) { $tokens.Add($m.Value) }
            }
            if ((@($tokens).Count -eq 0) -and ($name -match 'NIS2|Directive \(EU\) 2022/2555')) {
                $tokens.Add('NIS2')
            }
        }
    }

    return ,$tokens.ToArray()
}

function Get-FrameworkReferenceCandidates {
    param(
        [string]$Framework,
        [object[]]$References
    )

    switch ($Framework) {
        'ANSSI' {
            return @($References | Where-Object { ([string]$_.name) -match 'ANSSI|cyber\.gouv\.fr' })
        }
        'BSI' {
            return @($References | Where-Object { ([string]$_.name) -match '\bBSI\b|\bAPP\.|\bSYS\.' })
        }
        'CIS' {
            return @($References | Where-Object { ([string]$_.name) -match '\bCIS\b' })
        }
        'CISA' {
            return @($References | Where-Object { ([string]$_.name) -match '\bCISA\b|AA\d{2}-\d{3}[A-Z]?|BOD\s*\d{2}-\d{2}|Known Exploited Vulnerabilities|KEV' })
        }
        'DISA' {
            return @($References | Where-Object { ([string]$_.name) -match 'DISA|STIG|V-\d{6}|EX\d{2}-[A-Z]{2}-\d{6}' })
        }
        'ISM' {
            return @($References | Where-Object { ([string]$_.name) -match '\bISM\b|ISM-\d{4}' })
        }
        'NIS2' {
            return @($References | Where-Object { ([string]$_.name) -match 'NIS2|Directive \(EU\) 2022/2555|ENISA / NIS2|NCSC-NL|Article\s+\d+' })
        }
        'Best Practice' {
            $others = @(
                'ANSSI', 'BSI', 'CIS', 'CISA', 'DISA', 'ISM',
                'NIS2', 'Directive \(EU\) 2022/2555',
                'AA\d{2}-\d{3}[A-Z]?', 'BOD\s*\d{2}-\d{2}', 'STIG',
                'V-\d{6}', 'ISM-\d{4}'
            )

            return @(
                $References | Where-Object {
                    $name = [string]$_.name
                    -not ($others | Where-Object { $name -match $_ })
                }
            )
        }
        default {
            return @()
        }
    }
}

if (-not (Test-Path -Path $ControlsPath)) {
    throw "Controls path not found: $ControlsPath"
}

$frameworkOrder = @('Best Practice', 'ANSSI', 'BSI', 'CIS', 'CISA', 'DISA', 'ISM', 'NIS2')
$controlFiles = Get-ChildItem -Path $ControlsPath -Filter '*.json' -File | Sort-Object Name

$controls = foreach ($file in $controlFiles) {
    Get-Content -Path $file.FullName -Raw | ConvertFrom-Json
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('# EDCA Control to Security Framework Mapping Matrix')
$lines.Add('')
$lines.Add('This document is generated from Controls JSON metadata using Generate-Mapping.ps1.')
$lines.Add('Framework cells contain comma-separated links with extracted control/article IDs only; when no ID can be extracted, a checkmark is used.')
$lines.Add('')

$headerColumns = @('EDCA Control', 'EDCA Control Title') + $frameworkOrder
$lines.Add('| ' + ($headerColumns -join ' | ') + ' |')
$lines.Add('| ' + (($headerColumns | ForEach-Object { '---' }) -join ' | ') + ' |')

foreach ($control in ($controls | Sort-Object id)) {
    $id = ConvertTo-MarkdownCellText -Text ([string]$control.id)
    $description = ConvertTo-MarkdownCellText -Text ([string]$control.title)
    $frameworks = @($control.frameworks | ForEach-Object { [string]$_ })
    $references = @($control.references)

    $cells = @($id, $description)

    foreach ($framework in $frameworkOrder) {
        if ($frameworks -notcontains $framework) {
            $cells += '—'
            continue
        }

        $candidates = Get-FrameworkReferenceCandidates -Framework $framework -References $references
        if (@($candidates).Count -eq 0) {
            $candidates = $references
        }

        $entries = New-Object System.Collections.Generic.List[string]

        foreach ($reference in $candidates) {
            $name = [string]$reference.name
            $url = [string]$reference.url

            if ([string]::IsNullOrWhiteSpace($url)) {
                continue
            }

            $tokens = Get-ReferenceTokens -Framework $framework -ReferenceName $name

            if (@($tokens).Count -gt 0) {
                foreach ($token in $tokens) {
                    $entry = ('[{0}]({1})' -f (ConvertTo-MarkdownCellText -Text $token), $url)
                    if (-not $entries.Contains($entry)) { $entries.Add($entry) }
                }
            }
        }

        if ($entries.Count -eq 0) {
            $cells += '✓'
        }
        else {
            $cells += ($entries.ToArray() -join ', ')
        }
    }

    $lines.Add('| ' + ($cells -join ' | ') + ' |')
}

Set-Content -Path $OutputPath -Value $lines -Encoding UTF8
Write-Host ("Generated mapping file: {0}" -f $OutputPath)
Write-Host ("Controls processed: {0}" -f @($controls).Count)
