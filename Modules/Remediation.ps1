# Script:  Remediation.ps1
# Synopsis: Part of EDCA (Exchange Deployment & Compliance Assessment)
#           https://github.com/michelderooij/EDCA
# Author:  Michel de Rooij
# Website: https://eightwone.com

Set-StrictMode -Version Latest

function New-EDCARemediationScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$AnalysisData,
        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )

    $failed = @($AnalysisData.Findings | Where-Object { $_.OverallStatus -eq 'Fail' -and $_.Verify })

    $builder = New-Object System.Text.StringBuilder
    $null = $builder.AppendLine('# =============================================================')
    $null = $builder.AppendLine('# EDCA - Generated Sample Script')
    $null = $builder.AppendLine('# This script is provided as template derived from failed control evaluations.')
    $null = $builder.AppendLine('# It has not been reviewed or validated for your specific environment.')
    $null = $builder.AppendLine('# Review, test, and adapt this script thoroughly in a non-production environment')
    $null = $builder.AppendLine('# The author provides this script as-is without warranty or support. Use at your own risk.')
    $null = $builder.AppendLine('# =============================================================')
    $null = $builder.AppendLine('')
    $null = $builder.AppendLine('#requires -version 5.1')
    $null = $builder.AppendLine('param([switch]$WhatIfMode)')
    $null = $builder.AppendLine('Set-StrictMode -Version Latest')
    $null = $builder.AppendLine("`$ErrorActionPreference = 'Stop'")
    $null = $builder.AppendLine('')
    $null = $builder.AppendLine('Write-Host "Exchange SE remediation script" -ForegroundColor Cyan')
    $null = $builder.AppendLine('Write-Host "Run in an approved change window. Current user context is used." -ForegroundColor Yellow')
    $null = $builder.AppendLine('')

    foreach ($finding in $failed) {
        $functionName = ('Invoke-{0}' -f $finding.ControlId)
        $null = $builder.AppendLine(('function {0} {{' -f $functionName))
        $null = $builder.AppendLine(('    Write-Host "[{0}] {1}" -ForegroundColor Cyan' -f $finding.ControlId, ($finding.Title -replace '"', "'")))

        if ($finding.Remediation.automatable) {
            $template = [string]$finding.Remediation.scriptTemplate
            $escapedTemplate = $template -replace '"', "'"
            $null = $builder.AppendLine('    if ($WhatIfMode) {')
            $null = $builder.AppendLine(('        Write-Host "[WhatIf] {0}" -ForegroundColor Yellow' -f $escapedTemplate))
            $null = $builder.AppendLine('        return')
            $null = $builder.AppendLine('    }')
            $null = $builder.AppendLine(('    {0}' -f $template))
        }
        else {
            $description = ([string]$finding.Remediation.description) -replace '"', "'"
            $null = $builder.AppendLine(('    Write-Host "Manual remediation required: {0}" -ForegroundColor Yellow' -f $description))
        }

        $null = $builder.AppendLine('}')
        $null = $builder.AppendLine('')
    }

    $null = $builder.AppendLine('Write-Host "Applying remediation actions for failed checks..." -ForegroundColor Green')
    foreach ($finding in $failed) {
        $functionName = ('Invoke-{0}' -f $finding.ControlId)
        $null = $builder.AppendLine($functionName)
    }

    if ($failed.Count -eq 0) {
        $null = $builder.AppendLine('Write-Host "No failed checks found; no remediation actions generated." -ForegroundColor Green')
    }

    Set-Content -Path $OutputFile -Value $builder.ToString() -Encoding UTF8
    return $OutputFile
}

