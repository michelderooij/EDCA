# Author:  Michel de Rooij
# Website: https://eightwone.com

Set-StrictMode -Version Latest

function Get-EDCAStatusClass {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Status
    )

    switch ($Status) {
        'Pass' { return 'status-pass' }
        'Fail' { return 'status-fail' }
        'Skipped' { return 'status-skipped' }
        default { return 'status-unknown' }
    }
}

function Get-EDCARagLabel {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Status
    )

    switch ($Status) {
        'Pass' { return '<span class="rag-icon rag-pass" title="Passed">&#10004;</span>' }
        'Fail' { return '<span class="rag-icon rag-fail" title="Risk">&#10006;</span>' }
        'Skipped' { return '<span class="rag-icon rag-skip" title="Not applicable">&#8856;</span>' }
        default { return '<span class="rag-icon rag-warn" title="Warning">&#9888;</span>' }
    }
}

function Get-EDCAAggregateStatus {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string[]]$Statuses
    )

    $normalized = @($Statuses | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
    if ($normalized.Count -eq 0) {
        return 'Unknown'
    }

    $nonSkipped = @($normalized | Where-Object { $_ -ne 'Skipped' })
    if ($nonSkipped.Count -eq 0) {
        return 'Skipped'
    }

    if ($nonSkipped -contains 'Fail') {
        return 'Fail'
    }

    if ($nonSkipped -contains 'Unknown') {
        return 'Unknown'
    }

    return 'Pass'
}

function ConvertTo-EDCAHtmlEncoded {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    return [System.Security.SecurityElement]::Escape([string]$Value)
}

function ConvertTo-EDCAHtmlWithLineBreaks {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    $encoded = ConvertTo-EDCAHtmlEncoded -Value $Value
    return (($encoded -replace "`r`n", "`n") -replace "`n", '<br />')
}

function Format-EDCARemediationScriptForReport {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$ScriptTemplate
    )

    if ([string]::IsNullOrWhiteSpace($ScriptTemplate)) {
        return ''
    }

    $normalized = $ScriptTemplate -replace "`r`n", "`n"

    # Keep existing multiline templates unchanged.
    if ($normalized -match "`n") {
        return $normalized
    }

    # Render one-liner templates with command separators as one command per line.
    if ($normalized -match ';') {
        $parts = @($normalized -split ';' | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($parts.Count -gt 1) {
            return ($parts -join "`n")
        }
    }

    return $normalized
}

function New-EDCAHtmlReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$CollectionData,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$AnalysisData,
        [Parameter(Mandatory = $true)]
        [string]$OutputFile
    )

    Write-Verbose ('Generating HTML report for {0} findings and {1} server entries.' -f @($AnalysisData.Findings).Count, @($CollectionData.Servers).Count)
    $scoreCards = New-Object System.Text.StringBuilder
    foreach ($score in $AnalysisData.Scores) {
        $failCount = [int]$score.FailedControls
        $unknownCount = [int]$score.UnknownControls
        $skipCount = [int]$score.SkippedControls
        $totalCount = [int]$score.TotalControls
        $passCount = [math]::Max(0, $totalCount - $failCount - $unknownCount)
        $displayLabel = if ($score.Framework -eq 'All') { 'Total' } else { $score.Framework }

        $null = $scoreCards.AppendLine((
                ('<div class="score-card" data-pass="{0}" data-fail="{1}" data-warn="{2}" data-skip="{5}" data-label="{3}" data-score="{4}">' +
                '<canvas class="donut-canvas" width="120" height="120"></canvas>' +
                '<p class="card-label">{6}</p>' +
                '</div>') -f
                $passCount, $failCount, $unknownCount,
                $score.Framework,
                $score.Score,
                $skipCount,
                $displayLabel
            ))
    }

    $findingGroups = @{}
    foreach ($finding in $AnalysisData.Findings) {
        $frameworkText = ($finding.Frameworks -join ', ')
        $refs = @()
        foreach ($reference in $finding.References) {
            $refName = [string]$reference.name
            # DISA: "DISA STIG EX19-MB-000007: title (V-259646)" → "V-259646 title (EX19-MB-000007)"
            if ($refName -match '^DISA STIG ([A-Z0-9-]+): (.+?) \((V-\d+)\)$') {
                $refName = '{0} {1} ({2})' -f $Matches[3], $Matches[2], $Matches[1]
            }
            # CIS Benchmark with Section: "CIS ... Benchmark ..., Section X.Y.Z (L1): title" → "X.Y.Z (L1) title"
            elseif ($refName -match '^CIS .+?, Section ([\d.]+) \(([A-Z0-9]+)\): (.+)$') {
                $refName = '{0} ({1}) {2}' -f $Matches[1], $Matches[2], $Matches[3]
            }
            # CIS Controls: "CIS Controls vX, Control Y.Z (IGN): title" → "Y.Z (IGN) title"
            elseif ($refName -match '^CIS Controls v[\d.]+, Control ([\d.]+) \(([A-Z0-9]+)\): (.+)$') {
                $refName = '{0} ({1}) {2}' -f $Matches[1], $Matches[2], $Matches[3]
            }
            $refs += ('<li><a href="{0}" target="_blank" rel="noopener noreferrer">{1}</a></li>' -f $reference.url, (ConvertTo-EDCAHtmlEncoded -Value $refName))
        }
        $referencesHtml = if ($refs.Count -gt 0) { '<ul>' + ($refs -join '') + '</ul>' } else { '<p>No references.</p>' }

        $remediationHtml = '<p>No remediation command available.</p>'
        if (($finding.PSObject.Properties.Name -contains 'Remediation') -and $null -ne $finding.Remediation) {
            $remediationDescription = ''
            if (($finding.Remediation.PSObject.Properties.Name -contains 'description') -and -not [string]::IsNullOrWhiteSpace([string]$finding.Remediation.description)) {
                $remediationDescription = (ConvertTo-EDCAHtmlEncoded -Value $finding.Remediation.description)
            }

            $remediationScript = ''
            if (($finding.Remediation.PSObject.Properties.Name -contains 'scriptTemplate') -and -not [string]::IsNullOrWhiteSpace([string]$finding.Remediation.scriptTemplate)) {
                $formattedScript = Format-EDCARemediationScriptForReport -ScriptTemplate ([string]$finding.Remediation.scriptTemplate)
                $remediationScript = (ConvertTo-EDCAHtmlEncoded -Value $formattedScript)
            }

            $remediationParts = @()
            if (-not [string]::IsNullOrWhiteSpace($remediationDescription)) {
                $remediationParts += ('<p>{0}</p>' -f $remediationDescription)
            }
            if (-not [string]::IsNullOrWhiteSpace($remediationScript)) {
                $remediationParts += ('<pre><code>{0}</code></pre>' -f $remediationScript)
            }
            if ($remediationParts.Count -gt 0) {
                $remediationHtml = $remediationParts -join ''
            }
        }

        $considerationsHtml = ''
        if (($finding.PSObject.Properties.Name -contains 'Considerations') -and -not [string]::IsNullOrWhiteSpace([string]$finding.Considerations)) {
            $considerationsHtml = ('<p>{0}</p>' -f (ConvertTo-EDCAHtmlEncoded -Value $finding.Considerations))
        }

        $serverLines = @()
        $subjectLabel = if (($finding.PSObject.Properties.Name -contains 'SubjectLabel') -and -not [string]::IsNullOrWhiteSpace([string]$finding.SubjectLabel)) { [string]$finding.SubjectLabel } else { 'Server' }
        foreach ($serverResult in $finding.ServerResults) {
            $serverRagLabel = Get-EDCARagLabel -Status $serverResult.Status
            $serverLines += ('<tr class="{1}"><td>{0}</td><td>{2}</td><td class="evidence-cell">{3}</td></tr>' -f
                $serverResult.Server,
                (Get-EDCAStatusClass -Status $serverResult.Status),
                $serverRagLabel,
                (ConvertTo-EDCAHtmlWithLineBreaks -Value $serverResult.Evidence)
            )
        }

        $overallCss = Get-EDCAStatusClass -Status $finding.OverallStatus
        $overallRagLabel = Get-EDCARagLabel -Status $finding.OverallStatus
        $findingModalId = 'modal-' + ($finding.ControlId -replace '[^a-zA-Z0-9]', '-')
        $findingHtml = (
            ('<div class="finding-row {0}" data-status="{1}" data-category="{2}" data-framework="{3}" data-modal="{4}" data-id="{6}" data-title="{7}" data-description="{10}">' +
            '{5}<span class="finding-id">{6}</span> <span class="finding-title">{7}</span>' +
            '</div>' +
            '<div class="modal-data" id="{4}" hidden>' +
            '<h2>{6}: {7}</h2>' +
            '<p class="modal-meta"><strong>Category:</strong> {8} | <strong>Severity:</strong> {9} | <strong>Frameworks:</strong> {3}</p>' +
            '<p class="finding-description">{10}</p>' +
            '<h3>Evidence</h3>' +
            '<table class="evidence-table"><thead><tr><th>{15}</th><th>Status</th><th>Evidence</th></tr></thead><tbody>{11}</tbody></table>' +
            '<h3>Remediation</h3>{12}' +
            $(if (-not [string]::IsNullOrWhiteSpace($considerationsHtml)) { '<h3>Considerations</h3>{14}' } else { '' }) +
            '<h3>References</h3>{13}' +
            '</div>') -f
            $overallCss,
            $finding.OverallStatus,
            $finding.Category,
            $frameworkText,
            $findingModalId,
            $overallRagLabel,
            (ConvertTo-EDCAHtmlEncoded -Value $finding.ControlId),
            (ConvertTo-EDCAHtmlEncoded -Value $finding.Title),
            (ConvertTo-EDCAHtmlEncoded -Value $finding.Category),
            (ConvertTo-EDCAHtmlEncoded -Value $finding.Severity),
            (ConvertTo-EDCAHtmlEncoded -Value $finding.Description),
            ($serverLines -join ''),
            $remediationHtml,
            $referencesHtml,
            $considerationsHtml,
            $subjectLabel
        )

        $categoryName = [string]$finding.Category
        if ([string]::IsNullOrWhiteSpace($categoryName)) {
            $categoryName = 'Uncategorized'
        }

        if (-not $findingGroups.ContainsKey($categoryName)) {
            $findingGroups[$categoryName] = [pscustomobject]@{
                Builder  = (New-Object System.Text.StringBuilder)
                Statuses = @()
            }
        }

        $null = $findingGroups[$categoryName].Builder.AppendLine($findingHtml)
        $findingGroups[$categoryName].Statuses = @($findingGroups[$categoryName].Statuses) + @([string]$finding.OverallStatus)
    }

    $groupedFindingRows = New-Object System.Text.StringBuilder
    foreach ($categoryName in @($findingGroups.Keys | Sort-Object)) {
        $group = $findingGroups[$categoryName]
        $groupStatus = Get-EDCAAggregateStatus -Statuses @($group.Statuses)
        $groupCss = Get-EDCAStatusClass -Status $groupStatus
        $groupRagLabel = Get-EDCARagLabel -Status $groupStatus
        $groupCount = @($group.Statuses).Count
        $encodedCategoryName = ConvertTo-EDCAHtmlEncoded -Value $categoryName

        $null = $groupedFindingRows.AppendLine((
                '<details class="category-group {0}" data-category="{1}" data-group-status="{2}">
                <summary class="{0}">
                    <span class="status-label {0}">{3}</span>
                    <span class="category-name">{1}</span>
                    <span class="category-count">({4} controls)</span>
                </summary>
                <div class="category-group-body">
                    {5}
                </div>
            </details>' -f
                $groupCss,
                $encodedCategoryName,
                $groupStatus,
                $groupRagLabel,
                $groupCount,
                $group.Builder.ToString()
            ))
    }

    $metadata = $CollectionData.Metadata

    # Build environment notices (Edge servers, unsupported Exchange versions)
    $noticesHtml = New-Object System.Text.StringBuilder
    $edgeServers = @()
    if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
        ($CollectionData.Organization.PSObject.Properties.Name -contains 'EdgeServers')) {
        $edgeServers = @($CollectionData.Organization.EdgeServers)
    }
    if ($edgeServers.Count -gt 0) {
        $edgeNames = ($edgeServers | ForEach-Object { ConvertTo-EDCAHtmlEncoded -Value $_.Name }) -join ', '
        $null = $noticesHtml.AppendLine('<div class="env-notice"><span class="env-notice-icon">&#9888;</span><div><strong>Edge Transport servers detected</strong>Exchange Edge Transport servers are present in this environment (' + $edgeNames + '). EDCA does not collect data from or evaluate controls against Edge Transport servers. Edge-specific controls are not covered by this report.</div></div>')
    }
    $exchange2013Servers = @($CollectionData.Servers | Where-Object {
            ($_.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $_.Exchange -and
            ($_.Exchange.PSObject.Properties.Name -contains 'AdminDisplayVersion') -and
            ([string]$_.Exchange.AdminDisplayVersion -match '^Version 15\.0')
        })
    if ($exchange2013Servers.Count -gt 0) {
        $ex2013Names = ($exchange2013Servers | ForEach-Object { ConvertTo-EDCAHtmlEncoded -Value $_.Name }) -join ', '
        $null = $noticesHtml.AppendLine('<div class="env-notice"><span class="env-notice-icon">&#9888;</span><div><strong>Exchange Server 2013 detected &mdash; not supported</strong>Exchange Server 2013 was detected in this environment (' + $ex2013Names + '). EDCA does not support Exchange Server 2013. Collection and analysis results for these servers may be incomplete or inaccurate. Upgrade to a supported Exchange version.</div></div>')
    }
    $noticesSection = if ($noticesHtml.Length -gt 0) { "<div class=`"env-notices`">`n" + $noticesHtml.ToString() + "</div>`n" } else { '' }

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>EDCA: Exchange Deployment &amp; Compliance Assessment $($metadata.ToolVersion)</title>
    <style>
        :root {
            --bg:          #f2f6fc;
            --fg:          #1f2937;
            --card-bg:     #ffffff;
            --card-border: #cbd5e1;
            --header-bg:   #0f172a;
            --input-bg:    #ffffff;
            --input-border:#cbd5e1;
            --h2-color:    #0f172a;
            --id-color:    #334155;
            --summary-bg-p:#dcfce7; --summary-fg-p:#166534;
            --summary-bg-f:#fee2e2; --summary-fg-f:#991b1b;
            --summary-bg-u:#fef3c7; --summary-fg-u:#92400e;
            --row-bg-p:    #f0fdf4; --row-border-p: #16a34a;
            --row-bg-f:    #fef2f2; --row-border-f: #dc2626;
            --row-bg-u:    #fffbeb; --row-border-u: #d97706;
            --summary-bg-s:#f1f5f9; --summary-fg-s: #64748b;
            --row-bg-s:    #f8fafc; --row-border-s: #94a3b8;
            --desc-bg:     #f8fafc;
            --pre-bg:      #f8fafc;
            --pre-border:  #e2e8f0;
            --th-bg:       #f1f5f9;
            --td-border:   #e2e8f0;
            --modal-bg:    #ffffff;
            --modal-close: #64748b;
            --modal-h2:    #0f172a;
            --modal-h3:    #1e3a5f;
            --modal-meta:  #475569;
            --hover-bg:    #f8fafc;
            --donut-hole:  #ffffff;
            --donut-text:  #0f172a;
        }
        body.dark {
            --bg:          #0f172a;
            --fg:          #e2e8f0;
            --card-bg:     #1e293b;
            --card-border: #334155;
            --input-bg:    #1e293b;
            --input-border:#475569;
            --h2-color:    #e2e8f0;
            --id-color:    #94a3b8;
            --summary-bg-p:#14532d; --summary-fg-p:#86efac;
            --summary-bg-f:#7f1d1d; --summary-fg-f:#fca5a5;
            --summary-bg-u:#78350f; --summary-fg-u:#fde68a;
            --row-bg-p:    #14532d; --row-border-p: #22c55e;
            --row-bg-f:    #7f1d1d; --row-border-f: #f87171;
            --row-bg-u:    #78350f; --row-border-u: #fbbf24;
            --summary-bg-s:#1e293b; --summary-fg-s: #94a3b8;
            --row-bg-s:    #1e293b; --row-border-s: #475569;
            --desc-bg:     #1e293b;
            --pre-bg:      #0f172a;
            --pre-border:  #334155;
            --th-bg:       #1e293b;
            --td-border:   #334155;
            --modal-bg:    #1e293b;
            --modal-close: #94a3b8;
            --modal-h2:    #e2e8f0;
            --modal-h3:    #93c5fd;
            --modal-meta:  #94a3b8;
            --hover-bg:    #293548;
            --donut-hole:  #0f172a;
            --donut-text:  #e2e8f0;
        }
        *, *::before, *::after { box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; margin: 0; background: var(--bg); color: var(--fg); transition: background .2s, color .2s; }
        header { padding: 24px 32px; background: #0f172a; color: #f8fafc; display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; }
        header h1 { margin: 0 0 6px; font-size: 22px; }
        header p { margin: 0; font-size: 13px; opacity: .8; }
        /* Dark mode toggle */
        .dark-toggle { display: flex; align-items: center; gap: 8px; flex-shrink: 0; margin-top: 4px; }
        .dark-toggle-label { font-size: 12px; color: #94a3b8; white-space: nowrap; }
        .toggle-switch { position: relative; width: 44px; height: 24px; flex-shrink: 0; }
        .toggle-switch input { opacity: 0; width: 0; height: 0; position: absolute; }
        .toggle-track { position: absolute; inset: 0; background: #334155; border-radius: 24px; cursor: pointer; transition: background .2s; }
        .toggle-track::after { content: ''; position: absolute; left: 3px; top: 3px; width: 18px; height: 18px; background: #f8fafc; border-radius: 50%; transition: transform .2s; }
        .toggle-switch input:checked + .toggle-track { background: #3b82f6; }
        .toggle-switch input:checked + .toggle-track::after { transform: translateX(20px); }
        .toggle-switch input:focus-visible + .toggle-track { outline: 2px solid #60a5fa; outline-offset: 2px; }
        main { padding: 24px; max-width: 1400px; margin: 0 auto; }
        h2 { color: var(--h2-color); margin-top: 28px; margin-bottom: 12px; }
        /* Score cards / doughnuts */
        .score-grid { display: flex; flex-wrap: wrap; gap: 16px; }
        .score-card { background: var(--card-bg); border-radius: 12px; box-shadow: 0 4px 14px rgba(0,0,0,.08); padding: 14px 16px; display: flex; flex-direction: column; align-items: center; min-width: 140px; cursor: pointer; transition: transform .15s, box-shadow .15s; user-select: none; }
        .score-card:hover { transform: translateY(-2px); box-shadow: 0 6px 18px rgba(0,0,0,.14); }
        .score-card.active { outline: 2px solid #3b82f6; box-shadow: 0 4px 14px rgba(59,130,246,.35); }
        .donut-canvas { display: block; }
        .card-label { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; margin: 6px 0 0; color: var(--id-color); text-align: center; }
        /* RAG icons */
        .rag-icon { font-size: 15px; flex-shrink: 0; }
        .rag-pass { color: #16a34a; }
        .rag-warn { color: #d97706; }
        .rag-fail { color: #dc2626; }
        .rag-skip { color: #94a3b8; }
        /* Filters */
        .filters { display: flex; gap: 12px; flex-wrap: wrap; margin: 12px 0 16px; }
        select { padding: 8px 12px; border-radius: 8px; border: 1px solid var(--input-border); background: var(--input-bg); color: var(--fg); font-size: 14px; cursor: pointer; }
        .search-wrapper { position: relative; flex: 1 1 200px; min-width: 160px; display: flex; align-items: center; }
        input[type="text"].search-box { padding: 8px 12px; border-radius: 8px; border: 1px solid var(--input-border); background: var(--input-bg); color: var(--fg); font-size: 14px; flex: 1; min-width: 0; padding-right: 30px; outline: none; }
        input[type="text"].search-box:focus { border-color: #60a5fa; box-shadow: 0 0 0 2px rgba(96,165,250,.25); }
        .clear-btn { position: absolute; right: 8px; background: none; border: none; cursor: pointer; color: var(--fg); opacity: 0.45; font-size: 16px; padding: 0; line-height: 1; }
        .clear-btn:hover { opacity: 0.85; }
        .clear-btn:focus-visible { outline: 2px solid #60a5fa; border-radius: 3px; }
        select:focus { outline: 2px solid #3b82f6; }
        /* Category groups */
        details.category-group { background: var(--card-bg); border: 1px solid var(--card-border); border-radius: 12px; margin-bottom: 12px; overflow: hidden; }
        details.category-group > summary { cursor: pointer; list-style: none; padding: 12px 16px; display: flex; gap: 10px; align-items: center; font-weight: 700; user-select: none; }
        details.category-group > summary::-webkit-details-marker { display: none; }
        details.category-group > summary::before { content: '\25B8'; display: inline-block; margin-right: 2px; font-style: normal; }
        details.category-group[open] > summary::before { content: '\25BE'; }
        details.category-group.status-pass > summary { background: var(--summary-bg-p); color: var(--summary-fg-p); }
        details.category-group.status-fail > summary { background: var(--summary-bg-f); color: var(--summary-fg-f); }
        details.category-group.status-unknown > summary { background: var(--summary-bg-u); color: var(--summary-fg-u); }
        details.category-group.status-skipped > summary { background: var(--summary-bg-s); color: var(--summary-fg-s); }
        .category-count { opacity: .75; font-size: 13px; font-weight: 500; }
        .category-group-body { padding: 10px 12px 12px; }
        /* Finding rows */
        .finding-row { display: flex; align-items: center; gap: 10px; padding: 10px 12px; border: 1px solid var(--card-border); border-radius: 8px; margin-bottom: 7px; cursor: pointer; transition: box-shadow .15s, transform .1s; }
        .finding-row:hover { box-shadow: 0 3px 10px rgba(0,0,0,.12); transform: translateY(-1px); }
        .finding-row.status-pass    { border-left: 4px solid var(--row-border-p); background: var(--row-bg-p); }
        .finding-row.status-fail    { border-left: 4px solid var(--row-border-f); background: var(--row-bg-f); }
        .finding-row.status-unknown { border-left: 4px solid var(--row-border-u); background: var(--row-bg-u); }
        .finding-row.status-skipped { border-left: 4px solid var(--row-border-s); background: var(--row-bg-s); }
        .finding-id { font-family: Consolas, 'Courier New', monospace; font-weight: 600; color: var(--id-color); font-size: 13px; white-space: nowrap; }
        .finding-title { flex: 1; font-size: 14px; }
        /* Modal */
        .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.5); z-index: 1000; align-items: center; justify-content: center; }
        .modal-overlay.open { display: flex; }
        .modal-box { background: var(--modal-bg); color: var(--fg); border-radius: 16px; max-width: 940px; width: 92vw; max-height: 87vh; overflow-y: auto; padding: 28px 32px; position: relative; box-shadow: 0 20px 60px rgba(0,0,0,.3); }
        .modal-close { position: absolute; top: 14px; right: 18px; background: none; border: none; font-size: 24px; cursor: pointer; color: var(--modal-close); line-height: 1; padding: 4px 8px; border-radius: 6px; }
        .modal-close:hover { background: var(--hover-bg); color: var(--fg); }
        .modal-meta { color: var(--modal-meta); font-size: 13px; margin-bottom: 14px; }
        .modal-data h2 { margin-top: 0; font-size: 18px; color: var(--modal-h2); }
        .modal-data h3 { font-size: 15px; color: var(--modal-h3); border-top: 1px solid var(--td-border); padding-top: 12px; margin-top: 18px; }
        .finding-description { background: var(--desc-bg); border-radius: 8px; padding: 10px 14px; color: var(--fg); margin-bottom: 8px; }
        /* Evidence table */
        .evidence-table { width: 100%; border-collapse: collapse; margin: 8px 0; }
        .evidence-table th, .evidence-table td { text-align: left; border-bottom: 1px solid var(--td-border); padding: 8px 10px; font-size: 13px; }
        .evidence-table th { background: var(--th-bg); font-weight: 600; }
        td.evidence-cell { font-family: Consolas, 'Courier New', monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; }
        pre { margin: 8px 0 0; padding: 10px 14px; background: var(--pre-bg); border: 1px solid var(--pre-border); border-radius: 6px; overflow-x: auto; }
        pre code { font-family: Consolas, 'Courier New', monospace; font-size: 12px; white-space: pre; }
        .evidence-table tr.status-pass td    { background: var(--row-bg-p); }
        .evidence-table tr.status-fail td    { background: var(--row-bg-f); }
        .evidence-table tr.status-unknown td { background: var(--row-bg-u); }
        .evidence-table tr.status-skipped td { background: var(--row-bg-s); }
        /* Status utility */
        .status-pass    { background: var(--summary-bg-p); color: var(--summary-fg-p); }
        .status-fail    { background: var(--summary-bg-f); color: var(--summary-fg-f); }
        .status-unknown { background: var(--summary-bg-u); color: var(--summary-fg-u); }
        .status-skipped { background: var(--summary-bg-s); color: var(--summary-fg-s); }
        /* Inventory */
        .card { background: var(--card-bg); border-radius: 12px; box-shadow: 0 4px 14px rgba(0,0,0,.08); padding: 16px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; border-bottom: 1px solid var(--td-border); padding: 9px 10px; font-size: 13px; }
        th { background: var(--th-bg); font-weight: 600; }
        tbody tr:hover td { background: var(--hover-bg); }
        /* Environment notices */
        .env-notices { display: flex; flex-direction: column; gap: 10px; margin-bottom: 20px; }
        .env-notice { display: flex; align-items: flex-start; gap: 12px; padding: 12px 16px; border-radius: 10px; border-left: 4px solid #d97706; background: #fef3c7; color: #78350f; font-size: 13px; line-height: 1.5; }
        body.dark .env-notice { background: #451a03; color: #fde68a; border-left-color: #f59e0b; }
        .env-notice-icon { font-size: 17px; flex-shrink: 0; margin-top: 1px; }
        .env-notice strong { display: block; margin-bottom: 2px; }
        /* Print button */
        .print-btn { padding: 5px 14px; border-radius: 8px; border: 1px solid #475569; background: #1e293b; color: #f8fafc; font-size: 12px; cursor: pointer; white-space: nowrap; transition: background .15s; }
        .print-btn:hover { background: #334155; }
        .print-btn:focus-visible { outline: 2px solid #60a5fa; outline-offset: 2px; }
        /* Print / PDF */
        @media print {
            .no-print, .filters, .modal-overlay { display: none !important; }
            header { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
            body { background: #fff !important; }
            .score-grid { page-break-inside: avoid; }
            details.category-group { display: block !important; page-break-inside: avoid; margin-bottom: 8px; }
            details.category-group > .category-group-body { display: block !important; }
            details.category-group .finding-row { display: flex !important; box-shadow: none !important; transform: none !important; cursor: default !important; break-inside: avoid; }
            .score-card { box-shadow: none !important; cursor: default !important; }
            a[href]::after { content: none; }
        }
    </style>
</head>
<body>
    <header>
        <div>
            <h1>EDCA: Exchange Deployment &amp; Compliance Assessment $($metadata.ToolVersion)</h1>
            <p>Generated: $($metadata.CollectionTimestamp) | Executed by: $($metadata.ExecutedBy) | Author: <a href="https://eightwone.com" target="_blank" rel="noopener noreferrer" style="color:#93c5fd">Michel de Rooij</a></p>
        </div>
        <div class="dark-toggle no-print">
            <button class="print-btn" onclick="window.print()" title="Print or save as PDF">&#128438;&nbsp;Print&nbsp;/&nbsp;PDF</button>
            <span class="dark-toggle-label">Dark mode</span>
            <label class="toggle-switch" title="Toggle dark mode">
                <input type="checkbox" id="darkToggle" />
                <span class="toggle-track"></span>
            </label>
        </div>
    </header>
    <main>
        $noticesSection
        <section>
            <h2>Framework Scores</h2>
            <div class="score-grid">
                $($scoreCards.ToString())
            </div>
        </section>

        <section>
            <h2>Findings</h2>
            <div class="filters">
                <div class="search-wrapper">
                    <input type="text" class="search-box" id="searchFilter" placeholder="Search by ID, title or description" aria-label="Search findings" />
                    <button class="clear-btn" id="searchClear" aria-label="Clear search" title="Clear search" style="display:none">&#x2715;</button>
                </div>
                <select id="statusFilter">
                    <option value="All">All RAG States</option>
                    <option value="Pass">&#10004; Passed</option>
                    <option value="Fail">&#10006; Risk</option>
                    <option value="Unknown">&#9888; Warning</option>
                    <option value="Skipped">&#8856; Skipped</option>
                </select>
                <select id="frameworkFilter">
                    <option value="All">All Frameworks</option>
                    <option value="Best Practice">Best Practice</option>
                    <option value="CIS">CIS</option>
                    <option value="CISA">CISA</option>
                    <option value="ENISA">ENISA/NIS2</option>
                    <option value="DISA">DISA</option>
                </select>
                <select id="categoryFilter">
                    <option value="All">All Categories</option>
                    <option value="Compliance">Compliance</option>
                    <option value="Cryptography">Cryptography</option>
                    <option value="Email Authentication">Email Authentication</option>
                    <option value="Environment">Environment</option>
                    <option value="Governance">Governance</option>
                    <option value="Hardening">Hardening</option>
                    <option value="Identity">Identity</option>
                    <option value="Operations">Operations</option>
                    <option value="Performance">Performance</option>
                    <option value="Resilience">Resilience</option>
                    <option value="Transport">Transport</option>
                </select>
            </div>
            <div id="findingContainer">
                $($groupedFindingRows.ToString())
            </div>
        </section>
    </main>

    <!-- Modal overlay (outside <main> so it is not clipped) -->
    <div class="modal-overlay" id="findingModal" role="dialog" aria-modal="true">
        <div class="modal-box">
            <button class="modal-close" id="modalClose" aria-label="Close">&times;</button>
            <div id="modalContent"></div>
        </div>
    </div>

    <script>
        /* ── Doughnut charts (pure Canvas, no CDN) ── */
        (function () {
            var cards = document.querySelectorAll('.score-card');
            for (var ci = 0; ci < cards.length; ci++) {
                var card   = cards[ci];
                var canvas = card.querySelector('canvas.donut-canvas');
                if (!canvas) { continue; }
                var pass  = parseInt(card.getAttribute('data-pass'),  10) || 0;
                var fail  = parseInt(card.getAttribute('data-fail'),  10) || 0;
                var warn  = parseInt(card.getAttribute('data-warn'),  10) || 0;
                var skip  = parseInt(card.getAttribute('data-skip'),  10) || 0;
                var label = card.getAttribute('data-label') || '';
                var score = card.getAttribute('data-score') || '0';
                var total = pass + fail + warn + skip || 1;
                var ctx   = canvas.getContext('2d');
                var cx = 60, cy = 60, r = 52, hole = 34;
                var segments = [
                    { v: pass, c: '#16a34a' },
                    { v: warn, c: '#d97706' },
                    { v: fail, c: '#dc2626' },
                    { v: skip, c: '#94a3b8' }
                ];
                var start = -Math.PI / 2;
                for (var si = 0; si < segments.length; si++) {
                    var seg = segments[si];
                    if (seg.v <= 0) { continue; }
                    var end = start + (seg.v / total) * 2 * Math.PI;
                    ctx.beginPath();
                    ctx.moveTo(cx, cy);
                    ctx.arc(cx, cy, r, start, end);
                    ctx.closePath();
                    ctx.fillStyle = seg.c;
                    ctx.fill();
                    start = end;
                }
                /* punch hole */
                ctx.beginPath();
                ctx.arc(cx, cy, hole, 0, 2 * Math.PI);
                ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--donut-hole').trim() || '#ffffff';
                ctx.fill();
                /* score % centred in hole */
                ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--donut-text').trim() || '#0f172a';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.font = 'bold 15px Segoe UI, Arial, sans-serif';
                ctx.fillText(score + '%', cx, cy);
                /* hover tooltip */
                (function (c2, p2, w2, f2, s2, lbl2) {
                    var tip = document.createElement('div');
                    tip.style.cssText = 'display:none;position:fixed;background:#0f172a;color:#f8fafc;font-size:12px;padding:6px 10px;border-radius:8px;pointer-events:none;white-space:nowrap;z-index:9999;line-height:1.6;';
                    tip.innerHTML = '<strong>' + lbl2 + '</strong><br>&#10004;&nbsp;Pass:&nbsp;' + p2 + '<br>&#9888;&nbsp;Warn:&nbsp;' + w2 + '<br>&#10006;&nbsp;Fail:&nbsp;' + f2 + '<br>&#8856;&nbsp;Skip:&nbsp;' + s2;
                    document.body.appendChild(tip);
                    c2.parentElement.addEventListener('mouseenter', function () { tip.style.display = 'block'; });
                    c2.parentElement.addEventListener('mousemove',  function (e) {
                        tip.style.left = (e.clientX + 14) + 'px';
                        tip.style.top  = (e.clientY - 36) + 'px';
                    });
                    c2.parentElement.addEventListener('mouseleave', function () { tip.style.display = 'none'; });
                }(canvas, pass, warn, fail, skip, label));
            }
        })();

        /* ── Modal ── */
        (function () {
            var overlay  = document.getElementById('findingModal');
            var content  = document.getElementById('modalContent');
            var closeBtn = document.getElementById('modalClose');

            function openModal(modalId) {
                var dataEl = document.getElementById(modalId);
                if (!dataEl) { return; }
                content.innerHTML = dataEl.innerHTML;
                overlay.classList.add('open');
                document.body.style.overflow = 'hidden';
            }

            function closeModal() {
                overlay.classList.remove('open');
                document.body.style.overflow = '';
                content.innerHTML = '';
            }

            document.addEventListener('click', function (e) {
                var row = e.target.closest ? e.target.closest('.finding-row') : null;
                if (row) {
                    openModal(row.getAttribute('data-modal'));
                    return;
                }
                if (e.target === overlay || e.target === closeBtn) {
                    closeModal();
                }
            });

            document.addEventListener('keydown', function (e) {
                if (e.key === 'Escape') { closeModal(); }
            });
        })();

        /* ── Dark mode toggle ── */
        (function () {
            var toggle = document.getElementById('darkToggle');
            var body   = document.body;

            function applyDark(on) {
                body.classList.toggle('dark', on);
                toggle.checked = on;
                /* redraw donut holes so the colour updates immediately */
                var canvases = document.querySelectorAll('canvas.donut-canvas');
                for (var i = 0; i < canvases.length; i++) {
                    var c = canvases[i], card = c.parentElement;
                    var hole = 34, cx = 60, cy = 60;
                    c.getContext('2d').beginPath();
                    c.getContext('2d').arc(cx, cy, hole, 0, 2 * Math.PI);
                    c.getContext('2d').fillStyle = on ? '#0f172a' : '#ffffff';
                    c.getContext('2d').fill();
                    c.getContext('2d').fillStyle = on ? '#e2e8f0' : '#0f172a';
                    c.getContext('2d').textAlign = 'center';
                    c.getContext('2d').textBaseline = 'middle';
                    c.getContext('2d').font = 'bold 15px Segoe UI, Arial, sans-serif';
                    c.getContext('2d').fillText((card.getAttribute('data-score') || '0') + '%', cx, cy);
                }
            }

            /* restore saved preference */
            try { if (localStorage.getItem('edca-dark') === '1') { applyDark(true); } } catch (e) {}

            toggle.addEventListener('change', function () {
                applyDark(toggle.checked);
                try { localStorage.setItem('edca-dark', toggle.checked ? '1' : '0'); } catch (e) {}
            });
        })();

        /* ── Score card click-to-filter ── */
        (function () {
            var cards = document.querySelectorAll('.score-card');
            var frameworkFilter = document.getElementById('frameworkFilter');

            function setActiveCard(value) {
                for (var i = 0; i < cards.length; i++) {
                    cards[i].classList.toggle('active', cards[i].getAttribute('data-label') === value);
                }
            }

            for (var ci = 0; ci < cards.length; ci++) {
                (function (card) {
                    card.setAttribute('role', 'button');
                    card.setAttribute('tabindex', '0');
                    card.addEventListener('click', function () {
                        var lbl = card.getAttribute('data-label') || 'All';
                        frameworkFilter.value = lbl;
                        frameworkFilter.dispatchEvent(new Event('change'));
                    });
                    card.addEventListener('keydown', function (e) {
                        if (e.key === 'Enter' || e.key === ' ') { card.click(); e.preventDefault(); }
                    });
                }(cards[ci]));
            }

            frameworkFilter.addEventListener('change', function () {
                setActiveCard(frameworkFilter.value);
            });

            setActiveCard('All');
        })();

        /* ── Filters ── */
        (function () {
            var statusFilter    = document.getElementById('statusFilter');
            var frameworkFilter = document.getElementById('frameworkFilter');
            var categoryFilter  = document.getElementById('categoryFilter');
            var searchFilter    = document.getElementById('searchFilter');
            var groups = document.querySelectorAll('details.category-group');

            function getAggStatus(statuses) {
                var nonSkipped = statuses.filter(function(s) { return s !== 'Skipped'; });
                if (nonSkipped.length === 0) return 'Skipped';
                if (nonSkipped.indexOf('Fail') >= 0) return 'Fail';
                if (nonSkipped.indexOf('Unknown') >= 0) return 'Unknown';
                return 'Pass';
            }
            function getStatusClass(s) {
                if (s === 'Pass') return 'status-pass';
                if (s === 'Fail') return 'status-fail';
                if (s === 'Skipped') return 'status-skipped';
                return 'status-unknown';
            }
            function getRagHtml(s) {
                if (s === 'Pass')    return '<span class="rag-icon rag-pass" title="Passed">&#10004;</span>';
                if (s === 'Fail')    return '<span class="rag-icon rag-fail" title="Risk">&#10006;</span>';
                if (s === 'Skipped') return '<span class="rag-icon rag-skip" title="Not applicable">&#8856;</span>';
                return '<span class="rag-icon rag-warn" title="Warning">&#9888;</span>';
            }
            function applyFilters() {
                var searchText = searchFilter ? searchFilter.value.toLowerCase().trim() : '';
                for (var g = 0; g < groups.length; g++) {
                    var group = groups[g];
                    var groupCategory = group.getAttribute('data-category') || '';
                    var categoryMatch = categoryFilter.value === 'All' || groupCategory === categoryFilter.value;
                    var rows = group.querySelectorAll('.finding-row');
                    var visibleCount = 0;
                    var visibleStatuses = [];

                    for (var i = 0; i < rows.length; i++) {
                        var row = rows[i];
                        var statusMatch    = statusFilter.value === 'All'   || row.getAttribute('data-status') === statusFilter.value;
                        var frameworkText  = row.getAttribute('data-framework') || '';
                        var frameworkMatch = frameworkFilter.value === 'All' || frameworkText.indexOf(frameworkFilter.value) >= 0;
                        var rowId    = (row.getAttribute('data-id')    || '').toLowerCase();
                        var rowTitle = (row.getAttribute('data-title') || '').toLowerCase();
                        var rowDesc  = (row.getAttribute('data-description') || '').toLowerCase();
                        var searchMatch = searchText === '' || rowId.indexOf(searchText) >= 0 || rowTitle.indexOf(searchText) >= 0 || rowDesc.indexOf(searchText) >= 0;
                        var rowVisible = statusMatch && frameworkMatch && categoryMatch && searchMatch;
                        row.style.display = rowVisible ? '' : 'none';
                        if (rowVisible) {
                            visibleCount++;
                            visibleStatuses.push(row.getAttribute('data-status') || 'Unknown');
                        }
                    }

                    var countEl = group.querySelector('.category-count');
                    if (countEl) { countEl.textContent = '(' + visibleCount + ' controls)'; }
                    group.style.display = (categoryMatch && visibleCount > 0) ? '' : 'none';

                    if (visibleCount > 0) {
                        var aggStatus = getAggStatus(visibleStatuses);
                        var aggCss = getStatusClass(aggStatus);
                        group.className = 'category-group ' + aggCss;
                        group.setAttribute('data-group-status', aggStatus);
                        var summary = group.querySelector('summary');
                        if (summary) {
                            summary.className = aggCss;
                            var statusLabelEl = summary.querySelector('.status-label');
                            if (statusLabelEl) {
                                statusLabelEl.className = 'status-label ' + aggCss;
                                statusLabelEl.innerHTML = getRagHtml(aggStatus);
                            }
                        }
                    }
                }
            }

            statusFilter.addEventListener('change', applyFilters);
            frameworkFilter.addEventListener('change', applyFilters);
            categoryFilter.addEventListener('change', applyFilters);
            if (searchFilter) { searchFilter.addEventListener('input', applyFilters); }
            var clearBtn = document.getElementById('searchClear');
            if (searchFilter && clearBtn) {
                searchFilter.addEventListener('input', function() { clearBtn.style.display = searchFilter.value ? '' : 'none'; });
                clearBtn.addEventListener('click', function() { searchFilter.value = ''; clearBtn.style.display = 'none'; applyFilters(); searchFilter.focus(); });
            }
            applyFilters();
        })();
        /* Print: expand all findings then restore after */
        window.addEventListener('beforeprint', function () {
            var details = document.querySelectorAll('details.category-group');
            for (var i = 0; i < details.length; i++) {
                details[i].setAttribute('data-was-open', details[i].open ? '1' : '0');
                details[i].open = true;
                details[i].style.display = 'block';
            }
            var rows = document.querySelectorAll('.finding-row');
            for (var j = 0; j < rows.length; j++) {
                rows[j].setAttribute('data-print-orig', rows[j].style.display);
                rows[j].style.display = 'flex';
            }
        });
        window.addEventListener('afterprint', function () {
            var details = document.querySelectorAll('details.category-group');
            for (var i = 0; i < details.length; i++) {
                if (details[i].getAttribute('data-was-open') === '0') { details[i].open = false; }
            }
            var rows = document.querySelectorAll('.finding-row');
            for (var j = 0; j < rows.length; j++) {
                rows[j].style.display = rows[j].getAttribute('data-print-orig') || '';
            }
            var groups = document.querySelectorAll('details.category-group');
            for (var k = 0; k < groups.length; k++) {
                var visRows = groups[k].querySelectorAll('.finding-row');
                var hasVisible = false;
                for (var m = 0; m < visRows.length; m++) {
                    if (visRows[m].style.display !== 'none') { hasVisible = true; break; }
                }
                groups[k].style.display = hasVisible ? '' : 'none';
            }
        });
    </script>
</body>
</html>
"@

    Set-Content -Path $OutputFile -Value $html -Encoding UTF8
    Write-Verbose ('HTML report written to {0}' -f $OutputFile)
    return $OutputFile
}

