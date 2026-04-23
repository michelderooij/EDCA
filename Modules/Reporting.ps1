# Script:  Reporting.ps1
# Synopsis: Part of EDCA (Exchange Deployment & Compliance Assessment)
#           https://github.com/michelderooij/EDCA
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

function ConvertTo-EDCAHtmlMarkdown {
    # Renders a plain-text string with light markdown to HTML.
    # Supports: **bold**, bullet lists (lines starting with '- '), paragraph breaks (\n\n).
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return '' }
    $text = ([string]$Value) -replace "`r`n", "`n"
    $blocks = @($text -split "`n`n+" | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    $sb = [System.Text.StringBuilder]::new()
    foreach ($block in $blocks) {
        $lines = @($block -split "`n")
        $nonBullet = @($lines | Where-Object { $_ -notmatch '^\s*-\s' })
        if ($nonBullet.Count -eq 0 -and $lines.Count -gt 0) {
            $null = $sb.Append('<ul>')
            foreach ($line in $lines) {
                $item = [System.Security.SecurityElement]::Escape(($line -replace '^\s*-\s+', ''))
                $item = $item -replace '\*\*(.+?)\*\*', '<strong>$1</strong>'
                $null = $sb.Append("<li>$item</li>")
            }
            $null = $sb.Append('</ul>')
        }
        else {
            $para = [System.Security.SecurityElement]::Escape($block) -replace "`n", '<br />'
            $para = $para -replace '\*\*(.+?)\*\*', '<strong>$1</strong>'
            $null = $sb.Append("<p>$para</p>")
        }
    }
    return $sb.ToString()
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
        [string]$OutputFile,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [pscustomobject[]]$HistoryData = @()
    )

    Write-Verbose ('Generating HTML report for {0} findings and {1} server entries.' -f @($AnalysisData.Findings).Count, @($CollectionData.Servers).Count)

    # Build a map of server name -> role for role badge display in evidence tables.
    $serverRoleMap = @{}
    foreach ($srv in @($CollectionData.Servers)) {
        $srvName = if ($srv.PSObject.Properties.Name -contains 'Name') { [string]$srv.Name } else { '' }
        if ([string]::IsNullOrEmpty($srvName)) { continue }
        if (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and
            ($srv.Exchange.PSObject.Properties.Name -contains 'IsEdge') -and [bool]$srv.Exchange.IsEdge) {
            $serverRoleMap[$srvName] = 'Edge'
        }
        else {
            $serverRoleMap[$srvName] = 'Mailbox'
        }
    }

    # Build framework filter dropdown options from scores actually present in this report.
    $frameworkLabelMap = @{}
    $frameworkOptions = New-Object System.Text.StringBuilder
    foreach ($score in $AnalysisData.Scores) {
        if ($score.Framework -eq 'All') { continue }
        $label = if ($frameworkLabelMap.ContainsKey($score.Framework)) { $frameworkLabelMap[$score.Framework] } else { $score.Framework }
        $null = $frameworkOptions.AppendLine(('                    <option value="{0}">{1}</option>' -f $score.Framework, $label))
    }

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

    # Build compliance trend chart data from history analysis files.
    # Each entry embeds scores for every framework keyed by framework name,
    # so the chart JS can slice to the active filter without a round-trip.
    $trendCardHtml = ''
    if ($null -ne $HistoryData -and @($HistoryData).Count -gt 0) {
        $trendPoints = @(foreach ($entry in @($HistoryData)) {
                $hasAll = $entry.Scores | Where-Object { $_.Framework -eq 'All' }
                if (-not $hasAll) { continue }
                $dateLabel = ''
                try {
                    $rawTs = [string]$entry.Metadata.AnalysisTimestamp
                    # Handle PS5.1 /Date(ms)/ serialization as well as ISO 8601 strings
                    if ($rawTs -match '^/Date\((-?\d+)\)/$') {
                        $ts = [datetime]::new(621355968000000000, [System.DateTimeKind]::Utc).AddMilliseconds([long]$Matches[1]).ToLocalTime()
                    }
                    else {
                        $ts = [datetime]::Parse($rawTs)
                    }
                    $dateLabel = $ts.ToString('d MMM yyyy')
                }
                catch { $dateLabel = '' }
                $parts = '"d":"' + $dateLabel + '"'
                foreach ($sc in @($entry.Scores)) {
                    $fk = [string]$sc.Framework
                    $tFail = [int]$sc.FailedControls
                    $tWarn = [int]$sc.UnknownControls
                    $tSkip = [int]$sc.SkippedControls
                    $tTotal = [int]$sc.TotalControls
                    $tPass = [math]::Max(0, $tTotal - $tFail - $tWarn - $tSkip)
                    $parts += ',"' + $fk + '":{"p":' + $tPass + ',"w":' + $tWarn + ',"f":' + $tFail + ',"s":' + $tSkip + '}'
                }
                '{' + $parts + '}'
            })
        $trendJson = ('[' + ($trendPoints -join ',') + ']') -replace '"', '&quot;'
        if ($trendPoints.Count -ge 2) {
            $trendCardHtml = ('<div class="score-card trend-card" data-trend="{0}"><canvas class="trend-canvas" width="288" height="160"></canvas><p class="card-label">Total Compliance Trend</p></div>' -f $trendJson)
        }
    }

    $findingGroups = @{}
    foreach ($finding in @($AnalysisData.Findings | Sort-Object { [string]$_.Category }, { [string]$_.ControlId })) {
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
                $remediationParts += ('<div class="pre-wrapper"><button class="copy-btn" title="Copy to clipboard" aria-label="Copy script to clipboard">Copy</button><pre><code>{0}</code></pre></div>' -f $remediationScript)
            }
            if ($remediationParts.Count -gt 0) {
                $remediationHtml = $remediationParts -join ''
            }
        }

        $considerationsHtml = ''
        if (($finding.PSObject.Properties.Name -contains 'Considerations') -and -not [string]::IsNullOrWhiteSpace([string]$finding.Considerations)) {
            $considerationsHtml = ConvertTo-EDCAHtmlMarkdown -Value $finding.Considerations
        }

        $serverLines = @()
        $subjectLabel = if (($finding.PSObject.Properties.Name -contains 'SubjectLabel') -and -not [string]::IsNullOrWhiteSpace([string]$finding.SubjectLabel)) { [string]$finding.SubjectLabel } else { 'Server' }
        foreach ($serverResult in $finding.ServerResults) {
            if ($serverResult.Status -eq 'Skipped') { continue }
            $serverRagLabel = Get-EDCARagLabel -Status $serverResult.Status
            $srvName = [string]$serverResult.Server
            $srvRoleBadge = if ($serverRoleMap.ContainsKey($srvName) -and $serverRoleMap[$srvName] -eq 'Edge') { ' <span class="role-badge role-edge" title="Edge Transport server">Edge</span>' } else { '' }
            $serverLines += ('<tr class="{1}"><td>{0}{4}</td><td>{2}</td><td class="evidence-cell">{3}</td></tr>' -f
                (ConvertTo-EDCAHtmlEncoded -Value $srvName),
                (Get-EDCAStatusClass -Status $serverResult.Status),
                $serverRagLabel,
                (ConvertTo-EDCAHtmlWithLineBreaks -Value $serverResult.Evidence),
                $srvRoleBadge
            )
        }

        # Derive filter data attributes for subject and role targeting
        $findingSubject = if ($finding.PSObject.Properties.Name -contains 'Subject') { [string]$finding.Subject } else { '' }
        $findingRoles = if ($finding.PSObject.Properties.Name -contains 'Roles') { @($finding.Roles | ForEach-Object { [string]$_ }) } else { @() }
        $rolesValue = ($findingRoles -join ',')
        $targetValue = if ($findingSubject -eq 'Database') { 'Database' }
        elseif ($findingSubject -eq 'Mailbox') { 'Mailbox' }
        elseif ($subjectLabel -eq 'Domain') { 'Domain' }
        elseif ($subjectLabel -eq 'Organization' -or $findingSubject -eq 'Organization') { 'Organization' }
        else { 'Server' }

        $overallCss = Get-EDCAStatusClass -Status $finding.OverallStatus
        $overallRagLabel = Get-EDCARagLabel -Status $finding.OverallStatus
        $findingModalId = 'modal-' + ($finding.ControlId -replace '[^a-zA-Z0-9]', '-')
        $descriptionHtml = ConvertTo-EDCAHtmlMarkdown -Value $finding.Description
        $findingHtml = (
            ('<div class="finding-row {0}" data-status="{1}" data-category="{2}" data-framework="{3}" data-modal="{4}" data-id="{6}" data-title="{7}" data-description="{10}" data-subject="{17}" data-roles="{18}">' +
            '{5}<span class="finding-id">{6}</span> <span class="finding-title">{7}</span>' +
            '</div>' +
            '<div class="modal-data" id="{4}" hidden>' +
            '<h2>{6}: {7}</h2>' +
            '<p class="modal-meta"><strong>Category:</strong> {8} | <strong>Severity:</strong> {9} | <strong>Frameworks:</strong> {3}</p>' +
            '<div class="finding-description">{16}</div>' +
            '<div class="evidence-section"><h3>Evidence</h3>' +
            '<table class="evidence-table"><thead><tr><th>{15}</th><th>Status</th><th>Evidence</th></tr></thead><tbody>{11}</tbody></table></div>' +
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
            $subjectLabel,
            $descriptionHtml,
            $targetValue,
            $rolesValue
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
        $groupCount = @($group.Statuses | Where-Object { $_ -ne 'Skipped' }).Count
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
    $reportGeneratedAt = Get-Date -Format 'o'

    # Build environment notices (Edge servers, unsupported Exchange versions)
    $noticesHtml = New-Object System.Text.StringBuilder
    # Determine which Edge servers were collected vs. only detected in the org topology.
    $collectedEdgeServers = @($CollectionData.Servers | Where-Object {
            ($_.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $_.Exchange -and
            ($_.Exchange.PSObject.Properties.Name -contains 'IsEdge') -and [bool]$_.Exchange.IsEdge
        })
    $orgEdgeServers = @()
    if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
        ($CollectionData.Organization.PSObject.Properties.Name -contains 'EdgeServers')) {
        $orgEdgeServers = @($CollectionData.Organization.EdgeServers)
    }
    $collectedEdgeNames = @($collectedEdgeServers | ForEach-Object {
            if (($_.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $_.Exchange -and ($_.Exchange.PSObject.Properties.Name -contains 'Name')) { [string]$_.Exchange.Name }
            elseif ($_.PSObject.Properties.Name -contains 'Server') { [string]$_.Server }
            else { '' }
        })
    $uncollectedEdgeServers = @($orgEdgeServers | Where-Object { $n = if ($_.PSObject.Properties.Name -contains 'Name') { [string]$_.Name } else { '' }; $collectedEdgeNames -notcontains $n })
    if ($collectedEdgeServers.Count -gt 0) {
        $edgeNamesHtml = ($collectedEdgeServers | ForEach-Object {
                $n = if (($_.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $_.Exchange -and ($_.Exchange.PSObject.Properties.Name -contains 'Name')) { [string]$_.Exchange.Name }
                elseif ($_.PSObject.Properties.Name -contains 'Server') { [string]$_.Server }
                else { '' }
                ConvertTo-EDCAHtmlEncoded -Value $n
            }) -join ', '
        $null = $noticesHtml.AppendLine('<div class="env-notice env-notice-info"><span class="env-notice-icon">&#10003;</span><div><strong>Edge Transport servers collected and assessed</strong>' + $collectedEdgeServers.Count + ' Edge Transport server(s) were collected and assessed with role-specific controls: ' + $edgeNamesHtml + '.</div></div>')
    }
    if ($uncollectedEdgeServers.Count -gt 0) {
        $edgeNames = ($uncollectedEdgeServers | ForEach-Object { ConvertTo-EDCAHtmlEncoded -Value $(if ($_.PSObject.Properties.Name -contains 'Name') { $_.Name } else { '' }) }) -join ', '
        $null = $noticesHtml.AppendLine('<div class="env-notice"><span class="env-notice-icon">&#9888;</span><div><strong>Edge Transport servers not collected</strong>The following Edge Transport server(s) were detected in the Exchange organisation but not collected. Re-run EDCA specifying these servers to assess Edge-specific controls: ' + $edgeNames + '.</div></div>')
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
        /* Trend chart card — same width as 2 gauge cards (2×152px + 16px gap) */
        .trend-card { width: 320px; min-width: 320px; cursor: default; }
        .trend-card:hover { transform: none; box-shadow: 0 4px 14px rgba(0,0,0,.08); }
        .trend-canvas { display: block; }
        /* RAG icons */
        .rag-icon { font-size: 15px; flex-shrink: 0; }
        .rag-pass { color: #16a34a; }
        .rag-warn { color: #d97706; }
        .rag-fail { color: #dc2626; }
        .rag-skip { color: #94a3b8; }
        /* Role badges */
        .role-badge { display: inline-block; font-size: 10px; font-weight: 700; padding: 1px 6px; border-radius: 4px; vertical-align: middle; margin-left: 5px; letter-spacing: .04em; text-transform: uppercase; line-height: 16px; }
        .role-edge { background: #dbeafe; color: #1d4ed8; }
        body.dark .role-edge { background: #1e3a5f; color: #93c5fd; }
        /* Info env-notice variant (Edge collected) */
        .env-notice-info { border-left-color: #2563eb; background: #eff6ff; color: #1e40af; }
        body.dark .env-notice-info { background: #1e3a5f; color: #93c5fd; border-left-color: #3b82f6; }
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
        .pre-wrapper { position: relative; }
        .copy-btn { position: absolute; top: 16px; right: 8px; padding: 3px 10px; font-size: 11px; font-family: inherit; background: var(--th-bg); border: 1px solid var(--pre-border); border-radius: 4px; cursor: pointer; color: var(--fg); opacity: 0.7; transition: opacity 0.15s; }
        .copy-btn:hover { opacity: 1; }
        .copy-btn.copied { color: #16a34a; border-color: #16a34a; opacity: 1; }
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
            .modal-data { display: block !important; margin: 2px 0 6px 0; border-left: 3px solid #cbd5e1; padding-left: 10px; }
            .modal-data > * { display: none !important; }
            .modal-data > .evidence-section { display: block !important; }
            .evidence-section h3 { display: block !important; font-size: 12px; margin: 2px 0 4px; border-top: none; padding-top: 0; color: #334155; }
            .evidence-table { font-size: 11px; width: 100%; border-collapse: collapse; }
            .evidence-table th, .evidence-table td { padding: 4px 6px; border-bottom: 1px solid #e2e8f0; }
            td.evidence-cell { white-space: pre-wrap; word-break: break-word; font-family: Consolas, 'Courier New', monospace; }
        }
    </style>
</head>
<body>
    <header>
        <div>
            <h1>EDCA: Exchange Deployment &amp; Compliance Assessment $($metadata.ToolVersion)</h1>
            <p>Data collected: $($metadata.CollectionTimestamp) | Report generated: $reportGeneratedAt | Executed by: $($metadata.ExecutedBy)</p>
        </div>
        <div class="dark-toggle no-print">
            <button class="print-btn" onclick="window.print()" title="Print or save as PDF">&#128438;&nbsp;Print&nbsp;/&nbsp;PDF</button>
            <span class="dark-toggle-label">Show skipped</span>
            <label class="toggle-switch" title="Toggle show skipped controls">
                <input type="checkbox" id="skipToggle" checked />
                <span class="toggle-track"></span>
            </label>
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
            <h2>Framework Scoreboard</h2>
            <div class="score-grid">
                $($scoreCards.ToString())
                $trendCardHtml
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
                    $($frameworkOptions.ToString())
                </select>
                <select id="categoryFilter">
                    <option value="All">All Categories</option>
                    <option value="Data Security">Data Security</option>
                    <option value="Governance">Governance</option>
                    <option value="Identity and Access Control">Identity and Access Control</option>
                    <option value="Monitoring">Monitoring</option>
                    <option value="Performance">Performance</option>
                    <option value="Platform Security">Platform Security</option>
                    <option value="Resilience">Resilience</option>
                    <option value="Transport Security">Transport Security</option>
                </select>
                <select id="targetFilter">
                    <option value="all">All Targets</option>
                    <option value="org">Organisation</option>
                    <option value="domain">Domain Name</option>
                    <option value="mailbox">Mailbox Server</option>
                    $(if ($collectedEdgeServers.Count -gt 0) { '<option value="edge">Edge Transport Server</option>' })
                    <option value="database">Database</option>
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

        /* ── Compliance Trend stacked bar chart ── */
        (function () {
            var trendCard = document.querySelector('.trend-card');
            if (!trendCard) { return; }
            var canvas  = trendCard.querySelector('canvas.trend-canvas');
            var labelEl = trendCard.querySelector('.card-label');
            if (!canvas) { return; }
            var raw = (trendCard.getAttribute('data-trend') || '[]').replace(/&quot;/g, '"');
            var entries;
            try { entries = JSON.parse(raw); } catch (e) { return; }
            if (!entries || entries.length === 0) { return; }

            var W = canvas.width, H = canvas.height;
            var padL = 32, padR = 8, padT = 10, padB = 30;
            var chartW = W - padL - padR;
            var chartH = H - padT - padB;
            var ctx    = canvas.getContext('2d');
            var colors = { p: '#16a34a', w: '#d97706', f: '#dc2626', s: '#94a3b8' };
            var order  = ['s', 'f', 'w', 'p'];
            var currentEntries = [];
            var n = 0, slotW = 0;

            /* hover tooltip */
            var tip = document.createElement('div');
            tip.style.cssText = 'display:none;position:fixed;background:#0f172a;color:#f8fafc;font-size:12px;padding:6px 10px;border-radius:8px;pointer-events:none;white-space:nowrap;z-index:9999;line-height:1.6;';
            document.body.appendChild(tip);

            function drawChart(fw) {
                var key = (fw && fw !== 'All') ? fw : 'All';
                /* update card label to reflect active filter */
                if (labelEl) {
                    var fwSel = document.getElementById('frameworkFilter');
                    var lbl;
                    if (!fw || fw === 'All') {
                        lbl = 'Total';
                    } else {
                        lbl = (fwSel && fwSel.selectedIndex >= 0) ? fwSel.options[fwSel.selectedIndex].text : fw;
                    }
                    labelEl.textContent = lbl + ' Compliance Trend';
                }
                /* build currentEntries for the selected framework; fall back to All */
                currentEntries = [];
                for (var i = 0; i < entries.length; i++) {
                    var e  = entries[i];
                    var sc = e[key] || e['All'];
                    if (!sc) { continue; }
                    currentEntries.push({ d: e.d, p: sc.p || 0, w: sc.w || 0, f: sc.f || 0, s: sc.s || 0 });
                }
                n = currentEntries.length;
                if (n === 0) { ctx.clearRect(0, 0, W, H); return; }
                slotW = chartW / n;
                /* derive Y max */
                var maxTotal = 0;
                for (var j = 0; j < n; j++) {
                    var ce = currentEntries[j];
                    var t  = (ce.p || 0) + (ce.w || 0) + (ce.f || 0) + (ce.s || 0);
                    if (t > maxTotal) { maxTotal = t; }
                }
                var yMax = Math.ceil(maxTotal / 10) * 10 || 10;
                var textColor = getComputedStyle(document.documentElement).getPropertyValue('--donut-text').trim() || '#64748b';
                ctx.clearRect(0, 0, W, H);
                ctx.font = '10px Segoe UI, Arial, sans-serif';
                /* Y-axis grid lines + labels */
                var steps = 4;
                for (var s = 0; s <= steps; s++) {
                    var yVal = Math.round(yMax * s / steps);
                    var yPx  = padT + chartH - Math.round((yVal / yMax) * chartH);
                    ctx.beginPath();
                    ctx.moveTo(padL, yPx);
                    ctx.lineTo(padL + chartW, yPx);
                    ctx.strokeStyle = 'rgba(148,163,184,.25)';
                    ctx.stroke();
                    ctx.fillStyle = textColor;
                    ctx.textAlign = 'right';
                    ctx.textBaseline = 'middle';
                    ctx.fillText(yVal, padL - 4, yPx);
                }
                /* bars */
                var barW = Math.min(Math.floor(slotW) - 4, 40);
                for (var bi = 0; bi < n; bi++) {
                    var ce2   = currentEntries[bi];
                    var xL    = padL + Math.round(bi * slotW + (slotW - barW) / 2);
                    var yBase = padT + chartH;
                    var stack = 0;
                    for (var oi = 0; oi < order.length; oi++) {
                        var ok   = order[oi];
                        var val  = ce2[ok] || 0;
                        if (val <= 0) { continue; }
                        var barH = Math.round((val / yMax) * chartH);
                        ctx.fillStyle = colors[ok];
                        ctx.fillRect(xL, yBase - stack - barH, barW, barH);
                        stack += barH;
                    }
                    /* x-axis date label — omitted */
                }
            }

            var fwFilter = document.getElementById('frameworkFilter');
            drawChart(fwFilter ? fwFilter.value : 'All');
            if (fwFilter) {
                fwFilter.addEventListener('change', function () { drawChart(fwFilter.value); });
            }

            /* mouse hover interaction */
            canvas.addEventListener('mousemove', function (ev) {
                if (n === 0) { return; }
                var rect = canvas.getBoundingClientRect();
                var mx   = ev.clientX - rect.left;
                var idx  = Math.floor((mx - padL) / slotW);
                if (idx < 0 || idx >= n) { tip.style.display = 'none'; return; }
                var ce = currentEntries[idx];
                tip.innerHTML = '<strong>' + (ce.d || '') + '</strong><br>' +
                    '&#10004;&nbsp;Pass:&nbsp;' + (ce.p || 0) + '<br>' +
                    '&#9888;&nbsp;Unknown:&nbsp;' + (ce.w || 0) + '<br>' +
                    '&#10006;&nbsp;Fail:&nbsp;' + (ce.f || 0) + '<br>' +
                    '&#8856;&nbsp;Skip:&nbsp;' + (ce.s || 0);
                tip.style.display = 'block';
                tip.style.left = (ev.clientX + 14) + 'px';
                tip.style.top  = (ev.clientY - 36) + 'px';
            });
            canvas.addEventListener('mouseleave', function () { tip.style.display = 'none'; });
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

            /* restore saved preference, or follow system colour-scheme preference */
            try {
                var saved = localStorage.getItem('edca-dark');
                if (saved !== null) {
                    applyDark(saved === '1');
                } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
                    applyDark(true);
                }
            } catch (e) {}

            /* keep in sync when the OS preference changes and no explicit override is stored */
            try {
                window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function (e) {
                    try { if (localStorage.getItem('edca-dark') === null) { applyDark(e.matches); } } catch (ex) {}
                });
            } catch (e) {}

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
            var targetFilter    = document.getElementById('targetFilter');
            var searchFilter    = document.getElementById('searchFilter');
            var skipToggle      = document.getElementById('skipToggle');
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
                var hideSkipped = skipToggle ? !skipToggle.checked : false;
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
                        var rowStatus = row.getAttribute('data-status') || '';
                        if (hideSkipped && rowStatus === 'Skipped') {
                            row.style.display = 'none';
                            continue;
                        }
                        var statusMatch    = statusFilter.value === 'All'   || rowStatus === statusFilter.value;
                        var frameworkText  = row.getAttribute('data-framework') || '';
                        var frameworkMatch = frameworkFilter.value === 'All' || frameworkText.indexOf(frameworkFilter.value) >= 0;
                        var rowId    = (row.getAttribute('data-id')    || '').toLowerCase();
                        var rowTitle = (row.getAttribute('data-title') || '').toLowerCase();
                        var rowDesc  = (row.getAttribute('data-description') || '').toLowerCase();
                        var searchMatch = searchText === '' || rowId.indexOf(searchText) >= 0 || rowTitle.indexOf(searchText) >= 0 || rowDesc.indexOf(searchText) >= 0;
                        var rowSubject = row.getAttribute('data-subject') || '';
                        var rowRoles   = row.getAttribute('data-roles')   || '';
                        var tVal = targetFilter ? targetFilter.value : 'all';
                        var targetMatch = tVal === 'all' ||
                            (tVal === 'org'      && rowSubject === 'Organization') ||
                            (tVal === 'domain'   && rowSubject === 'Domain') ||
                            (tVal === 'mailbox'  && rowRoles.indexOf('Mailbox') >= 0) ||
                            (tVal === 'edge'     && rowRoles.indexOf('Edge') >= 0) ||
                            (tVal === 'database' && rowSubject === 'Database');
                        var rowVisible = statusMatch && frameworkMatch && categoryMatch && searchMatch && targetMatch;
                        row.style.display = rowVisible ? '' : 'none';
                        if (rowVisible) {
                            visibleCount++;
                            visibleStatuses.push(rowStatus || 'Unknown');
                        }
                    }

                    var countEl = group.querySelector('.category-count');
                    var nonSkippedCount = visibleStatuses.filter(function(s) { return s !== 'Skipped'; }).length;
                    if (countEl) { countEl.textContent = '(' + nonSkippedCount + ' controls)'; }
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
            if (targetFilter) { targetFilter.addEventListener('change', applyFilters); }
            if (searchFilter) { searchFilter.addEventListener('input', applyFilters); }
            if (skipToggle) {
                try {
                    var savedSkip = localStorage.getItem('edca-show-skipped');
                    if (savedSkip === '0') { skipToggle.checked = false; }
                } catch (e) {}
                skipToggle.addEventListener('change', function () {
                    try { localStorage.setItem('edca-show-skipped', skipToggle.checked ? '1' : '0'); } catch (e) {}
                    applyFilters();
                });
            }
            var clearBtn = document.getElementById('searchClear');
            if (searchFilter && clearBtn) {
                searchFilter.addEventListener('input', function() { clearBtn.style.display = searchFilter.value ? '' : 'none'; });
                clearBtn.addEventListener('click', function() { searchFilter.value = ''; clearBtn.style.display = 'none'; applyFilters(); searchFilter.focus(); });
            }
            applyFilters();
        })();
        /* Print: expand visible findings respecting active filters, then restore after */
        window.addEventListener('beforeprint', function () {
            var details = document.querySelectorAll('details.category-group');
            for (var i = 0; i < details.length; i++) {
                details[i].setAttribute('data-was-open', details[i].open ? '1' : '0');
                if (details[i].style.display !== 'none') {
                    details[i].open = true;
                }
            }
            var rows = document.querySelectorAll('.finding-row');
            for (var j = 0; j < rows.length; j++) {
                rows[j].setAttribute('data-print-orig', rows[j].style.display);
                if (rows[j].style.display !== 'none') {
                    rows[j].style.display = 'flex';
                    var modalId = rows[j].getAttribute('data-modal');
                    if (modalId) {
                        var modalEl = document.getElementById(modalId);
                        if (modalEl) { modalEl.removeAttribute('hidden'); }
                    }
                }
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
            var modals = document.querySelectorAll('.modal-data');
            for (var k = 0; k < modals.length; k++) { modals[k].setAttribute('hidden', ''); }
            var groups = document.querySelectorAll('details.category-group');
            for (var m = 0; m < groups.length; m++) {
                var visRows = groups[m].querySelectorAll('.finding-row');
                var hasVisible = false;
                for (var n = 0; n < visRows.length; n++) {
                    if (visRows[n].style.display !== 'none') { hasVisible = true; break; }
                }
                groups[m].style.display = hasVisible ? '' : 'none';
            }
        });
        /* ── Copy-to-clipboard for remediation script blocks ── */
        document.addEventListener('click', function (e) {
            var btn = e.target.closest ? e.target.closest('.copy-btn') : (e.target.className === 'copy-btn' ? e.target : null);
            if (!btn) { return; }
            var code = btn.parentElement.querySelector('code');
            if (!code) { return; }
            var text = code.innerText || code.textContent || '';
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(function () {
                    btn.textContent = 'Copied!';
                    btn.classList.add('copied');
                    setTimeout(function () { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
                }, function () {
                    btn.textContent = 'Failed';
                    setTimeout(function () { btn.textContent = 'Copy'; }, 2000);
                });
            } else {
                try {
                    var ta = document.createElement('textarea');
                    ta.value = text;
                    ta.style.position = 'fixed'; ta.style.opacity = '0';
                    document.body.appendChild(ta);
                    ta.focus(); ta.select();
                    document.execCommand('copy');
                    document.body.removeChild(ta);
                    btn.textContent = 'Copied!';
                    btn.classList.add('copied');
                    setTimeout(function () { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 2000);
                } catch (ex) {
                    btn.textContent = 'Failed';
                    setTimeout(function () { btn.textContent = 'Copy'; }, 2000);
                }
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

