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

    if ($normalized -contains 'Fail') {
        return 'Fail'
    }

    if ($normalized -contains 'Unknown') {
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
        $totalCount = [int]$score.TotalControls
        $passCount = [math]::Max(0, $totalCount - $failCount - $unknownCount)
        $displayLabel = if ($score.Framework -eq 'All') { 'Total' } else { $score.Framework }

        $null = $scoreCards.AppendLine((
                ('<div class="score-card" data-pass="{0}" data-fail="{1}" data-warn="{2}" data-label="{3}" data-score="{4}">' +
                '<canvas class="donut-canvas" width="120" height="120"></canvas>' +
                '<p class="card-label">{5}</p>' +
                '</div>') -f
                $passCount, $failCount, $unknownCount,
                $score.Framework,
                $score.Score,
                $displayLabel
            ))
    }

    $findingGroups = @{}
    foreach ($finding in $AnalysisData.Findings) {
        $frameworkText = ($finding.Frameworks -join ', ')
        $refs = @()
        foreach ($reference in $finding.References) {
            $refs += ('<li><a href="{0}" target="_blank" rel="noopener noreferrer">{1}</a></li>' -f $reference.url, $reference.name)
        }
        $referencesHtml = if ($refs.Count -gt 0) { '<ul>' + ($refs -join '') + '</ul>' } else { '<p>No references.</p>' }

        $remediationHtml = '<p>No remediation command available.</p>'
        if (($finding.PSObject.Properties.Name -contains 'Remediation') -and $null -ne $finding.Remediation) {
            $remediationDescription = ''
            if (($finding.Remediation.PSObject.Properties.Name -contains 'description') -and -not [string]::IsNullOrWhiteSpace([string]$finding.Remediation.description)) {
                $remediationDescription = (ConvertTo-EDCAHtmlEncoded -Value $finding.Remediation.description)
            }

            if (-not [string]::IsNullOrWhiteSpace($remediationDescription)) {
                $remediationHtml = ('<p>{0}</p>' -f $remediationDescription)
            }
        }

        $considerationsHtml = ''
        if (($finding.PSObject.Properties.Name -contains 'Considerations') -and -not [string]::IsNullOrWhiteSpace([string]$finding.Considerations)) {
            $considerationsHtml = ('<p>{0}</p>' -f (ConvertTo-EDCAHtmlEncoded -Value $finding.Considerations))
        }

        $serverLines = @()
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
            ('<div class="finding-row {0}" data-status="{1}" data-category="{2}" data-framework="{3}" data-modal="{4}">' +
            '{5}<span class="finding-id">{6}</span> <span class="finding-title">{7}</span>' +
            '</div>' +
            '<div class="modal-data" id="{4}" hidden>' +
            '<h2>{6}: {7}</h2>' +
            '<p class="modal-meta"><strong>Category:</strong> {8} | <strong>Severity:</strong> {9} | <strong>Frameworks:</strong> {3}</p>' +
            '<p class="finding-description">{10}</p>' +
            '<h3>Evidence</h3>' +
            '<table class="evidence-table"><thead><tr><th>Server</th><th>Status</th><th>Evidence</th></tr></thead><tbody>{11}</tbody></table>' +
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
            $considerationsHtml
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

    $serverInventoryRows = New-Object System.Text.StringBuilder
    foreach ($server in $CollectionData.Servers) {
        $serverShortName = ([string]$server.Server -split '\.')[0]
        if ($server.PSObject.Properties.Name -contains 'CollectionError') {
            $null = $serverInventoryRows.AppendLine((
                    '<tr><td>{0}</td><td colspan="5" class="status-fail">Collection failed: {1}</td></tr>' -f
                    $serverShortName,
                    (ConvertTo-EDCAHtmlEncoded -Value $server.CollectionError)
                ))
            continue
        }

        $productLine = 'Unknown'
        if ($server.PSObject.Properties.Name -contains 'Exchange' -and $server.Exchange.PSObject.Properties.Name -contains 'ProductLine') {
            $productLine = [string]$server.Exchange.ProductLine
        }

        $null = $serverInventoryRows.AppendLine((
                '<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td><td>{6}</td></tr>' -f
                $serverShortName,
                (ConvertTo-EDCAHtmlEncoded -Value $server.OS.OSCaption),
                (ConvertTo-EDCAHtmlEncoded -Value $productLine),
                (ConvertTo-EDCAHtmlEncoded -Value $server.Exchange.AdminDisplayVersion),
                (ConvertTo-EDCAHtmlEncoded -Value $server.Exchange.Edition),
                (ConvertTo-EDCAHtmlEncoded -Value $server.OS.ExecutionPolicy),
                (ConvertTo-EDCAHtmlEncoded -Value $server.OS.TotalPhysicalMemoryGB)
            ))
    }

    $edgeServerSection = ''
    $edgeServers = @()
    if ($CollectionData.PSObject.Properties.Name -contains 'Organization' -and
        $null -ne $CollectionData.Organization -and
        $CollectionData.Organization.PSObject.Properties.Name -contains 'EdgeServers') {
        $edgeServers = @($CollectionData.Organization.EdgeServers)
    }
    if ($edgeServers.Count -gt 0) {
        $edgeRows = New-Object System.Text.StringBuilder
        foreach ($es in $edgeServers) {
            $null = $edgeRows.AppendLine((
                    '<tr><td>{0}</td><td>{1}</td><td>{2}</td></tr>' -f
                    (ConvertTo-EDCAHtmlEncoded -Value ([string]$es.Name)),
                    (ConvertTo-EDCAHtmlEncoded -Value ([string]$es.AdminDisplayVersion)),
                    (ConvertTo-EDCAHtmlEncoded -Value ([string]$es.Edition))
                ))
        }
        $edgeServerSection = @"
        <section>
            <h2>Edge Transport Servers (not assessed)</h2>
            <div class="card">
                <p>The following Edge Transport server(s) were discovered but are <strong>not included</strong> in the security assessment.
                Edge servers operate in the perimeter network and require a separate review.</p>
                <table>
                    <thead>
                        <tr><th>Server</th><th>Exchange Build</th><th>Edition</th></tr>
                    </thead>
                    <tbody>
                        $($edgeRows.ToString())
                    </tbody>
                </table>
            </div>
        </section>
"@
    }

    $metadata = $CollectionData.Metadata
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8" />
    <title>EDCA: Exchange Deployment &amp; Compliance Assessment v0.1 Preview</title>
    <style>
        *, *::before, *::after { box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; margin: 0; background: #f2f6fc; color: #1f2937; }
        header { padding: 24px 32px; background: #0f172a; color: #f8fafc; }
        header h1 { margin: 0 0 6px; font-size: 22px; }
        header p { margin: 0; font-size: 13px; opacity: .8; }
        main { padding: 24px; max-width: 1400px; margin: 0 auto; }
        h2 { color: #0f172a; margin-top: 28px; margin-bottom: 12px; }
        /* Score cards / doughnuts */
        .score-grid { display: flex; flex-wrap: wrap; gap: 16px; }
        .score-card { background: #fff; border-radius: 12px; box-shadow: 0 4px 14px rgba(0,0,0,.08); padding: 14px 16px; display: flex; flex-direction: column; align-items: center; min-width: 140px; cursor: pointer; transition: transform .15s, box-shadow .15s; user-select: none; }
        .score-card:hover { transform: translateY(-2px); box-shadow: 0 6px 18px rgba(0,0,0,.14); }
        .score-card.active { outline: 2px solid #3b82f6; box-shadow: 0 4px 14px rgba(59,130,246,.35); }
        .donut-canvas { display: block; }
        .card-label { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .04em; margin: 6px 0 0; color: #334155; text-align: center; }
        /* RAG icons */
        .rag-icon { font-size: 15px; flex-shrink: 0; }
        .rag-pass { color: #16a34a; }
        .rag-warn { color: #d97706; }
        .rag-fail { color: #dc2626; }
        /* Filters */
        .filters { display: flex; gap: 12px; flex-wrap: wrap; margin: 12px 0 16px; }
        select { padding: 8px 12px; border-radius: 8px; border: 1px solid #cbd5e1; background: #fff; font-size: 14px; cursor: pointer; }
        select:focus { outline: 2px solid #3b82f6; }
        /* Category groups */
        details.category-group { background: #fff; border: 1px solid #cbd5e1; border-radius: 12px; margin-bottom: 12px; overflow: hidden; }
        details.category-group > summary { cursor: pointer; list-style: none; padding: 12px 16px; display: flex; gap: 10px; align-items: center; font-weight: 700; user-select: none; }
        details.category-group > summary::-webkit-details-marker { display: none; }
        details.category-group.status-pass > summary { background: #dcfce7; color: #166534; }
        details.category-group.status-fail > summary { background: #fee2e2; color: #991b1b; }
        details.category-group.status-unknown > summary { background: #fef3c7; color: #92400e; }
        .category-count { opacity: .75; font-size: 13px; font-weight: 500; }
        .category-group-body { padding: 10px 12px 12px; }
        /* Finding rows */
        .finding-row { display: flex; align-items: center; gap: 10px; padding: 10px 12px; border: 1px solid #e2e8f0; border-radius: 8px; margin-bottom: 7px; cursor: pointer; transition: box-shadow .15s, transform .1s; }
        .finding-row:hover { box-shadow: 0 3px 10px rgba(0,0,0,.12); transform: translateY(-1px); }
        .finding-row.status-pass  { border-left: 4px solid #16a34a; background: #f0fdf4; }
        .finding-row.status-fail  { border-left: 4px solid #dc2626; background: #fef2f2; }
        .finding-row.status-unknown { border-left: 4px solid #d97706; background: #fffbeb; }
        .finding-id { font-family: Consolas, 'Courier New', monospace; font-weight: 600; color: #334155; font-size: 13px; white-space: nowrap; }
        .finding-title { flex: 1; font-size: 14px; }
        /* Modal */
        .modal-overlay { display: none; position: fixed; inset: 0; background: rgba(0,0,0,.5); z-index: 1000; align-items: center; justify-content: center; }
        .modal-overlay.open { display: flex; }
        .modal-box { background: #fff; border-radius: 16px; max-width: 940px; width: 92vw; max-height: 87vh; overflow-y: auto; padding: 28px 32px; position: relative; box-shadow: 0 20px 60px rgba(0,0,0,.3); }
        .modal-close { position: absolute; top: 14px; right: 18px; background: none; border: none; font-size: 24px; cursor: pointer; color: #64748b; line-height: 1; padding: 4px 8px; border-radius: 6px; }
        .modal-close:hover { background: #f1f5f9; color: #1f2937; }
        .modal-meta { color: #475569; font-size: 13px; margin-bottom: 14px; }
        .modal-data h2 { margin-top: 0; font-size: 18px; color: #0f172a; }
        .modal-data h3 { font-size: 15px; color: #1e3a5f; border-top: 1px solid #e2e8f0; padding-top: 12px; margin-top: 18px; }
        .finding-description { background: #f8fafc; border-radius: 8px; padding: 10px 14px; color: #334155; margin-bottom: 8px; }
        /* Evidence table */
        .evidence-table { width: 100%; border-collapse: collapse; margin: 8px 0; }
        .evidence-table th, .evidence-table td { text-align: left; border-bottom: 1px solid #e2e8f0; padding: 8px 10px; font-size: 13px; }
        .evidence-table th { background: #f1f5f9; font-weight: 600; }
        td.evidence-cell { font-family: Consolas, 'Courier New', monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; }
        .evidence-table tr.status-pass td { background: #f0fdf4; }
        .evidence-table tr.status-fail td { background: #fef2f2; }
        .evidence-table tr.status-unknown td { background: #fffbeb; }
        /* Status utility */
        .status-pass   { background: #dcfce7; color: #166534; }
        .status-fail   { background: #fee2e2; color: #991b1b; }
        .status-unknown { background: #fef3c7; color: #92400e; }
        /* Inventory */
        .card { background: #fff; border-radius: 12px; box-shadow: 0 4px 14px rgba(0,0,0,.08); padding: 16px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; border-bottom: 1px solid #e2e8f0; padding: 9px 10px; font-size: 13px; }
        th { background: #f1f5f9; font-weight: 600; }
        tbody tr:hover td { background: #f8fafc; }
    </style>
</head>
<body>
    <header>
        <h1>EDCA v0.1 &mdash; Exchange Deployment &amp; Compliance Assessment</h1>
        <p>Generated: $($metadata.CollectionTimestamp) | Executed by: $($metadata.ExecutedBy) | Author: <a href="https://eightwone.com" target="_blank" rel="noopener noreferrer" style="color:#93c5fd">Michel de Rooij</a></p>
    </header>
    <main>
        <section>
            <h2>Framework Scores</h2>
            <div class="score-grid">
                $($scoreCards.ToString())
            </div>
        </section>

        <section>
            <h2>Findings</h2>
            <div class="filters">
                <select id="statusFilter">
                    <option value="All">All RAG States</option>
                    <option value="Pass">&#10004; Passed</option>
                    <option value="Fail">&#10006; Risk</option>
                    <option value="Unknown">&#9888; Warning</option>
                </select>
                <select id="frameworkFilter">
                    <option value="All">All Frameworks</option>
                    <option value="BestPractice">BestPractice</option>
                    <option value="CIS">CIS</option>
                    <option value="CISA">CISA</option>
                    <option value="NIS2">NIS2</option>
                    <option value="DISA">DISA</option>
                </select>
                <select id="categoryFilter">
                    <option value="All">All Categories</option>
                    <option value="Authentication">Authentication</option>
                    <option value="Availability">Availability</option>
                    <option value="Cryptography">Cryptography</option>
                    <option value="Email Authentication">Email Authentication</option>
                    <option value="Environment">Environment</option>
                    <option value="Hardening">Hardening</option>
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

        <section>
            <h2>Exchange As-Built Inventory</h2>
            <div class="card">
                <table>
                    <thead>
                        <tr><th>Server</th><th>OS</th><th>Product Line</th><th>Exchange Build</th><th>Edition</th><th>Execution Policy</th><th>RAM (GB)</th></tr>
                    </thead>
                    <tbody>
                        $($serverInventoryRows.ToString())
                    </tbody>
                </table>
            </div>
        </section>
        $edgeServerSection
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
                var label = card.getAttribute('data-label') || '';
                var score = card.getAttribute('data-score') || '0';
                var total = pass + fail + warn || 1;
                var ctx   = canvas.getContext('2d');
                var cx = 60, cy = 60, r = 52, hole = 34;
                var segments = [
                    { v: pass, c: '#16a34a' },
                    { v: warn, c: '#d97706' },
                    { v: fail, c: '#dc2626' }
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
                ctx.fillStyle = '#ffffff';
                ctx.fill();
                /* score % centred in hole */
                ctx.fillStyle = '#0f172a';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.font = 'bold 15px Segoe UI, Arial, sans-serif';
                ctx.fillText(score + '%', cx, cy);
                /* hover tooltip */
                (function (c2, p2, w2, f2, lbl2) {
                    var tip = document.createElement('div');
                    tip.style.cssText = 'display:none;position:fixed;background:#0f172a;color:#f8fafc;font-size:12px;padding:6px 10px;border-radius:8px;pointer-events:none;white-space:nowrap;z-index:9999;line-height:1.6;';
                    tip.innerHTML = '<strong>' + lbl2 + '</strong><br>&#10004;&nbsp;Pass:&nbsp;' + p2 + '<br>&#9888;&nbsp;Warn:&nbsp;' + w2 + '<br>&#10006;&nbsp;Fail:&nbsp;' + f2;
                    document.body.appendChild(tip);
                    c2.parentElement.addEventListener('mouseenter', function () { tip.style.display = 'block'; });
                    c2.parentElement.addEventListener('mousemove',  function (e) {
                        tip.style.left = (e.clientX + 14) + 'px';
                        tip.style.top  = (e.clientY - 36) + 'px';
                    });
                    c2.parentElement.addEventListener('mouseleave', function () { tip.style.display = 'none'; });
                }(canvas, pass, warn, fail, label));
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
            var statusFilter   = document.getElementById('statusFilter');
            var frameworkFilter = document.getElementById('frameworkFilter');
            var categoryFilter = document.getElementById('categoryFilter');
            var groups = document.querySelectorAll('details.category-group');

            function applyFilters() {
                for (var g = 0; g < groups.length; g++) {
                    var group = groups[g];
                    var groupCategory = group.getAttribute('data-category') || '';
                    var categoryMatch = categoryFilter.value === 'All' || groupCategory === categoryFilter.value;
                    var rows = group.querySelectorAll('.finding-row');
                    var visibleCount = 0;

                    for (var i = 0; i < rows.length; i++) {
                        var row = rows[i];
                        var statusMatch    = statusFilter.value === 'All'   || row.getAttribute('data-status') === statusFilter.value;
                        var frameworkText  = row.getAttribute('data-framework') || '';
                        var frameworkMatch = frameworkFilter.value === 'All' || frameworkText.indexOf(frameworkFilter.value) >= 0;
                        var rowVisible = statusMatch && frameworkMatch && categoryMatch;
                        row.style.display = rowVisible ? '' : 'none';
                        if (rowVisible) { visibleCount++; }
                    }

                    var countEl = group.querySelector('.category-count');
                    if (countEl) { countEl.textContent = '(' + visibleCount + ' controls)'; }
                    group.style.display = (categoryMatch && visibleCount > 0) ? '' : 'none';
                }
            }

            statusFilter.addEventListener('change', applyFilters);
            frameworkFilter.addEventListener('change', applyFilters);
            categoryFilter.addEventListener('change', applyFilters);
            applyFilters();
        })();
    </script>
</body>
</html>
"@

    Set-Content -Path $OutputFile -Value $html -Encoding UTF8
    Write-Verbose ('HTML report written to {0}' -f $OutputFile)
    return $OutputFile
}

