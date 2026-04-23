# Script:  Analysis.ps1
# Synopsis: Part of EDCA (Exchange Deployment & Compliance Assessment)
#           https://github.com/michelderooij/EDCA
# Author:  Michel de Rooij
# Website: https://eightwone.com

Set-StrictMode -Version Latest

function Get-EDCAFindingStatusFromBool {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return 'Unknown'
    }

    if ([bool]$Value) {
        return 'Pass'
    }

    return 'Fail'
}

function Get-EDCAStateDescriptor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Value,
        [Parameter(Mandatory = $true)]
        [ValidateSet('Enabled', 'Disabled', 'Required', 'Configured', 'Passed', 'Present', 'Active')]
        [string]$Expectation
    )

    switch ($Expectation) {
        'Enabled' {
            if ($Value) { return 'enabled' }
            return 'not enabled'
        }
        'Disabled' {
            if ($Value) { return 'not disabled' }
            return 'disabled'
        }
        'Required' {
            if ($Value) { return 'required' }
            return 'not required'
        }
        'Configured' {
            if ($Value) { return 'configured' }
            return 'not configured'
        }
        'Passed' {
            if ($Value) { return 'passed' }
            return 'not passed'
        }
        'Present' {
            if ($Value) { return 'present' }
            return 'not present'
        }
        default {
            if ($Value) { return 'active' }
            return 'not active'
        }
    }
}

function Get-EDCAProductLineFromServerData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Server
    )

    $productLine = ''
    if ($Server.PSObject.Properties.Name -contains 'Exchange' -and $Server.Exchange.PSObject.Properties.Name -contains 'ProductLine') {
        $productLine = [string]$Server.Exchange.ProductLine
    }

    $build = ''
    if ($Server.PSObject.Properties.Name -contains 'Exchange' -and $Server.Exchange.PSObject.Properties.Name -contains 'AdminDisplayVersion') {
        $build = [string]$Server.Exchange.AdminDisplayVersion
    }

    $derivedProductLine = 'Unknown'
    if ($build -match 'Version 15\.1') {
        $derivedProductLine = 'Exchange2016'
    }
    elseif ($build -match 'Version 15\.2') {
        $isSe = $false
        if ($build -match 'Subscription|SE') {
            $isSe = $true
        }
        elseif ($build -match 'Build\s+(\d+)\.') {
            if ([int]$matches[1] -ge 2562) {
                # Exchange SE builds can be identified by 15.2 build train even when explicit SE markers are missing.
                $isSe = $true
            }
        }

        $derivedProductLine = if ($isSe) { 'ExchangeSE' } else { 'Exchange2019' }
    }

    if (-not [string]::IsNullOrWhiteSpace($productLine) -and $productLine -ne 'Unknown') {
        # Prefer explicit collected product line, but correct known stale Exchange2019 labels
        # when build metadata clearly identifies Exchange SE.
        if ($productLine -eq 'Exchange2019' -and $derivedProductLine -eq 'ExchangeSE') {
            return 'ExchangeSE'
        }

        return $productLine
    }

    if ($derivedProductLine -ne 'Unknown') {
        return $derivedProductLine
    }

    return 'Unknown'
}

function Format-EDCAEvidenceWithElements {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Summary,
        [AllowNull()]
        [object[]]$Elements
    )

    $lines = @()
    if (-not [string]::IsNullOrWhiteSpace($Summary)) {
        $lines += ([string]$Summary).Trim()
    }

    foreach ($element in @($Elements)) {
        $text = [string]$element
        if (-not [string]::IsNullOrWhiteSpace($text)) {
            $lines += ('- {0}' -f $text.Trim())
        }
    }

    return ($lines -join "`n")
}

function Test-EDCAIsTls13SupportedOs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Server
    )

    $osVersionText = ''
    if (($Server.PSObject.Properties.Name -contains 'OS') -and ($Server.OS.PSObject.Properties.Name -contains 'OSVersion')) {
        $osVersionText = [string]$Server.OS.OSVersion
    }

    if ([string]::IsNullOrWhiteSpace($osVersionText)) {
        return [pscustomobject]@{
            IsSupported = $false
            IsKnown     = $false
            Evidence    = 'OS version unavailable.'
        }
    }

    $osVersion = $null
    if (-not [System.Version]::TryParse($osVersionText, [ref]$osVersion)) {
        return [pscustomobject]@{
            IsSupported = $false
            IsKnown     = $false
            Evidence    = ('Unable to parse OS version: {0}' -f $osVersionText)
        }
    }

    # TLS 1.3 support is available on newer Windows Server builds (Server 2022+ baseline).
    $isSupported = ($osVersion.Major -gt 10) -or (($osVersion.Major -eq 10) -and ($osVersion.Build -ge 20348))
    return [pscustomobject]@{
        IsSupported = $isSupported
        IsKnown     = $true
        Evidence    = ('OS version: {0}; TLS 1.3 supported baseline: build 20348+' -f $osVersionText)
    }
}

function Get-EDCAOsBuildInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Server
    )

    $osVersionText = ''
    if (($Server.PSObject.Properties.Name -contains 'OS') -and ($Server.OS.PSObject.Properties.Name -contains 'OSVersion')) {
        $osVersionText = [string]$Server.OS.OSVersion
    }

    if ([string]::IsNullOrWhiteSpace($osVersionText)) {
        return [pscustomobject]@{
            IsKnown  = $false
            Build    = $null
            Evidence = 'OS version unavailable.'
        }
    }

    $osVersion = $null
    if (-not [System.Version]::TryParse($osVersionText, [ref]$osVersion)) {
        return [pscustomobject]@{
            IsKnown  = $false
            Build    = $null
            Evidence = ('Unable to parse OS version: {0}' -f $osVersionText)
        }
    }

    return [pscustomobject]@{
        IsKnown  = $true
        Build    = $osVersion.Build
        Evidence = ('OS version: {0}; build: {1}' -f $osVersionText, $osVersion.Build)
    }
}

function Test-EDCAControl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Control,
        [Parameter(Mandatory = $true)]
        [pscustomobject]$CollectionData
    )

    if ($Control.id -in @('EDCA-MON-001', 'EDCA-IAC-001', 'EDCA-DATA-002', 'EDCA-IAC-004', 'EDCA-IAC-008', 'EDCA-SEC-032', 'EDCA-TLS-026', 'EDCA-TLS-023', 'EDCA-TLS-025', 'EDCA-TLS-024', 'EDCA-TLS-027', 'EDCA-TLS-028', 'EDCA-TLS-029', 'EDCA-SEC-004', 'EDCA-SEC-003', 'EDCA-SEC-005', 'EDCA-TLS-003', 'EDCA-IAC-011', 'EDCA-GOV-004', 'EDCA-IAC-009', 'EDCA-IAC-010', 'EDCA-TLS-004', 'EDCA-TLS-005', 'EDCA-TLS-006', 'EDCA-TLS-007', 'EDCA-TLS-008', 'EDCA-TLS-009', 'EDCA-MON-008', 'EDCA-TLS-010', 'EDCA-TLS-011', 'EDCA-TLS-014', 'EDCA-IAC-014', 'EDCA-IAC-015', 'EDCA-IAC-016', 'EDCA-IAC-017', 'EDCA-IAC-018', 'EDCA-IAC-019', 'EDCA-IAC-020', 'EDCA-IAC-021', 'EDCA-IAC-022', 'EDCA-IAC-023', 'EDCA-IAC-024', 'EDCA-TLS-012', 'EDCA-TLS-018', 'EDCA-TLS-019', 'EDCA-DATA-016', 'EDCA-RES-012', 'EDCA-GOV-009', 'EDCA-PERF-012', 'EDCA-GOV-011', 'EDCA-SEC-036', 'EDCA-IAC-028', 'EDCA-RES-011')) {
        $status = 'Unknown'
        $evidence = ''
        $domainServerResults = $null
        $subjectLabel = 'Organization'

        switch ($Control.id) {
            'EDCA-SEC-032' {
                $settingOverrides = $null
                foreach ($srv in @($CollectionData.Servers)) {
                    if (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and
                        ($srv.Exchange.PSObject.Properties.Name -contains 'SettingOverrides') -and
                        $null -ne $srv.Exchange.SettingOverrides) {
                        $settingOverrides = $srv.Exchange.SettingOverrides
                        break
                    }
                }
                if ($null -eq $settingOverrides) {
                    $status = 'Unknown'
                    $evidence = 'Setting override telemetry unavailable; cannot verify P2 FROM detection state.'
                }
                else {
                    $overrideNames = @()
                    if (($settingOverrides.PSObject.Properties.Name -contains 'Names') -and $null -ne $settingOverrides.Names) {
                        $overrideNames = @($settingOverrides.Names | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
                    }
                    $disableOverrides = @($overrideNames | Where-Object { $_ -match '(?i)DisableP2FromRegexMatch' })
                    if ($disableOverrides.Count -gt 0) {
                        $status = 'Fail'
                        $summary = ('Detected {0} P2 FROM detection override(s) that disable default protections.' -f $disableOverrides.Count)
                        $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $disableOverrides
                    }
                    else {
                        $status = 'Pass'
                        if ($overrideNames.Count -eq 0) {
                            $evidence = 'No Exchange setting overrides detected; P2 FROM detection defaults are preserved.'
                        }
                        else {
                            $evidence = 'No P2 FROM detection disabling overrides detected in Exchange setting overrides.'
                        }
                    }
                }
            }
            'EDCA-IAC-001' {
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and ($CollectionData.Organization.PSObject.Properties.Name -contains 'UpnPrimarySmtpMismatchCount') -and $null -ne $CollectionData.Organization.UpnPrimarySmtpMismatchCount) {
                    $count = [int]$CollectionData.Organization.UpnPrimarySmtpMismatchCount
                    $status = if ($count -eq 0) { 'Pass' } else { 'Fail' }
                    $evidence = if ($count -eq 0) { 'Compliant — no UPN/Primary SMTP mismatches detected.' } else { ('UPN/Primary SMTP mismatches: {0}' -f $count) }
                }
                else {
                    $status = 'Unknown'
                    $evidence = 'Mailbox UPN/SMTP baseline data unavailable.'
                }
            }
            'EDCA-IAC-004' {
                $maIssues = @()

                # Check 1: OAuth2ClientProfileEnabled
                $oauthEnabled = $null
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'OAuth2ClientProfileEnabled')) {
                    $oauthEnabled = $CollectionData.Organization.OAuth2ClientProfileEnabled
                }
                if ($null -eq $oauthEnabled) {
                    $maIssues += 'OAuth2ClientProfileEnabled: data unavailable (cannot verify)'
                }
                elseif ([bool]$oauthEnabled -eq $false) {
                    $maIssues += 'OAuth2ClientProfileEnabled is False — run: Set-OrganizationConfig -OAuth2ClientProfileEnabled $true'
                }

                # Check 2: auth server with IsDefaultAuthorizationEndpoint = true and a configured AuthMetadataUrl
                # Detected type: HMA (login.windows.net/login.microsoftonline.com) or ADFS (on-premises endpoint)
                $detectedModernAuthType = 'None'
                $detectedAuthMetadataUrl = ''
                foreach ($srv in @($CollectionData.Servers)) {
                    if (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and
                        ($srv.Exchange.PSObject.Properties.Name -contains 'HybridApplication') -and $null -ne $srv.Exchange.HybridApplication) {
                        $hybApp = $srv.Exchange.HybridApplication
                        if (($hybApp.PSObject.Properties.Name -contains 'ModernAuthType') -and
                            [string]$hybApp.ModernAuthType -ne 'None' -and
                            -not [string]::IsNullOrWhiteSpace([string]$hybApp.ModernAuthType)) {
                            $detectedModernAuthType = [string]$hybApp.ModernAuthType
                            $detectedAuthMetadataUrl = if ($hybApp.PSObject.Properties.Name -contains 'DefaultAuthServerAuthMetadataUrl') {
                                [string]$hybApp.DefaultAuthServerAuthMetadataUrl
                            }
                            else { '' }
                            break
                        }
                    }
                }
                if ($detectedModernAuthType -eq 'None') {
                    $maIssues += 'No auth server has IsDefaultAuthorizationEndpoint = True with a configured AuthMetadataUrl — configure HMA (run: Set-AuthServer -Identity EvoSts -IsDefaultAuthorizationEndpoint $true after running the Hybrid Configuration Wizard) or AD FS (run: New-AuthServer -Type ADFS -Name <name> -AuthMetadataUrl https://<adfs-fqdn>/FederationMetadata/2007-06/FederationMetadata.xml, then Set-AuthServer -Identity <name> -IsDefaultAuthorizationEndpoint $true)'
                }

                # Check 3: SSL Offloading disabled (incompatible with Modern Authentication)
                $sslOffloadingServers = @()
                foreach ($srv in @($CollectionData.Servers)) {
                    if (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and
                        ($srv.Exchange.PSObject.Properties.Name -contains 'OutlookAnywhereSSLOffloading')) {
                        foreach ($oa in @($srv.Exchange.OutlookAnywhereSSLOffloading)) {
                            if ($null -ne $oa.SSLOffloading -and [bool]$oa.SSLOffloading -eq $true) {
                                $sslOffloadingServers += [string]$oa.Identity
                            }
                        }
                    }
                }
                if ($sslOffloadingServers.Count -gt 0) {
                    $maIssues += ('SSL Offloading is enabled on {0} Outlook Anywhere connector(s) — incompatible with Modern Authentication: {1}' -f $sslOffloadingServers.Count, ($sslOffloadingServers -join ', '))
                }

                # Check 4: OAuth enabled on EWS and Autodiscover vdirs
                # Note: Set-MapiVirtualDirectory and Set-ActiveSyncVirtualDirectory do not expose -OAuthAuthentication; those vdirs are excluded.
                $targetTypes = @('Get-WebServicesVirtualDirectory', 'Get-AutodiscoverVirtualDirectory')
                $nonCompliantVdirs = @()
                $checkedVdirCount = 0
                $vdirDataAvailable = $false
                foreach ($srv in @($CollectionData.Servers)) {
                    if (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and
                        ($srv.Exchange.PSObject.Properties.Name -contains 'ExtendedProtectionStatus') -and
                        @($srv.Exchange.ExtendedProtectionStatus).Count -gt 0) {
                        $vdirDataAvailable = $true
                        foreach ($vdir in @($srv.Exchange.ExtendedProtectionStatus)) {
                            if ([string]$vdir.VirtualDirectoryType -notin $targetTypes) { continue }
                            $checkedVdirCount++
                            $oauthValue = if ($vdir.PSObject.Properties.Name -contains 'OAuthAuthentication') { $vdir.OAuthAuthentication } else { $null }
                            if ($null -eq $oauthValue) {
                                $nonCompliantVdirs += ('{0}: OAuthAuthentication data unavailable' -f [string]$vdir.Identity)
                            }
                            elseif ([bool]$oauthValue -eq $false) {
                                $nonCompliantVdirs += ('{0}: OAuthAuthentication = False' -f [string]$vdir.Identity)
                            }
                        }
                    }
                }
                if (-not $vdirDataAvailable) {
                    $maIssues += 'Virtual directory data unavailable — cannot verify OAuthAuthentication on EWS/Autodiscover vdirs'
                }
                elseif ($nonCompliantVdirs.Count -gt 0) {
                    foreach ($vdirIssue in $nonCompliantVdirs) {
                        $maIssues += ('OAuthAuthentication not enabled: {0}' -f $vdirIssue)
                    }
                }

                if ($maIssues.Count -eq 0) {
                    $authTypeLabel = switch ($detectedModernAuthType) {
                        'HMA' { 'HMA (Entra/Azure AD)' }
                        'ADFS' { 'AD FS' }
                        default { $detectedModernAuthType }
                    }
                    $status = 'Pass'
                    $evidence = ('Modern Authentication prerequisites satisfied: OAuth2ClientProfileEnabled = True, {0} authorization endpoint configured (AuthMetadataUrl: {1}), SSL Offloading disabled, OAuth enabled on all {2} checked virtual directory(s).' -f $authTypeLabel, $detectedAuthMetadataUrl, $checkedVdirCount)
                }
                else {
                    $status = 'Fail'
                    $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} Modern Authentication prerequisite issue(s) detected:' -f $maIssues.Count) -Elements $maIssues
                }
            }
            'EDCA-IAC-008' {
                $splitPermissionsEnabled = $null
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization) {
                    if (($CollectionData.Organization.PSObject.Properties.Name -contains 'AdSplitPermissionEnabled') -and $null -ne $CollectionData.Organization.AdSplitPermissionEnabled) {
                        $splitPermissionsEnabled = [bool]$CollectionData.Organization.AdSplitPermissionEnabled
                    }
                    elseif (($CollectionData.Organization.PSObject.Properties.Name -contains 'ADSplitPermissionEnabled') -and $null -ne $CollectionData.Organization.ADSplitPermissionEnabled) {
                        $splitPermissionsEnabled = [bool]$CollectionData.Organization.ADSplitPermissionEnabled
                    }
                }

                if ($null -eq $splitPermissionsEnabled) {
                    $status = 'Unknown'
                    $evidence = 'Split permission organization setting unavailable.'
                }
                else {
                    $status = if ($splitPermissionsEnabled) { 'Pass' } else { 'Fail' }
                    $evidence = ('AdSplitPermissionEnabled is {0}.' -f (Get-EDCAStateDescriptor -Value $splitPermissionsEnabled -Expectation 'Enabled'))
                }
            }
            'EDCA-TLS-026' {
                $subjectLabel = 'Domain'
                $domainResults = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'EmailAuthentication') -and $null -ne $CollectionData.EmailAuthentication -and ($CollectionData.EmailAuthentication.PSObject.Properties.Name -contains 'DomainResults')) {
                    $domainResults = @($CollectionData.EmailAuthentication.DomainResults)
                }

                if ($domainResults.Count -eq 0) {
                    $status = 'Unknown'
                    if (($CollectionData.PSObject.Properties.Name -contains 'EmailAuthentication') -and ($CollectionData.EmailAuthentication.PSObject.Properties.Name -contains 'Reason')) {
                        $evidence = ('No domain-level SPF evidence available. {0}' -f [string]$CollectionData.EmailAuthentication.Reason)
                    }
                    else {
                        $evidence = 'No domain-level SPF evidence available.'
                    }
                }
                else {
                    $domainServerResults = @($domainResults | ForEach-Object {
                            if ([string]$_.Domain -match '(?i)\.(local|lan|internal|corp|home|localdomain|localhost)$') {
                                [pscustomobject]@{ Server = $_.Domain; Status = 'Skipped'; Evidence = 'Non-internet-routable domain — SPF check not applicable.' }
                            }
                            else {
                                $noPublicMx = ($null -eq $_.Dane -or $null -eq $_.Dane.MxHosts -or @($_.Dane.MxHosts).Count -eq 0)
                                $hasSpfRecords = ($null -ne $_.Spf -and ($_.Spf.PSObject.Properties.Name -contains 'Records') -and @($_.Spf.Records).Count -gt 0)
                                if ($noPublicMx -and -not $hasSpfRecords) {
                                    [pscustomobject]@{ Server = $_.Domain; Status = 'Skipped'; Evidence = 'No public MX records found — likely an internal domain; SPF check not applicable.' }
                                }
                                else {
                                    $spfEvidence = [string]$_.Spf.Evidence
                                    $spfCount = $null
                                    if ($_.Spf.PSObject.Properties.Name -contains 'PotentialDnsLookupCount') {
                                        $spfCount = $_.Spf.PotentialDnsLookupCount
                                    }
                                    if ($null -ne $spfCount -and [int]$spfCount -gt 10) {
                                        $spfEvidence += ("`nNote: DNS lookup count ({0}) exceeds RFC 7208 limit of 10; receiving MTAs will likely ignore this SPF record." -f $spfCount)
                                    }
                                    [pscustomobject]@{ Server = $_.Domain; Status = $_.Spf.Status; Evidence = $spfEvidence }
                                }
                            }
                        })
                    $failed = @($domainServerResults | Where-Object { $_.Status -eq 'Fail' })
                    $unknown = @($domainServerResults | Where-Object { $_.Status -eq 'Unknown' })
                    if ($failed.Count -gt 0) {
                        $status = 'Fail'
                    }
                    elseif ($unknown.Count -gt 0) {
                        $status = 'Unknown'
                    }
                    elseif (@($domainServerResults | Where-Object { $_.Status -eq 'Pass' }).Count -gt 0) {
                        $status = 'Pass'
                    }
                    else {
                        $status = 'Skipped'
                        $evidence = 'All accepted domains are non-internet-routable — SPF check not applicable.'
                    }
                }
            }
            'EDCA-TLS-027' {
                $subjectLabel = 'Domain'
                $domainResults = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'EmailAuthentication') -and $null -ne $CollectionData.EmailAuthentication -and ($CollectionData.EmailAuthentication.PSObject.Properties.Name -contains 'DomainResults')) {
                    $domainResults = @($CollectionData.EmailAuthentication.DomainResults)
                }

                if ($domainResults.Count -eq 0) {
                    $status = 'Unknown'
                    if (($CollectionData.PSObject.Properties.Name -contains 'EmailAuthentication') -and ($CollectionData.EmailAuthentication.PSObject.Properties.Name -contains 'Reason')) {
                        $evidence = ('No domain-level DKIM evidence available. {0}' -f [string]$CollectionData.EmailAuthentication.Reason)
                    }
                    else {
                        $evidence = 'No domain-level DKIM evidence available.'
                    }
                }
                else {
                    $domainServerResults = @($domainResults | ForEach-Object {
                            if ($null -eq $_ -or -not ($_.PSObject.Properties.Name -contains 'Domain')) { return }
                            if ([string]$_.Domain -match '(?i)\.(local|lan|internal|corp|home|localdomain|localhost)$') {
                                [pscustomobject]@{ Server = $_.Domain; Status = 'Skipped'; Evidence = 'Non-internet-routable domain — DKIM check not applicable.' }
                            }
                            else {
                                $noPublicMx = (-not ($_.PSObject.Properties.Name -contains 'Dane') -or $null -eq $_.Dane -or -not ($_.Dane.PSObject.Properties.Name -contains 'MxHosts') -or $null -eq $_.Dane.MxHosts -or @($_.Dane.MxHosts).Count -eq 0)
                                $hasSpfRecords = ($null -ne $_.Spf -and ($_.Spf.PSObject.Properties.Name -contains 'Records') -and @($_.Spf.Records).Count -gt 0)
                                if ($noPublicMx -and -not $hasSpfRecords) {
                                    [pscustomobject]@{ Server = $_.Domain; Status = 'Skipped'; Evidence = 'No public MX records found — likely an internal domain; DKIM check not applicable.' }
                                }
                                else {
                                    $dkimStatus = 'Unknown'
                                    $dkimEvidence = 'DKIM data not collected.'
                                    if (($_.PSObject.Properties.Name -contains 'Dkim') -and $null -ne $_.Dkim) {
                                        $rawDkimStatus = if ($_.Dkim.PSObject.Properties.Name -contains 'Status') { [string]$_.Dkim.Status } else { 'Unknown' }
                                        if ($rawDkimStatus -eq 'Pass') {
                                            $passParts = @()
                                            if (($_.Dkim.PSObject.Properties.Name -contains 'DetectedSelectors') -and $null -ne $_.Dkim.DetectedSelectors -and $_.Dkim.DetectedSelectors -is [PSCustomObject]) {
                                                $domainNorm = ([string]$_.Domain).TrimEnd('.').ToLowerInvariant()
                                                $platformGroups = [ordered]@{}
                                                foreach ($selProp in $_.Dkim.DetectedSelectors.PSObject.Properties) {
                                                    if ($null -eq $selProp) { continue }
                                                    $selName = $selProp.Name
                                                    $selEntry = $selProp.Value
                                                    if ($null -eq $selEntry) { continue }
                                                    $record = ('{0}._domainkey.{1}' -f $selName, [string]$_.Domain)
                                                    $hasCname = ($selEntry.PSObject.Properties.Name -contains 'Type') -and [string]$selEntry.Type -eq 'CNAME' -and ($selEntry.PSObject.Properties.Name -contains 'Cname') -and -not [string]::IsNullOrWhiteSpace([string]$selEntry.Cname)
                                                    # Skip self-referential CNAMEs — resolving back to the domain itself is not evidence of platform DKIM signing
                                                    if ($hasCname) {
                                                        $cnameNorm = ([string]$selEntry.Cname).TrimEnd('.').ToLowerInvariant()
                                                        if ($cnameNorm -eq $domainNorm) { continue }
                                                    }
                                                    $service = if ($selEntry.PSObject.Properties.Name -contains 'Service') { [string]$selEntry.Service } else { '' }
                                                    if ([string]::IsNullOrWhiteSpace($service)) { $service = '(unknown platform)' }
                                                    if (-not $platformGroups.Contains($service)) { $platformGroups[$service] = [System.Collections.Generic.List[string]]::new() }
                                                    if ($hasCname) {
                                                        $platformGroups[$service].Add(('  - {0} → CNAME: {1}' -f $record, [string]$selEntry.Cname))
                                                    }
                                                    else {
                                                        $platformGroups[$service].Add(('  - {0} → TXT record found' -f $record))
                                                    }
                                                }
                                                foreach ($svc in $platformGroups.Keys) {
                                                    $passParts += ('{0}:' -f $svc)
                                                    foreach ($line in $platformGroups[$svc]) { $passParts += $line }
                                                }
                                            }
                                            $dkimStatus = 'Pass'
                                            $dkimEvidence = if ($passParts.Count -gt 0) { $passParts -join "`n" } elseif ($_.Dkim.PSObject.Properties.Name -contains 'Evidence') { [string]$_.Dkim.Evidence } else { '' }
                                        }
                                        elseif ($rawDkimStatus -eq 'Fail') {
                                            $dkimStatus = 'Warn'
                                            $dkimEvidence = 'DKIM signing could not be verified — no selector records found matching the predefined set of popular DKIM-supporting platforms. ' + (if ($_.Dkim.PSObject.Properties.Name -contains 'Evidence') { [string]$_.Dkim.Evidence } else { '' })
                                        }
                                        else {
                                            $dkimStatus = $rawDkimStatus
                                            $dkimEvidence = if ($_.Dkim.PSObject.Properties.Name -contains 'Evidence') { [string]$_.Dkim.Evidence } else { '' }
                                        }
                                    }
                                    [pscustomobject]@{ Server = $_.Domain; Status = $dkimStatus; Evidence = $dkimEvidence }
                                }
                            }
                        })
                    $failed = @($domainServerResults | Where-Object { $_.Status -eq 'Fail' })
                    $warned = @($domainServerResults | Where-Object { $_.Status -eq 'Warn' })
                    $unknown = @($domainServerResults | Where-Object { $_.Status -eq 'Unknown' })
                    if ($failed.Count -gt 0) {
                        $status = 'Fail'
                    }
                    elseif ($unknown.Count -gt 0) {
                        $status = 'Unknown'
                    }
                    elseif ($warned.Count -gt 0) {
                        $status = 'Warn'
                    }
                    elseif (@($domainServerResults | Where-Object { $_.Status -eq 'Pass' }).Count -gt 0) {
                        $status = 'Pass'
                    }
                    else {
                        $status = 'Skipped'
                        $evidence = 'All accepted domains are non-internet-routable — DKIM check not applicable.'
                    }
                }
            }
            'EDCA-TLS-028' {
                $subjectLabel = 'Domain'
                $domainResults = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'EmailAuthentication') -and $null -ne $CollectionData.EmailAuthentication -and ($CollectionData.EmailAuthentication.PSObject.Properties.Name -contains 'DomainResults')) {
                    $domainResults = @($CollectionData.EmailAuthentication.DomainResults)
                }

                if ($domainResults.Count -eq 0) {
                    $status = 'Unknown'
                    if (($CollectionData.PSObject.Properties.Name -contains 'EmailAuthentication') -and ($CollectionData.EmailAuthentication.PSObject.Properties.Name -contains 'Reason')) {
                        $evidence = ('No domain-level TLS-RPT evidence available. {0}' -f [string]$CollectionData.EmailAuthentication.Reason)
                    }
                    else {
                        $evidence = 'No domain-level TLS-RPT evidence available.'
                    }
                }
                else {
                    $domainServerResults = @($domainResults | ForEach-Object {
                            if ([string]$_.Domain -match '(?i)\.(local|lan|internal|corp|home|localdomain|localhost)$') {
                                [pscustomobject]@{ Server = $_.Domain; Status = 'Skipped'; Evidence = 'Non-internet-routable domain — TLS-RPT check not applicable.' }
                            }
                            else {
                                $noPublicMx = ($null -eq $_.Dane -or $null -eq $_.Dane.MxHosts -or @($_.Dane.MxHosts).Count -eq 0)
                                $hasSpfRecords = ($null -ne $_.Spf -and ($_.Spf.PSObject.Properties.Name -contains 'Records') -and @($_.Spf.Records).Count -gt 0)
                                if ($noPublicMx -and -not $hasSpfRecords) {
                                    [pscustomobject]@{ Server = $_.Domain; Status = 'Skipped'; Evidence = 'No public MX records found — likely an internal domain; TLS-RPT check not applicable.' }
                                }
                                else {
                                    $tlsRptStatus = 'Unknown'
                                    $tlsRptEvidence = 'TLS-RPT data not collected.'
                                    if (($_.PSObject.Properties.Name -contains 'TlsRpt') -and $null -ne $_.TlsRpt) {
                                        $tlsRptStatus = [string]$_.TlsRpt.Status
                                        $tlsRptEvidence = [string]$_.TlsRpt.Evidence
                                    }
                                    [pscustomobject]@{ Server = $_.Domain; Status = $tlsRptStatus; Evidence = $tlsRptEvidence }
                                }
                            }
                        })
                    $failed = @($domainServerResults | Where-Object { $_.Status -eq 'Fail' })
                    $unknown = @($domainServerResults | Where-Object { $_.Status -eq 'Unknown' })
                    if ($failed.Count -gt 0) {
                        $status = 'Fail'
                    }
                    elseif ($unknown.Count -gt 0) {
                        $status = 'Unknown'
                    }
                    elseif (@($domainServerResults | Where-Object { $_.Status -eq 'Pass' }).Count -gt 0) {
                        $status = 'Pass'
                    }
                    else {
                        $status = 'Skipped'
                        $evidence = 'All accepted domains are non-internet-routable — TLS-RPT check not applicable.'
                    }
                }
            }
            'EDCA-TLS-023' {
                $subjectLabel = 'Domain'
                $domainResults = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'EmailAuthentication') -and $null -ne $CollectionData.EmailAuthentication -and ($CollectionData.EmailAuthentication.PSObject.Properties.Name -contains 'DomainResults')) {
                    $domainResults = @($CollectionData.EmailAuthentication.DomainResults)
                }

                if ($domainResults.Count -eq 0) {
                    $status = 'Unknown'
                    if (($CollectionData.PSObject.Properties.Name -contains 'EmailAuthentication') -and ($CollectionData.EmailAuthentication.PSObject.Properties.Name -contains 'Reason')) {
                        $evidence = ('No domain-level DMARC evidence available. {0}' -f [string]$CollectionData.EmailAuthentication.Reason)
                    }
                    else {
                        $evidence = 'No domain-level DMARC evidence available.'
                    }
                }
                else {
                    $domainServerResults = @($domainResults | ForEach-Object {
                            if ([string]$_.Domain -match '(?i)\.(local|lan|internal|corp|home|localdomain|localhost)$') {
                                [pscustomobject]@{ Server = $_.Domain; Status = 'Skipped'; Evidence = 'Non-internet-routable domain — DMARC check not applicable.' }
                            }
                            else {
                                $noPublicMx = ($null -eq $_.Dane -or $null -eq $_.Dane.MxHosts -or @($_.Dane.MxHosts).Count -eq 0)
                                $hasSpfRecords = ($null -ne $_.Spf -and ($_.Spf.PSObject.Properties.Name -contains 'Records') -and @($_.Spf.Records).Count -gt 0)
                                if ($noPublicMx -and -not $hasSpfRecords) {
                                    [pscustomobject]@{ Server = $_.Domain; Status = 'Skipped'; Evidence = 'No public MX records found — likely an internal domain; DMARC check not applicable.' }
                                }
                                else {
                                    [pscustomobject]@{ Server = $_.Domain; Status = $_.Dmarc.Status; Evidence = [string]$_.Dmarc.Evidence }
                                }
                            }
                        })
                    $failed = @($domainServerResults | Where-Object { $_.Status -eq 'Fail' })
                    $unknown = @($domainServerResults | Where-Object { $_.Status -eq 'Unknown' })
                    if ($failed.Count -gt 0) {
                        $status = 'Fail'
                    }
                    elseif ($unknown.Count -gt 0) {
                        $status = 'Unknown'
                    }
                    elseif (@($domainServerResults | Where-Object { $_.Status -eq 'Pass' }).Count -gt 0) {
                        $status = 'Pass'
                    }
                    else {
                        $status = 'Skipped'
                        $evidence = 'All accepted domains are non-internet-routable — DMARC check not applicable.'
                    }
                }
            }
            'EDCA-TLS-025' {
                $subjectLabel = 'Domain'
                $domainResults = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'EmailAuthentication') -and $null -ne $CollectionData.EmailAuthentication -and ($CollectionData.EmailAuthentication.PSObject.Properties.Name -contains 'DomainResults')) {
                    $domainResults = @($CollectionData.EmailAuthentication.DomainResults)
                }

                if ($domainResults.Count -eq 0) {
                    $status = 'Unknown'
                    if (($CollectionData.PSObject.Properties.Name -contains 'EmailAuthentication') -and ($CollectionData.EmailAuthentication.PSObject.Properties.Name -contains 'Reason')) {
                        $evidence = ('No domain-level MTA-STS evidence available. {0}' -f [string]$CollectionData.EmailAuthentication.Reason)
                    }
                    else {
                        $evidence = 'No domain-level MTA-STS evidence available.'
                    }
                }
                else {
                    $domainServerResults = @($domainResults | ForEach-Object {
                            if ([string]$_.Domain -match '(?i)\.(local|lan|internal|corp|home|localdomain|localhost)$') {
                                [pscustomobject]@{ Server = $_.Domain; Status = 'Skipped'; Evidence = 'Non-internet-routable domain — MTA-STS check not applicable.' }
                            }
                            else {
                                $noPublicMx = ($null -eq $_.Dane -or $null -eq $_.Dane.MxHosts -or @($_.Dane.MxHosts).Count -eq 0)
                                $hasSpfRecords = ($null -ne $_.Spf -and ($_.Spf.PSObject.Properties.Name -contains 'Records') -and @($_.Spf.Records).Count -gt 0)
                                if ($noPublicMx -and -not $hasSpfRecords) {
                                    [pscustomobject]@{ Server = $_.Domain; Status = 'Skipped'; Evidence = 'No public MX records found — likely an internal domain; MTA-STS check not applicable.' }
                                }
                                else {
                                    $mtaSts = $_.MtaSts
                                    $mtaEvidence = [string]$mtaSts.Evidence
                                    if (($mtaSts.PSObject.Properties.Name -contains 'PolicyStatus') -and [string]$mtaSts.PolicyStatus -eq 'Fetched') {
                                        $evParts = @('DNS record: "{0}"' -f [string]$mtaSts.DnsRecord)
                                        $evParts += ('Policy ({0}):' -f [string]$mtaSts.PolicyUrl)
                                        if (($mtaSts.PSObject.Properties.Name -contains 'PolicyMode') -and $null -ne $mtaSts.PolicyMode) {
                                            $evParts += ('  mode: {0}' -f [string]$mtaSts.PolicyMode)
                                        }
                                        if (($mtaSts.PSObject.Properties.Name -contains 'PolicyMaxAge') -and $null -ne $mtaSts.PolicyMaxAge) {
                                            $evParts += ('  max_age: {0}' -f [string]$mtaSts.PolicyMaxAge)
                                        }
                                        if (($mtaSts.PSObject.Properties.Name -contains 'PolicyMxEntries') -and $null -ne $mtaSts.PolicyMxEntries) {
                                            foreach ($mxEntry in @($mtaSts.PolicyMxEntries)) { $evParts += ('  mx: {0}' -f [string]$mxEntry) }
                                        }
                                        $issueList = @()
                                        if ($mtaSts.PSObject.Properties.Name -contains 'Issues') { $issueList = @($mtaSts.Issues) }
                                        foreach ($iss in $issueList) { $evParts += ('  issue: {0}' -f [string]$iss) }
                                        $mtaEvidence = $evParts -join "`n"
                                    }
                                    [pscustomobject]@{ Server = $_.Domain; Status = $mtaSts.Status; Evidence = $mtaEvidence }
                                }
                            }
                        })
                    $failed = @($domainServerResults | Where-Object { $_.Status -eq 'Fail' })
                    $unknown = @($domainServerResults | Where-Object { $_.Status -eq 'Unknown' })
                    if ($failed.Count -gt 0) {
                        $status = 'Fail'
                    }
                    elseif ($unknown.Count -gt 0) {
                        $status = 'Unknown'
                    }
                    elseif (@($domainServerResults | Where-Object { $_.Status -eq 'Pass' }).Count -gt 0) {
                        $status = 'Pass'
                    }
                    else {
                        $status = 'Skipped'
                        $evidence = 'All accepted domains are non-internet-routable — MTA-STS check not applicable.'
                    }
                }
            }
            'EDCA-TLS-024' {
                $subjectLabel = 'Domain'
                $domainResults = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'EmailAuthentication') -and $null -ne $CollectionData.EmailAuthentication -and ($CollectionData.EmailAuthentication.PSObject.Properties.Name -contains 'DomainResults')) {
                    $domainResults = @($CollectionData.EmailAuthentication.DomainResults)
                }

                if ($domainResults.Count -eq 0) {
                    $status = 'Unknown'
                    if (($CollectionData.PSObject.Properties.Name -contains 'EmailAuthentication') -and ($CollectionData.EmailAuthentication.PSObject.Properties.Name -contains 'Reason')) {
                        $evidence = ('No domain-level SMTP DANE evidence available. {0}' -f [string]$CollectionData.EmailAuthentication.Reason)
                    }
                    else {
                        $evidence = 'No domain-level SMTP DANE evidence available.'
                    }
                }
                else {
                    $domainServerResults = @($domainResults | ForEach-Object {
                            if ([string]$_.Domain -match '(?i)\.(local|lan|internal|corp|home|localdomain|localhost)$') {
                                [pscustomobject]@{ Server = $_.Domain; Status = 'Skipped'; Evidence = 'Non-internet-routable domain — SMTP DANE check not applicable.' }
                            }
                            else {
                                $noPublicMx = ($null -eq $_.Dane -or $null -eq $_.Dane.MxHosts -or @($_.Dane.MxHosts).Count -eq 0)
                                $hasSpfRecords = ($null -ne $_.Spf -and ($_.Spf.PSObject.Properties.Name -contains 'Records') -and @($_.Spf.Records).Count -gt 0)
                                if ($noPublicMx -and -not $hasSpfRecords) {
                                    [pscustomobject]@{ Server = $_.Domain; Status = 'Skipped'; Evidence = 'No public MX records found — likely an internal domain; SMTP DANE check not applicable.' }
                                }
                                else {
                                    [pscustomobject]@{ Server = $_.Domain; Status = $_.Dane.Status; Evidence = [string]$_.Dane.Evidence }
                                }
                            }
                        })
                    $failed = @($domainServerResults | Where-Object { $_.Status -eq 'Fail' })
                    $unknown = @($domainServerResults | Where-Object { $_.Status -eq 'Unknown' })
                    if ($failed.Count -gt 0) {
                        $status = 'Fail'
                    }
                    elseif ($unknown.Count -gt 0) {
                        $status = 'Unknown'
                    }
                    elseif (@($domainServerResults | Where-Object { $_.Status -eq 'Pass' }).Count -gt 0) {
                        $status = 'Pass'
                    }
                    else {
                        $status = 'Skipped'
                        $evidence = 'All accepted domains are non-internet-routable — SMTP DANE check not applicable.'
                    }
                }
            }
            'EDCA-SEC-004' {
                $forestLevel = $null
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and ($CollectionData.Organization.PSObject.Properties.Name -contains 'ForestFunctionalLevel') -and $null -ne $CollectionData.Organization.ForestFunctionalLevel) {
                    $forestLevel = [int]$CollectionData.Organization.ForestFunctionalLevel
                }

                if ($null -eq $forestLevel) {
                    $status = 'Unknown'
                    $evidence = 'AD Forest functional level data unavailable.'
                }
                else {
                    $adLevelNames = @{ 0 = 'Windows 2000'; 1 = 'Windows Server 2003 Interim'; 2 = 'Windows Server 2003'; 3 = 'Windows Server 2008'; 4 = 'Windows Server 2008 R2'; 5 = 'Windows Server 2012'; 6 = 'Windows Server 2012 R2'; 7 = 'Windows Server 2016'; 8 = 'Windows Server 2019'; 9 = 'Windows Server 2022' }
                    $forestLevelName = if ($adLevelNames.ContainsKey($forestLevel)) { $adLevelNames[$forestLevel] } else { 'Level ' + $forestLevel }

                    $requiredLevel = 0
                    $srvList = @()
                    if ($CollectionData.PSObject.Properties.Name -contains 'Servers') { $srvList = @($CollectionData.Servers) }
                    foreach ($srv in $srvList) {
                        if (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and ($srv.Exchange.PSObject.Properties.Name -contains 'ProductLine')) {
                            $needed = switch ([string]$srv.Exchange.ProductLine) {
                                'Exchange2016' { 4 }
                                'Exchange2019' { 6 }
                                'ExchangeSE' { 7 }
                                default { 0 }
                            }
                            if ($needed -gt $requiredLevel) { $requiredLevel = $needed }
                        }
                    }

                    if ($requiredLevel -eq 0) {
                        $status = 'Unknown'
                        $evidence = ('AD Forest functional level is {0} (level {1}); Exchange version could not be determined, cannot verify compatibility.' -f $forestLevelName, $forestLevel)
                    }
                    elseif ($forestLevel -ge $requiredLevel) {
                        $requiredLevelName = if ($adLevelNames.ContainsKey($requiredLevel)) { $adLevelNames[$requiredLevel] } else { 'Level ' + $requiredLevel }
                        $status = 'Pass'
                        $evidence = ('Compliant — AD Forest functional level is {0} (level {1}).' -f $forestLevelName, $forestLevel)
                    }
                    else {
                        $requiredLevelName = if ($adLevelNames.ContainsKey($requiredLevel)) { $adLevelNames[$requiredLevel] } else { 'Level ' + $requiredLevel }
                        $status = 'Fail'
                        $evidence = ('AD Forest functional level is {0} (level {1}), which does not meet the minimum requirement of {2} (level {3}) for the detected Exchange version(s).' -f $forestLevelName, $forestLevel, $requiredLevelName, $requiredLevel)
                    }
                }
            }
            'EDCA-SEC-003' {
                $domainLevel = $null
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and ($CollectionData.Organization.PSObject.Properties.Name -contains 'DomainFunctionalLevel') -and $null -ne $CollectionData.Organization.DomainFunctionalLevel) {
                    $domainLevel = [int]$CollectionData.Organization.DomainFunctionalLevel
                }

                if ($null -eq $domainLevel) {
                    $status = 'Unknown'
                    $evidence = 'AD Domain functional level data unavailable.'
                }
                else {
                    $adLevelNames = @{ 0 = 'Windows 2000'; 1 = 'Windows Server 2003 Interim'; 2 = 'Windows Server 2003'; 3 = 'Windows Server 2008'; 4 = 'Windows Server 2008 R2'; 5 = 'Windows Server 2012'; 6 = 'Windows Server 2012 R2'; 7 = 'Windows Server 2016'; 8 = 'Windows Server 2019'; 9 = 'Windows Server 2022' }
                    $domainLevelName = if ($adLevelNames.ContainsKey($domainLevel)) { $adLevelNames[$domainLevel] } else { 'Level ' + $domainLevel }

                    $requiredLevel = 0
                    $srvList = @()
                    if ($CollectionData.PSObject.Properties.Name -contains 'Servers') { $srvList = @($CollectionData.Servers) }
                    foreach ($srv in $srvList) {
                        if (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and ($srv.Exchange.PSObject.Properties.Name -contains 'ProductLine')) {
                            $needed = switch ([string]$srv.Exchange.ProductLine) {
                                'Exchange2016' { 4 }
                                'Exchange2019' { 6 }
                                'ExchangeSE' { 7 }
                                default { 0 }
                            }
                            if ($needed -gt $requiredLevel) { $requiredLevel = $needed }
                        }
                    }

                    if ($requiredLevel -eq 0) {
                        $status = 'Unknown'
                        $evidence = ('AD Domain functional level is {0} (level {1}); Exchange version could not be determined, cannot verify compatibility.' -f $domainLevelName, $domainLevel)
                    }
                    elseif ($domainLevel -ge $requiredLevel) {
                        $requiredLevelName = if ($adLevelNames.ContainsKey($requiredLevel)) { $adLevelNames[$requiredLevel] } else { 'Level ' + $requiredLevel }
                        $status = 'Pass'
                        $evidence = ('Compliant — AD Domain functional level is {0} (level {1}).' -f $domainLevelName, $domainLevel)
                    }
                    else {
                        $requiredLevelName = if ($adLevelNames.ContainsKey($requiredLevel)) { $adLevelNames[$requiredLevel] } else { 'Level ' + $requiredLevel }
                        $status = 'Fail'
                        $evidence = ('AD Domain functional level is {0} (level {1}), which does not meet the minimum requirement of {2} (level {3}) for the detected Exchange version(s).' -f $domainLevelName, $domainLevel, $requiredLevelName, $requiredLevel)
                    }
                }
            }
            'EDCA-SEC-005' {
                $adSiteCount = $null
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and ($CollectionData.Organization.PSObject.Properties.Name -contains 'AdSiteCount') -and $null -ne $CollectionData.Organization.AdSiteCount) {
                    $adSiteCount = [int]$CollectionData.Organization.AdSiteCount
                }

                if ($null -eq $adSiteCount) {
                    $status = 'Unknown'
                    $evidence = 'AD site count data unavailable.'
                }
                elseif ($adSiteCount -ge 1000) {
                    $status = 'Fail'
                    $evidence = ('Total AD site count is {0}. Very large AD site counts are an Exchange performance risk.' -f $adSiteCount)
                }
                elseif ($adSiteCount -ge 750) {
                    $status = 'Unknown'
                    $evidence = ('Total AD site count is {0}. This is a warning-level threshold for larger environments.' -f $adSiteCount)
                }
                else {
                    $status = 'Pass'
                    $evidence = ('Compliant — AD site count is {0}, below the warning threshold.' -f $adSiteCount)
                }
            }
            'EDCA-TLS-003' {
                $allSendConnectors = @()
                $serverList = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Servers') -and $null -ne $CollectionData.Servers) {
                    $serverList = @($CollectionData.Servers)
                }

                foreach ($serverEntry in $serverList) {
                    if (($serverEntry.PSObject.Properties.Name -contains 'CollectionError') -and -not [string]::IsNullOrWhiteSpace([string]$serverEntry.CollectionError)) {
                        continue
                    }

                    $isExchangeServer = (
                        ($serverEntry.PSObject.Properties.Name -contains 'Exchange') -and
                        $null -ne $serverEntry.Exchange -and
                        ($serverEntry.Exchange.PSObject.Properties.Name -contains 'IsExchangeServer') -and
                        [bool]$serverEntry.Exchange.IsExchangeServer
                    )

                    if (-not $isExchangeServer) {
                        continue
                    }

                    if (($serverEntry.Exchange.PSObject.Properties.Name -contains 'SendConnectors') -and $null -ne $serverEntry.Exchange.SendConnectors) {
                        $allSendConnectors += @($serverEntry.Exchange.SendConnectors)
                    }
                }

                if ($allSendConnectors.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Send connector telemetry unavailable.'
                }
                else {
                    $connectorByIdentity = @{}
                    foreach ($connector in $allSendConnectors) {
                        $cId = [string]$connector.Identity
                        if ([string]::IsNullOrWhiteSpace($cId)) { continue }
                        if (-not $connectorByIdentity.ContainsKey($cId)) {
                            $connectorByIdentity[$cId] = $connector
                        }
                    }

                    $dedupedConnectors = @($connectorByIdentity.Values)
                    $hybridConnectors = @($dedupedConnectors | Where-Object {
                            ($_.CloudServicesMailEnabled -eq $true) -or
                            (@($_.SmartHosts | Where-Object { [string]$_ -match 'mail\.protection\.outlook\.com' }).Count -gt 0)
                        })

                    if ($hybridConnectors.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = 'No hybrid/EXO-targeted send connectors detected.'
                    }
                    else {
                        $domainServerResults = @($hybridConnectors | ForEach-Object {
                                $connIssues = @()
                                $evLines = @()

                                $requireTls = if ($_.PSObject.Properties.Name -contains 'RequireTLS') { $_.RequireTLS } else { $null }
                                $tlsAuthLevel = if ($_.PSObject.Properties.Name -contains 'TlsAuthLevel') { [string]$_.TlsAuthLevel } else { $null }
                                $tlsDomain = if ($_.PSObject.Properties.Name -contains 'TlsDomain') { [string]$_.TlsDomain } else { $null }
                                $tlsCertName = if ($_.PSObject.Properties.Name -contains 'TlsCertificateName') { [string]$_.TlsCertificateName } else { $null }
                                $certSyntaxValid = if ($_.PSObject.Properties.Name -contains 'TlsCertificateSyntaxValid') { $_.TlsCertificateSyntaxValid } else { $null }

                                # RequireTLS must be True
                                if ($null -eq $requireTls) {
                                    $connIssues += 'RequireTLS: unknown'
                                }
                                elseif ($requireTls -ne $true) {
                                    $connIssues += 'RequireTLS: False (must be True)'
                                }
                                $evLines += ('RequireTLS: {0}' -f $(if ($null -eq $requireTls) { 'unknown' } else { [string]$requireTls }))

                                # TlsAuthLevel must be DomainValidation
                                if ([string]::IsNullOrWhiteSpace($tlsAuthLevel)) {
                                    $connIssues += 'TlsAuthLevel: not set (must be DomainValidation)'
                                }
                                elseif ($tlsAuthLevel -ne 'DomainValidation') {
                                    $connIssues += ('TlsAuthLevel: {0} (must be DomainValidation)' -f $tlsAuthLevel)
                                }
                                $evLines += ('TlsAuthLevel: {0}' -f $(if ([string]::IsNullOrWhiteSpace($tlsAuthLevel)) { 'not set' } else { $tlsAuthLevel }))

                                # TlsDomain must point to mail.protection.outlook.com
                                $tlsDomainOk = (-not [string]::IsNullOrWhiteSpace($tlsDomain)) -and ($tlsDomain -match '(?i)(^|\*\.)mail\.protection\.outlook\.com\.?$')
                                if ([string]::IsNullOrWhiteSpace($tlsDomain)) {
                                    $connIssues += 'TlsDomain: not set (must be mail.protection.outlook.com)'
                                }
                                elseif (-not $tlsDomainOk) {
                                    $connIssues += ('TlsDomain: {0} (expected mail.protection.outlook.com)' -f $tlsDomain)
                                }
                                $evLines += ('TlsDomain: {0}' -f $(if ([string]::IsNullOrWhiteSpace($tlsDomain)) { 'not set' } else { $tlsDomain }))

                                # TlsCertificateName must be set and have valid <I>...<S>... syntax
                                if ([string]::IsNullOrWhiteSpace($tlsCertName)) {
                                    $connIssues += 'TlsCertificateName: not set'
                                }
                                elseif ($certSyntaxValid -eq $false) {
                                    $connIssues += ('TlsCertificateName: invalid syntax — {0}' -f $tlsCertName)
                                }
                                $evLines += ('TlsCertificateName: {0}' -f $(if ([string]::IsNullOrWhiteSpace($tlsCertName)) { 'not set' } else { $tlsCertName }))

                                $itemStatus = if ($connIssues.Count -eq 0) { 'Pass' } else { 'Fail' }
                                if ($connIssues.Count -gt 0) { $evLines += ('Issues: ' + ($connIssues -join '; ')) }
                                [pscustomobject]@{
                                    Server   = [string]$_.Identity
                                    Status   = $itemStatus
                                    Evidence = $evLines -join "`n"
                                }
                            })

                        $subjectLabel = 'Connector'
                        $failCount = @($domainServerResults | Where-Object { $_.Status -eq 'Fail' }).Count
                        $unknownCount = @($domainServerResults | Where-Object { $_.Status -eq 'Unknown' }).Count
                        if ($failCount -gt 0) {
                            $status = 'Fail'
                        }
                        elseif ($unknownCount -gt 0) {
                            $status = 'Unknown'
                        }
                        else {
                            $status = 'Pass'
                        }
                    }
                }
            }
            'EDCA-TLS-029' {
                $allReceiveConnectors = @()
                $serverList = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Servers') -and $null -ne $CollectionData.Servers) {
                    $serverList = @($CollectionData.Servers)
                }

                foreach ($serverEntry in $serverList) {
                    if (($serverEntry.PSObject.Properties.Name -contains 'CollectionError') -and -not [string]::IsNullOrWhiteSpace([string]$serverEntry.CollectionError)) {
                        continue
                    }

                    $isExchangeServer = (
                        ($serverEntry.PSObject.Properties.Name -contains 'Exchange') -and
                        $null -ne $serverEntry.Exchange -and
                        ($serverEntry.Exchange.PSObject.Properties.Name -contains 'IsExchangeServer') -and
                        [bool]$serverEntry.Exchange.IsExchangeServer
                    )

                    if (-not $isExchangeServer) {
                        continue
                    }

                    if (($serverEntry.Exchange.PSObject.Properties.Name -contains 'ReceiveConnectors') -and $null -ne $serverEntry.Exchange.ReceiveConnectors) {
                        $allReceiveConnectors += @($serverEntry.Exchange.ReceiveConnectors)
                    }
                }

                if ($allReceiveConnectors.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Receive connector telemetry unavailable.'
                }
                else {
                    $connectorByIdentity = @{}
                    foreach ($connector in $allReceiveConnectors) {
                        $cId = [string]$connector.Identity
                        if ([string]::IsNullOrWhiteSpace($cId)) { continue }
                        if (-not $connectorByIdentity.ContainsKey($cId)) {
                            $connectorByIdentity[$cId] = $connector
                        }
                    }

                    $dedupedConnectors = @($connectorByIdentity.Values)
                    $hybridRcvConnectors = @($dedupedConnectors | Where-Object {
                            ($_.PSObject.Properties.Name -contains 'TransportRole') -and
                            ([string]$_.TransportRole -eq 'FrontendTransport') -and
                            ($_.PSObject.Properties.Name -contains 'TlsDomainCapabilities') -and
                            -not [string]::IsNullOrWhiteSpace([string]$_.TlsDomainCapabilities)
                        })

                    if ($hybridRcvConnectors.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = 'No frontend receive connectors with TlsDomainCapabilities detected — hybrid receive connector may not be present or telemetry is incomplete.'
                    }
                    else {
                        $domainServerResults = @($hybridRcvConnectors | ForEach-Object {
                                $connIssues = @()
                                $evLines = @()

                                $enabled = if ($_.PSObject.Properties.Name -contains 'Enabled') { $_.Enabled } else { $null }
                                $authMechanism = if ($_.PSObject.Properties.Name -contains 'AuthMechanism') { [string]$_.AuthMechanism } else { $null }
                                $tlsDomainCaps = if ($_.PSObject.Properties.Name -contains 'TlsDomainCapabilities') { [string]$_.TlsDomainCapabilities } else { $null }

                                # Connector must be enabled
                                if ($null -eq $enabled) {
                                    $connIssues += 'Enabled: unknown'
                                }
                                elseif ($enabled -ne $true) {
                                    $connIssues += 'Enabled: False (connector must be enabled)'
                                }
                                $evLines += ('Enabled: {0}' -f $(if ($null -eq $enabled) { 'unknown' } else { [string]$enabled }))

                                # TlsDomainCapabilities must contain AcceptCloudServicesMail or AcceptOorgProtocol for mail.protection.outlook.com
                                $oorgOk = (-not [string]::IsNullOrWhiteSpace($tlsDomainCaps)) -and
                                ($tlsDomainCaps -match '(?i)mail\.protection\.outlook\.com\s*:\s*(?:AcceptCloudServicesMail|AcceptOorgProtocol)')
                                if ([string]::IsNullOrWhiteSpace($tlsDomainCaps)) {
                                    $connIssues += 'TlsDomainCapabilities: not set (must include mail.protection.outlook.com:AcceptCloudServicesMail or AcceptOorgProtocol)'
                                }
                                elseif (-not $oorgOk) {
                                    $connIssues += ('TlsDomainCapabilities: AcceptCloudServicesMail/AcceptOorgProtocol for mail.protection.outlook.com not found — {0}' -f $tlsDomainCaps)
                                }
                                $evLines += ('TlsDomainCapabilities: {0}' -f $(if ([string]::IsNullOrWhiteSpace($tlsDomainCaps)) { 'not set' } else { $tlsDomainCaps }))

                                # AuthMechanism must include Tls
                                $tlsInAuth = (-not [string]::IsNullOrWhiteSpace($authMechanism)) -and ($authMechanism -match '(?i)\bTls\b')
                                if ([string]::IsNullOrWhiteSpace($authMechanism)) {
                                    $connIssues += 'AuthMechanism: not set (must include Tls)'
                                }
                                elseif (-not $tlsInAuth) {
                                    $connIssues += ('AuthMechanism: Tls not present — {0}' -f $authMechanism)
                                }
                                $evLines += ('AuthMechanism: {0}' -f $(if ([string]::IsNullOrWhiteSpace($authMechanism)) { 'not set' } else { $authMechanism }))

                                $itemStatus = if ($connIssues.Count -eq 0) { 'Pass' } else { 'Fail' }
                                if ($connIssues.Count -gt 0) { $evLines += ('Issues: ' + ($connIssues -join '; ')) }
                                [pscustomobject]@{
                                    Server   = [string]$_.Identity
                                    Status   = $itemStatus
                                    Evidence = $evLines -join "`n"
                                }
                            })

                        $subjectLabel = 'Connector'
                        $failCount = @($domainServerResults | Where-Object { $_.Status -eq 'Fail' }).Count
                        $unknownCount = @($domainServerResults | Where-Object { $_.Status -eq 'Unknown' }).Count
                        if ($failCount -gt 0) {
                            $status = 'Fail'
                        }
                        elseif ($unknownCount -gt 0) {
                            $status = 'Unknown'
                        }
                        else {
                            $status = 'Pass'
                        }
                    }
                }
            }
            'EDCA-IAC-011' {
                $hybridApplication = $null
                foreach ($srv in $CollectionData.Servers) {
                    if ($srv.PSObject.Properties.Name -contains 'CollectionError') { continue }
                    if (-not (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and ($srv.Exchange.PSObject.Properties.Name -contains 'HybridApplication'))) { continue }
                    if ($null -eq $srv.Exchange.HybridApplication) { continue }
                    $hybridApplication = $srv.Exchange.HybridApplication
                    break
                }

                if ($null -eq $hybridApplication) {
                    $status = 'Unknown'
                    $evidence = 'Hybrid application telemetry unavailable.'
                }
                elseif ($hybridApplication.PSObject.Properties.Name -contains 'Configured' -and (-not [bool]$hybridApplication.Configured)) {
                    $status = 'Pass'
                    $evidence = 'Hybrid configuration not detected; dedicated hybrid app baseline is not applicable.'
                }
                elseif (-not ($hybridApplication.PSObject.Properties.Name -contains 'DedicatedHybridAppConfigured')) {
                    $status = 'Unknown'
                    $evidence = 'Dedicated hybrid app telemetry unavailable.'
                }
                else {
                    $dedicatedHybridAppConfigured = [bool]$hybridApplication.DedicatedHybridAppConfigured

                    $overrideCount = -1
                    if (($hybridApplication.PSObject.Properties.Name -contains 'DedicatedHybridAppOverrideCount') -and $null -ne $hybridApplication.DedicatedHybridAppOverrideCount) {
                        $overrideCount = [int]$hybridApplication.DedicatedHybridAppOverrideCount
                    }

                    $dedicatedAuthServerCount = -1
                    if (($hybridApplication.PSObject.Properties.Name -contains 'DedicatedHybridAppAuthServerCount') -and $null -ne $hybridApplication.DedicatedHybridAppAuthServerCount) {
                        $dedicatedAuthServerCount = [int]$hybridApplication.DedicatedHybridAppAuthServerCount
                    }

                    $sharedAppAuthServerCount = -1
                    if (($hybridApplication.PSObject.Properties.Name -contains 'SharedExchangeOnlineAppAuthServerCount') -and $null -ne $hybridApplication.SharedExchangeOnlineAppAuthServerCount) {
                        $sharedAppAuthServerCount = [int]$hybridApplication.SharedExchangeOnlineAppAuthServerCount
                    }

                    $status = if ($dedicatedHybridAppConfigured) { 'Pass' } else { 'Fail' }
                    $summary = ('Dedicated hybrid app configured: {0}; override count: {1}; dedicated-app auth server count: {2}; shared-app auth server count: {3}.' -f $dedicatedHybridAppConfigured, $overrideCount, $dedicatedAuthServerCount, $sharedAppAuthServerCount)

                    if (($hybridApplication.PSObject.Properties.Name -contains 'Details') -and -not [string]::IsNullOrWhiteSpace([string]$hybridApplication.Details)) {
                        $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements @([string]$hybridApplication.Details)
                    }
                    else {
                        $evidence = $summary
                    }
                }
            }
            'EDCA-GOV-004' {
                $hybridApplication = $null
                foreach ($srv in $CollectionData.Servers) {
                    if ($srv.PSObject.Properties.Name -contains 'CollectionError') { continue }
                    if (-not (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and ($srv.Exchange.PSObject.Properties.Name -contains 'HybridApplication'))) { continue }
                    if ($null -eq $srv.Exchange.HybridApplication) { continue }
                    $hybridApplication = $srv.Exchange.HybridApplication
                    break
                }

                if ($null -eq $hybridApplication) {
                    $status = 'Unknown'
                    $evidence = 'Hybrid application telemetry unavailable.'
                }
                elseif ($hybridApplication.PSObject.Properties.Name -contains 'Configured' -and $hybridApplication.Configured -eq $true) {
                    $status = 'Pass'
                    $evidence = [string]$hybridApplication.Details
                }
                elseif ($hybridApplication.PSObject.Properties.Name -contains 'Configured' -and $hybridApplication.Configured -eq $false) {
                    $status = 'Fail'
                    $evidence = [string]$hybridApplication.Details
                }
                else {
                    $status = 'Unknown'
                    $evidence = if (($hybridApplication.PSObject.Properties.Name -contains 'Details') -and -not [string]::IsNullOrWhiteSpace([string]$hybridApplication.Details)) { [string]$hybridApplication.Details } else { 'Hybrid application state unavailable.' }
                }
            }
            'EDCA-IAC-010' {
                $clientAccessRules = $null
                $nonAdminPsUsers = $null
                $nonAdminPsCount = $null

                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization) {
                    if ($CollectionData.Organization.PSObject.Properties.Name -contains 'ClientAccessRules') {
                        $clientAccessRules = $CollectionData.Organization.ClientAccessRules
                    }
                    if ($CollectionData.Organization.PSObject.Properties.Name -contains 'NonAdminRemotePowerShellUsers') {
                        $nonAdminPsUsers = $CollectionData.Organization.NonAdminRemotePowerShellUsers
                    }
                    if (($CollectionData.Organization.PSObject.Properties.Name -contains 'NonAdminRemotePowerShellCountTotal') -and $null -ne $CollectionData.Organization.NonAdminRemotePowerShellCountTotal) {
                        $nonAdminPsCount = [int]$CollectionData.Organization.NonAdminRemotePowerShellCountTotal
                    }
                }

                if ($null -eq $clientAccessRules -and $null -eq $nonAdminPsCount) {
                    $status = 'Unknown'
                    $evidence = 'Client Access Rule and remote PowerShell user data unavailable. Collection may not have run against a Mailbox server.'
                }
                else {
                    # Sub-check 1: Client Access Rules
                    $carStatus = $null
                    $carEvidence = $null

                    if ($null -eq $clientAccessRules) {
                        $carStatus = 'Unknown'
                        $carEvidence = 'Client Access Rule data unavailable.'
                    }
                    elseif ($clientAccessRules.Count -eq 0) {
                        $carStatus = 'Fail'
                        $carEvidence = 'No Client Access Rules are configured. Access to the Exchange Admin Center and remote PowerShell is unrestricted by rule.'
                    }
                    else {
                        $mgmtProtocols = @('RemotePowerShell', 'ExchangeAdminCenter')
                        $enabledRules = @($clientAccessRules | Where-Object { $null -eq $_.Enabled -or [bool]$_.Enabled })
                        $psRules = @($enabledRules | Where-Object {
                                $protocols = @($_.AnyOfProtocols)
                                ($protocols | Where-Object { $_ -in $mgmtProtocols }).Count -gt 0
                            })
                        if ($psRules.Count -eq 0) {
                            $ruleNames = @($enabledRules | ForEach-Object { [string]$_.Name })
                            $carStatus = 'Fail'
                            $carEvidence = Format-EDCAEvidenceWithElements -Summary ('{0} Client Access Rule(s) configured but none restrict RemotePowerShell or ExchangeAdminCenter access:' -f $enabledRules.Count) -Elements $ruleNames
                        }
                        else {
                            $ruleDetails = @($psRules | ForEach-Object { '{0} (Action: {1}, Priority: {2})' -f [string]$_.Name, [string]$_.Action, [string]$_.Priority })
                            $carStatus = 'Pass'
                            $carEvidence = Format-EDCAEvidenceWithElements -Summary ('{0} Client Access Rule(s) restrict EAC/remote PowerShell access:' -f $psRules.Count) -Elements $ruleDetails
                        }
                    }

                    # Sub-check 2: non-Exchange-admin users with RemotePowerShellEnabled
                    $psStatus = $null
                    $psEvidence = $null

                    if ($null -eq $nonAdminPsCount) {
                        $psStatus = 'Unknown'
                        $psEvidence = 'Non-Exchange-admin remote PowerShell user data unavailable.'
                    }
                    elseif ($nonAdminPsCount -eq 0) {
                        $psStatus = 'Pass'
                        $psEvidence = 'No non-Exchange-admin users have RemotePowerShellEnabled set to $true.'
                    }
                    else {
                        $userDetails = @($nonAdminPsUsers | ForEach-Object {
                                $typeDetail = [string]$_.RecipientTypeDetails
                                if (-not [string]::IsNullOrWhiteSpace($typeDetail)) { '{0} ({1})' -f [string]$_.Name, $typeDetail }
                                else { [string]$_.Name }
                            })
                        $psStatus = 'Fail'
                        $psEvidence = Format-EDCAEvidenceWithElements -Summary ('{0} non-Exchange-admin user(s) have RemotePowerShellEnabled set to $true:' -f $nonAdminPsCount) -Elements $userDetails
                    }

                    # Combine sub-check statuses
                    $subStatuses = @($carStatus, $psStatus) | Where-Object { $null -ne $_ }
                    if ($subStatuses -contains 'Fail') { $status = 'Fail' }
                    elseif ($subStatuses -contains 'Unknown') { $status = 'Unknown' }
                    else { $status = 'Pass' }

                    $evidenceParts = @()
                    if (-not [string]::IsNullOrWhiteSpace($carEvidence)) { $evidenceParts += 'Client Access Rules: ' + $carEvidence }
                    if (-not [string]::IsNullOrWhiteSpace($psEvidence)) { $evidenceParts += 'Remote PowerShell access: ' + $psEvidence }
                    $evidence = $evidenceParts -join "`n"
                }
            }
            'EDCA-IAC-009' {
                $basicAuthState = $null
                $policyName = $null
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization) {
                    if (($CollectionData.Organization.PSObject.Properties.Name -contains 'DefaultAuthPolicyBasicAuth') -and $null -ne $CollectionData.Organization.DefaultAuthPolicyBasicAuth) {
                        $basicAuthState = $CollectionData.Organization.DefaultAuthPolicyBasicAuth
                    }
                    if (($CollectionData.Organization.PSObject.Properties.Name -contains 'DefaultAuthPolicyName') -and -not [string]::IsNullOrWhiteSpace([string]$CollectionData.Organization.DefaultAuthPolicyName)) {
                        $policyName = [string]$CollectionData.Organization.DefaultAuthPolicyName
                    }
                }

                if ($null -eq $basicAuthState) {
                    $status = 'Unknown'
                    $evidence = 'Default authentication policy data unavailable. Either no authentication policy is configured, collection ran against an Edge Transport server only, or data collection failed.'
                }
                else {
                    $basicAuthPropNames = @('AllowBasicAuthActiveSync', 'AllowBasicAuthAutodiscover', 'AllowBasicAuthImap', 'AllowBasicAuthMapi', 'AllowBasicAuthOfflineAddressBook', 'AllowBasicAuthOutlookService', 'AllowBasicAuthPop', 'AllowBasicAuthReportingWebServices', 'AllowBasicAuthRest', 'AllowBasicAuthRpc', 'AllowBasicAuthSmtp', 'AllowBasicAuthWebServices', 'AllowBasicAuthWindowsLiveId')
                    $allowedProtocols = @()
                    foreach ($prop in $basicAuthPropNames) {
                        if (($basicAuthState.PSObject.Properties.Name -contains $prop) -and ([bool]$basicAuthState.$prop -eq $true)) {
                            $allowedProtocols += ($prop -replace '^AllowBasicAuth', '')
                        }
                    }

                    $policyLabel = if (-not [string]::IsNullOrWhiteSpace($policyName)) { ('Policy: {0}' -f $policyName) } else { 'Default authentication policy' }
                    if ($allowedProtocols.Count -eq 0) {
                        $status = 'Pass'
                        $evidence = ('{0}: Basic Authentication is blocked for all {1} tracked protocol(s).' -f $policyLabel, $basicAuthPropNames.Count)
                    }
                    else {
                        $status = 'Unknown'
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0}: Basic Authentication is still permitted for {1} of {2} tracked protocol(s):' -f $policyLabel, $allowedProtocols.Count, $basicAuthPropNames.Count) -Elements $allowedProtocols
                    }
                }
            }
            'EDCA-TLS-004' {
                $remoteDomains = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'RemoteDomains')) {
                    $remoteDomains = @($CollectionData.Organization.RemoteDomains)
                }
                if ($remoteDomains.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Remote domain configuration data unavailable.'
                }
                else {
                    # Exclude onmicrosoft.com remote domains — AutoForwardEnabled=True on these is expected for hybrid/EXO coexistence.
                    $applicableDomains = @($remoteDomains | Where-Object { [string]$_.DomainName -notmatch '\.onmicrosoft\.com$' })
                    $nonCompliant = @($applicableDomains | Where-Object { $null -ne $_.AutoForwardEnabled -and [bool]$_.AutoForwardEnabled -eq $true })
                    if ($nonCompliant.Count -gt 0) {
                        $status = 'Fail'
                        $details = @($nonCompliant | ForEach-Object { '{0} ({1}): AutoForwardEnabled=True' -f [string]$_.Name, [string]$_.DomainName })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} remote domain(s) have AutoForwardEnabled set to True.' -f $nonCompliant.Count) -Elements $details
                    }
                    else {
                        $excluded = $remoteDomains.Count - $applicableDomains.Count
                        $suffix = if ($excluded -gt 0) { (' ({0} onmicrosoft.com domain(s) excluded from check).' -f $excluded) } else { '.' }
                        $status = 'Pass'
                        $evidence = ('All {0} applicable remote domain(s) have AutoForwardEnabled set to False{1}' -f $applicableDomains.Count, $suffix)
                    }
                }
            }
            'EDCA-TLS-005' {
                $remoteDomains = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'RemoteDomains')) {
                    $remoteDomains = @($CollectionData.Organization.RemoteDomains)
                }
                if ($remoteDomains.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Remote domain configuration data unavailable.'
                }
                else {
                    # Exclude onmicrosoft.com remote domains — AutoReplyEnabled=True on these is expected for hybrid/EXO coexistence.
                    $applicableDomains = @($remoteDomains | Where-Object { [string]$_.DomainName -notmatch '\.onmicrosoft\.com$' })
                    $nonCompliant = @($applicableDomains | Where-Object { $null -ne $_.AutoReplyEnabled -and [bool]$_.AutoReplyEnabled -eq $true })
                    if ($nonCompliant.Count -gt 0) {
                        $status = 'Fail'
                        $details = @($nonCompliant | ForEach-Object { '{0} ({1}): AutoReplyEnabled=True' -f [string]$_.Name, [string]$_.DomainName })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} remote domain(s) have AutoReplyEnabled set to True.' -f $nonCompliant.Count) -Elements $details
                    }
                    else {
                        $excluded = $remoteDomains.Count - $applicableDomains.Count
                        $suffix = if ($excluded -gt 0) { (' ({0} onmicrosoft.com domain(s) excluded from check).' -f $excluded) } else { '.' }
                        $status = 'Pass'
                        $evidence = ('All {0} applicable remote domain(s) have AutoReplyEnabled set to False{1}' -f $applicableDomains.Count, $suffix)
                    }
                }
            }
            'EDCA-TLS-006' {
                $subjectLabel = 'Domain'
                $remoteDomains = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'RemoteDomains')) {
                    $remoteDomains = @($CollectionData.Organization.RemoteDomains)
                }
                if ($remoteDomains.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Remote domain configuration data unavailable.'
                }
                else {
                    $domainServerResults = @($remoteDomains | ForEach-Object {
                            $rdName = [string]$_.Name
                            $rdDomain = if ($_.PSObject.Properties.Name -contains 'DomainName') { [string]$_.DomainName } else { '' }
                            $rdDisplay = if ([string]::IsNullOrWhiteSpace($rdDomain)) { $rdName } else { '{0} ({1})' -f $rdName, $rdDomain }
                            $isOnMicrosoft = [string]$rdDomain -match '\.onmicrosoft\.com$'
                            $ndrEnabled = if ($_.PSObject.Properties.Name -contains 'NDREnabled') { $_.NDREnabled } else { $null }
                            if ($isOnMicrosoft) {
                                [pscustomobject]@{ Server = $rdDisplay; Status = 'Skipped'; Evidence = 'onmicrosoft.com domain — NDREnabled=True is expected for hybrid/EXO coexistence.' }
                            }
                            elseif ($null -eq $ndrEnabled) {
                                [pscustomobject]@{ Server = $rdDisplay; Status = 'Unknown'; Evidence = 'NDREnabled data not available.' }
                            }
                            elseif ([bool]$ndrEnabled -eq $true) {
                                [pscustomobject]@{ Server = $rdDisplay; Status = 'Fail'; Evidence = 'NDREnabled: True (expected False).' }
                            }
                            else {
                                [pscustomobject]@{ Server = $rdDisplay; Status = 'Pass'; Evidence = 'NDREnabled: False.' }
                            }
                        })
                    $failCount = @($domainServerResults | Where-Object { $_.Status -eq 'Fail' }).Count
                    $unknownCount = @($domainServerResults | Where-Object { $_.Status -eq 'Unknown' }).Count
                    if ($failCount -gt 0) {
                        $status = 'Fail'
                    }
                    elseif ($unknownCount -gt 0) {
                        $status = 'Unknown'
                    }
                    elseif (@($domainServerResults | Where-Object { $_.Status -eq 'Pass' }).Count -gt 0) {
                        $status = 'Pass'
                    }
                    else {
                        $status = 'Skipped'
                        $evidence = 'All remote domains are onmicrosoft.com — NDR check not applicable.'
                    }
                }
            }
            'EDCA-TLS-007' {
                $subjectLabel = 'Domain'
                $remoteDomains = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'RemoteDomains')) {
                    $remoteDomains = @($CollectionData.Organization.RemoteDomains)
                }
                if ($remoteDomains.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Remote domain configuration data unavailable.'
                }
                else {
                    $domainServerResults = @($remoteDomains | ForEach-Object {
                            $rdName = [string]$_.Name
                            $rdDomain = if ($_.PSObject.Properties.Name -contains 'DomainName') { [string]$_.DomainName } else { '' }
                            $rdOofType = if ($_.PSObject.Properties.Name -contains 'AllowedOOFType') { $_.AllowedOOFType } else { $null }
                            $rdDisplay = if ([string]::IsNullOrWhiteSpace($rdDomain)) { $rdName } else { '{0} ({1})' -f $rdName, $rdDomain }
                            $isOnMicrosoft = [string]$rdDomain -match '\.onmicrosoft\.com$'

                            if ($isOnMicrosoft) {
                                $oofDisplay = if ($null -ne $rdOofType) { [string]$rdOofType } else { 'unknown' }
                                [pscustomobject]@{ Server = $rdDisplay; Status = 'Pass'; Evidence = ('AllowedOOFType: {0} — onmicrosoft.com domain; OOF to Exchange Online is acceptable in hybrid deployments.' -f $oofDisplay) }
                            }
                            elseif ($null -eq $rdOofType) {
                                [pscustomobject]@{ Server = $rdDisplay; Status = 'Unknown'; Evidence = 'AllowedOOFType data not available.' }
                            }
                            elseif ([string]$rdOofType -eq 'None') {
                                [pscustomobject]@{ Server = $rdDisplay; Status = 'Pass'; Evidence = 'AllowedOOFType: None.' }
                            }
                            else {
                                [pscustomobject]@{ Server = $rdDisplay; Status = 'Fail'; Evidence = ('AllowedOOFType: {0} (expected None).' -f [string]$rdOofType) }
                            }
                        })

                    $failCount = @($domainServerResults | Where-Object { $_.Status -eq 'Fail' }).Count
                    $unknownCount = @($domainServerResults | Where-Object { $_.Status -eq 'Unknown' }).Count
                    if ($failCount -gt 0) {
                        $status = 'Fail'
                    }
                    elseif ($unknownCount -gt 0) {
                        $status = 'Unknown'
                    }
                    else {
                        $status = 'Pass'
                    }
                }
            }
            'EDCA-TLS-008' {
                $transportConfig = $null
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'TransportConfig')) {
                    $transportConfig = $CollectionData.Organization.TransportConfig
                }
                if ($null -eq $transportConfig) {
                    $status = 'Unknown'
                    $evidence = 'Transport configuration data unavailable.'
                }
                else {
                    $maxSendBytes = if ($transportConfig.PSObject.Properties.Name -contains 'MaxSendSizeBytes' -and $null -ne $transportConfig.MaxSendSizeBytes) { [long]$transportConfig.MaxSendSizeBytes } else { $null }
                    $maxSendDisplay = if ($transportConfig.PSObject.Properties.Name -contains 'MaxSendSizeDisplay' -and $null -ne $transportConfig.MaxSendSizeDisplay) { [string]$transportConfig.MaxSendSizeDisplay } else { 'unknown' }
                    if ($null -eq $maxSendBytes) {
                        $status = 'Unknown'
                        $evidence = 'MaxSendSize data unavailable.'
                    }
                    else {
                        $limit = 26214400 # 25 MB in bytes
                        $status = if ($maxSendBytes -le $limit) { 'Pass' } else { 'Fail' }
                        $evidence = ('MaxSendSize is {0} ({1} bytes).' -f $maxSendDisplay, $maxSendBytes)
                    }
                }
            }
            'EDCA-TLS-009' {
                $transportConfig = $null
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'TransportConfig')) {
                    $transportConfig = $CollectionData.Organization.TransportConfig
                }
                if ($null -eq $transportConfig) {
                    $status = 'Unknown'
                    $evidence = 'Transport configuration data unavailable.'
                }
                else {
                    $maxReceiveBytes = if ($transportConfig.PSObject.Properties.Name -contains 'MaxReceiveSizeBytes' -and $null -ne $transportConfig.MaxReceiveSizeBytes) { [long]$transportConfig.MaxReceiveSizeBytes } else { $null }
                    $maxReceiveDisplay = if ($transportConfig.PSObject.Properties.Name -contains 'MaxReceiveSizeDisplay' -and $null -ne $transportConfig.MaxReceiveSizeDisplay) { [string]$transportConfig.MaxReceiveSizeDisplay } else { 'unknown' }
                    if ($null -eq $maxReceiveBytes) {
                        $status = 'Unknown'
                        $evidence = 'MaxReceiveSize data unavailable.'
                    }
                    else {
                        $limit = 26214400 # 25 MB in bytes
                        $status = if ($maxReceiveBytes -le $limit) { 'Pass' } else { 'Fail' }
                        $evidence = ('MaxReceiveSize is {0} ({1} bytes).' -f $maxReceiveDisplay, $maxReceiveBytes)
                    }
                }
            }
            'EDCA-TLS-010' {
                $subjectLabel = 'Connector'
                $allConnectors = @{}
                foreach ($srv in @($CollectionData.Servers)) {
                    if (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and
                        ($srv.Exchange.PSObject.Properties.Name -contains 'SendConnectors')) {
                        foreach ($c in @($srv.Exchange.SendConnectors)) {
                            $cId = [string]$c.Identity
                            if (-not $allConnectors.ContainsKey($cId)) {
                                $allConnectors[$cId] = $c
                            }
                        }
                    }
                }
                $externalConnectors = @($allConnectors.Values | Where-Object {
                        $spaces = @($_.AddressSpaces)
                        (@($spaces | Where-Object { [string]$_ -match '\*' })).Count -gt 0
                    })
                if ($allConnectors.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Send connector data unavailable.'
                }
                elseif ($externalConnectors.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No external send connector (address space containing *) found.'
                }
                else {
                    $domainServerResults = @($externalConnectors | ForEach-Object {
                            $dnsEnabled = if ($_.PSObject.Properties.Name -contains 'DNSRoutingEnabled' -and $null -ne $_.DNSRoutingEnabled) { [bool]$_.DNSRoutingEnabled } else { $null }
                            $itemStatus = if ($dnsEnabled -eq $true) { 'Pass' } elseif ($null -eq $dnsEnabled) { 'Unknown' } else { 'Fail' }
                            $dnsDisplay = if ($dnsEnabled -eq $true) { 'enabled' } elseif ($dnsEnabled -eq $false) { 'disabled' } else { 'unknown' }
                            $smartHostList = @($_.SmartHosts | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
                            $connEvidence = 'DNS routing: {0}.' -f $dnsDisplay
                            if ($dnsEnabled -eq $false -and $smartHostList.Count -gt 0) {
                                $connEvidence += (' Smart hosts: {0}.' -f ($smartHostList -join ', '))
                            }
                            [pscustomobject]@{
                                Server   = [string]$_.Identity
                                Status   = $itemStatus
                                Evidence = $connEvidence
                            }
                        })
                    $failCount = @($domainServerResults | Where-Object { $_.Status -eq 'Fail' }).Count
                    $unknownCount = @($domainServerResults | Where-Object { $_.Status -eq 'Unknown' }).Count
                    if ($failCount -gt 0) {
                        $status = 'Fail'
                    }
                    elseif ($unknownCount -gt 0) {
                        $status = 'Unknown'
                    }
                    else {
                        $status = 'Pass'
                    }
                }
            }
            'EDCA-MON-008' {
                $subjectLabel = 'Connector'
                $allConnectors = @{}
                foreach ($srv in @($CollectionData.Servers)) {
                    if (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and
                        ($srv.Exchange.PSObject.Properties.Name -contains 'SendConnectors')) {
                        foreach ($c in @($srv.Exchange.SendConnectors)) {
                            $cId = [string]$c.Identity
                            if (-not $allConnectors.ContainsKey($cId)) {
                                $allConnectors[$cId] = $c
                            }
                        }
                    }
                }
                if ($allConnectors.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Send connector data unavailable.'
                }
                else {
                    $domainServerResults = @($allConnectors.Values | ForEach-Object {
                            $lvl = if ($_.PSObject.Properties.Name -contains 'ProtocolLoggingLevel') { [string]$_.ProtocolLoggingLevel } else { $null }
                            $lvlDisplay = if (-not [string]::IsNullOrWhiteSpace($lvl)) { $lvl } else { 'unknown' }
                            $itemStatus = if ($lvl -eq 'Verbose') { 'Pass' } elseif ([string]::IsNullOrWhiteSpace($lvl)) { 'Unknown' } else { 'Fail' }
                            [pscustomobject]@{
                                Server   = [string]$_.Identity
                                Status   = $itemStatus
                                Evidence = ('ProtocolLoggingLevel: {0}.' -f $lvlDisplay)
                            }
                        })
                    $failCount = @($domainServerResults | Where-Object { $_.Status -eq 'Fail' }).Count
                    $unknownCount = @($domainServerResults | Where-Object { $_.Status -eq 'Unknown' }).Count
                    if ($failCount -gt 0) {
                        $status = 'Fail'
                    }
                    elseif ($unknownCount -gt 0) {
                        $status = 'Unknown'
                    }
                    else {
                        $status = 'Pass'
                    }
                }
            }
            'EDCA-TLS-011' {
                $subjectLabel = 'Connector'
                $allConnectors = @{}
                foreach ($srv in @($CollectionData.Servers)) {
                    if (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and
                        ($srv.Exchange.PSObject.Properties.Name -contains 'SendConnectors')) {
                        foreach ($c in @($srv.Exchange.SendConnectors)) {
                            $cId = [string]$c.Identity
                            if (-not $allConnectors.ContainsKey($cId)) {
                                $allConnectors[$cId] = $c
                            }
                        }
                    }
                }
                $externalConnectors = @($allConnectors.Values | Where-Object {
                        $spaces = @($_.AddressSpaces)
                        (@($spaces | Where-Object { [string]$_ -match '\*' })).Count -gt 0
                    })
                if ($allConnectors.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Send connector data unavailable.'
                }
                elseif ($externalConnectors.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No external send connector (address space containing *) found.'
                }
                else {
                    $domainServerResults = @($externalConnectors | ForEach-Object {
                            $ist = if ($_.PSObject.Properties.Name -contains 'IgnoreStartTLS') { $_.IgnoreStartTLS } else { $null }
                            $istDisplay = if ($ist -eq $true) { 'True' } elseif ($ist -eq $false) { 'False' } else { 'unknown' }
                            $itemStatus = if ($ist -eq $false) { 'Pass' } elseif ($null -eq $ist) { 'Unknown' } else { 'Fail' }
                            [pscustomobject]@{
                                Server   = [string]$_.Identity
                                Status   = $itemStatus
                                Evidence = ('IgnoreStartTLS: {0}.' -f $istDisplay)
                            }
                        })
                    $failCount = @($domainServerResults | Where-Object { $_.Status -eq 'Fail' }).Count
                    $unknownCount = @($domainServerResults | Where-Object { $_.Status -eq 'Unknown' }).Count
                    if ($failCount -gt 0) {
                        $status = 'Fail'
                    }
                    elseif ($unknownCount -gt 0) {
                        $status = 'Unknown'
                    }
                    else {
                        $status = 'Pass'
                    }
                }
            }
            'EDCA-TLS-014' {
                $subjectLabel = 'Connector'
                $allConnectors = @{}
                foreach ($srv in @($CollectionData.Servers)) {
                    if (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and
                        ($srv.Exchange.PSObject.Properties.Name -contains 'SendConnectors')) {
                        foreach ($c in @($srv.Exchange.SendConnectors)) {
                            $cId = [string]$c.Identity
                            if (-not $allConnectors.ContainsKey($cId)) {
                                $allConnectors[$cId] = $c
                            }
                        }
                    }
                }
                $externalConnectors = @($allConnectors.Values | Where-Object {
                        $spaces = @($_.AddressSpaces)
                        (@($spaces | Where-Object { [string]$_ -match '\*' })).Count -gt 0
                    })
                if ($allConnectors.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Send connector data unavailable.'
                }
                elseif ($externalConnectors.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No external send connector (address space containing *) found.'
                }
                else {
                    $domainServerResults = @($externalConnectors | ForEach-Object {
                            $dse = if ($_.PSObject.Properties.Name -contains 'DomainSecureEnabled') { $_.DomainSecureEnabled } else { $null }
                            $reqTls = if ($_.PSObject.Properties.Name -contains 'RequireTLS') { $_.RequireTLS } else { $null }
                            $tlsAuth = if ($_.PSObject.Properties.Name -contains 'TlsAuthLevel') { [string]$_.TlsAuthLevel } else { $null }
                            $tlsDomain = if ($_.PSObject.Properties.Name -contains 'TlsDomain') { [string]$_.TlsDomain } else { $null }
                            $tlsCert = if ($_.PSObject.Properties.Name -contains 'TlsCertificateName') { [string]$_.TlsCertificateName } else { $null }
                            $dseDisplay = if ($dse -eq $true) { 'True' } elseif ($dse -eq $false) { 'False' } else { 'unknown' }
                            $reqTlsDisplay = if ($null -ne $reqTls) { [string]$reqTls } else { 'unknown' }
                            $tlsAuthDisplay = if (-not [string]::IsNullOrWhiteSpace($tlsAuth)) { $tlsAuth } else { 'not set' }
                            $tlsDomainDisplay = if (-not [string]::IsNullOrWhiteSpace($tlsDomain)) { $tlsDomain } else { 'not set' }
                            $tlsCertDisplay = if (-not [string]::IsNullOrWhiteSpace($tlsCert)) { $tlsCert } else { 'not set' }
                            $itemStatus = if ($dse -eq $true) { 'Pass' } elseif ($null -eq $dse) { 'Unknown' } else { 'Fail' }
                            [pscustomobject]@{
                                Server   = [string]$_.Identity
                                Status   = $itemStatus
                                Evidence = ('DomainSecureEnabled: {0} | RequireTLS: {1} | TlsAuthLevel: {2} | TlsDomain: {3} | TlsCertificateName: {4}.' -f $dseDisplay, $reqTlsDisplay, $tlsAuthDisplay, $tlsDomainDisplay, $tlsCertDisplay)
                            }
                        })
                    $failCount = @($domainServerResults | Where-Object { $_.Status -eq 'Fail' }).Count
                    $unknownCount = @($domainServerResults | Where-Object { $_.Status -eq 'Unknown' }).Count
                    if ($failCount -gt 0) {
                        $status = 'Fail'
                    }
                    elseif ($unknownCount -gt 0) {
                        $status = 'Unknown'
                    }
                    else {
                        $status = 'Pass'
                    }
                }
            }
            'EDCA-TLS-012' {
                $subjectLabel = 'Connector'
                $allConnectors = @{}
                foreach ($srv in @($CollectionData.Servers)) {
                    if (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and
                        ($srv.Exchange.PSObject.Properties.Name -contains 'SendConnectors')) {
                        foreach ($c in @($srv.Exchange.SendConnectors)) {
                            $cId = [string]$c.Identity
                            if (-not $allConnectors.ContainsKey($cId)) {
                                $allConnectors[$cId] = $c
                            }
                        }
                    }
                }
                if ($allConnectors.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Send connector data unavailable.'
                }
                else {
                    $limit = 26214400 # 25 MB in bytes
                    $domainServerResults = @($allConnectors.Values | ForEach-Object {
                            $bytes = if ($_.PSObject.Properties.Name -contains 'MaxMessageSizeBytes' -and $null -ne $_.MaxMessageSizeBytes) { [long]$_.MaxMessageSizeBytes } else { $null }
                            $itemStatus = if ($null -eq $bytes) { 'Unknown' } elseif ($bytes -eq -1 -or $bytes -gt $limit) { 'Fail' } else { 'Pass' }
                            $bytesDisplay = if ($bytes -eq -1) { 'Unlimited' } elseif ($null -ne $bytes) { ('{0:N0} bytes ({1} MB)' -f $bytes, [math]::Round($bytes / 1MB, 2)) } else { 'unknown' }
                            [pscustomobject]@{
                                Server   = [string]$_.Identity
                                Status   = $itemStatus
                                Evidence = ('MaxMessageSizeBytes: {0}.' -f $bytesDisplay)
                            }
                        })
                    $failCount = @($domainServerResults | Where-Object { $_.Status -eq 'Fail' }).Count
                    $unknownCount = @($domainServerResults | Where-Object { $_.Status -eq 'Unknown' }).Count
                    if ($failCount -gt 0) {
                        $status = 'Fail'
                    }
                    elseif ($unknownCount -gt 0) {
                        $status = 'Unknown'
                    }
                    else {
                        $status = 'Pass'
                    }
                }
            }
            'EDCA-TLS-018' {
                $subjectLabel = 'Connector'
                $allConnectors = @{}
                foreach ($srv in @($CollectionData.Servers)) {
                    if (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and
                        ($srv.Exchange.PSObject.Properties.Name -contains 'SendConnectors')) {
                        foreach ($c in @($srv.Exchange.SendConnectors)) {
                            $cId = [string]$c.Identity
                            if (-not $allConnectors.ContainsKey($cId)) {
                                $allConnectors[$cId] = $c
                            }
                        }
                    }
                }
                if ($allConnectors.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Send connector data unavailable.'
                }
                else {
                    $domainServerResults = @($allConnectors.Values | ForEach-Object {
                            $timeoutStr = if ($_.PSObject.Properties.Name -contains 'ConnectionInactivityTimeOut') { [string]$_.ConnectionInactivityTimeOut } else { $null }
                            $parsed = $null
                            if (-not [string]::IsNullOrWhiteSpace($timeoutStr)) {
                                try { $parsed = [timespan]$timeoutStr } catch {}
                            }
                            $itemStatus = if ($null -eq $parsed) { 'Unknown' } elseif ($parsed.TotalMinutes -gt 10) { 'Fail' } else { 'Pass' }
                            $timeoutDisplay = if (-not [string]::IsNullOrWhiteSpace($timeoutStr)) { $timeoutStr } else { 'unknown' }
                            [pscustomobject]@{
                                Server   = [string]$_.Identity
                                Status   = $itemStatus
                                Evidence = ('ConnectionInactivityTimeOut: {0}.' -f $timeoutDisplay)
                            }
                        })
                    $failCount = @($domainServerResults | Where-Object { $_.Status -eq 'Fail' }).Count
                    $unknownCount = @($domainServerResults | Where-Object { $_.Status -eq 'Unknown' }).Count
                    if ($failCount -gt 0) {
                        $status = 'Fail'
                    }
                    elseif ($unknownCount -gt 0) {
                        $status = 'Unknown'
                    }
                    else {
                        $status = 'Pass'
                    }
                }
            }
            'EDCA-IAC-014' {
                $mdmPolicies = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'MobileDevicePolicies')) {
                    $mdmPolicies = @($CollectionData.Organization.MobileDevicePolicies)
                }
                if ($mdmPolicies.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mobile device mailbox policies found.'
                }
                else {
                    $defaultPolicy = $mdmPolicies | Where-Object { ($_.PSObject.Properties.Name -contains 'IsDefault') -and [bool]$_.IsDefault } | Select-Object -First 1
                    if ($null -eq $defaultPolicy) { $defaultPolicy = $mdmPolicies[0] }
                    $val = if ($defaultPolicy.PSObject.Properties.Name -contains 'AllowSimplePassword') { $defaultPolicy.AllowSimplePassword } else { $null }
                    if ($null -eq $val) {
                        $status = 'Unknown'
                        $evidence = 'AllowSimplePassword not available on the default mobile device mailbox policy.'
                    }
                    else {
                        $status = if (-not [bool]$val) { 'Pass' } else { 'Fail' }
                        $evidence = if (-not [bool]$val) { 'Compliant — AllowSimplePassword is False on the default mobile device mailbox policy.' } else { 'AllowSimplePassword is True on the default mobile device mailbox policy.' }
                    }
                }
            }
            'EDCA-IAC-015' {
                $mdmPolicies = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'MobileDevicePolicies')) {
                    $mdmPolicies = @($CollectionData.Organization.MobileDevicePolicies)
                }
                if ($mdmPolicies.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mobile device mailbox policies found.'
                }
                else {
                    $defaultPolicy = $mdmPolicies | Where-Object { ($_.PSObject.Properties.Name -contains 'IsDefault') -and [bool]$_.IsDefault } | Select-Object -First 1
                    if ($null -eq $defaultPolicy) { $defaultPolicy = $mdmPolicies[0] }
                    $val = if ($defaultPolicy.PSObject.Properties.Name -contains 'AllowNonProvisionableDevices') { $defaultPolicy.AllowNonProvisionableDevices } else { $null }
                    if ($null -eq $val) {
                        $status = 'Unknown'
                        $evidence = 'AllowNonProvisionableDevices not available on the default mobile device mailbox policy.'
                    }
                    else {
                        $status = if (-not [bool]$val) { 'Pass' } else { 'Fail' }
                        $evidence = if (-not [bool]$val) { 'Compliant — AllowNonProvisionableDevices is False on the default mobile device mailbox policy.' } else { 'AllowNonProvisionableDevices is True on the default mobile device mailbox policy.' }
                    }
                }
            }
            'EDCA-IAC-016' {
                $mdmPolicies = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'MobileDevicePolicies')) {
                    $mdmPolicies = @($CollectionData.Organization.MobileDevicePolicies)
                }
                if ($mdmPolicies.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mobile device mailbox policies found.'
                }
                else {
                    $defaultPolicy = $mdmPolicies | Where-Object { ($_.PSObject.Properties.Name -contains 'IsDefault') -and [bool]$_.IsDefault } | Select-Object -First 1
                    if ($null -eq $defaultPolicy) { $defaultPolicy = $mdmPolicies[0] }
                    $val = if ($defaultPolicy.PSObject.Properties.Name -contains 'PasswordHistory') { $defaultPolicy.PasswordHistory } else { $null }
                    if ($null -eq $val) {
                        $status = 'Unknown'
                        $evidence = 'PasswordHistory not available on the default mobile device mailbox policy.'
                    }
                    elseif ([string]$val -eq 'Unlimited') {
                        $status = 'Unknown'
                        $evidence = 'PasswordHistory is set to Unlimited on the default mobile device mailbox policy.'
                    }
                    else {
                        $intVal = [int]$val
                        $status = if ($intVal -ge 4) { 'Pass' } else { 'Fail' }
                        $evidence = ('PasswordHistory is {0} on the default mobile device mailbox policy.' -f $intVal)
                    }
                }
            }
            'EDCA-IAC-017' {
                $mdmPolicies = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'MobileDevicePolicies')) {
                    $mdmPolicies = @($CollectionData.Organization.MobileDevicePolicies)
                }
                if ($mdmPolicies.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mobile device mailbox policies found.'
                }
                else {
                    $defaultPolicy = $mdmPolicies | Where-Object { ($_.PSObject.Properties.Name -contains 'IsDefault') -and [bool]$_.IsDefault } | Select-Object -First 1
                    if ($null -eq $defaultPolicy) { $defaultPolicy = $mdmPolicies[0] }
                    $val = if ($defaultPolicy.PSObject.Properties.Name -contains 'MinPasswordLength') { $defaultPolicy.MinPasswordLength } else { $null }
                    if ($null -eq $val) {
                        $status = 'Unknown'
                        $evidence = 'MinPasswordLength not available on the default mobile device mailbox policy.'
                    }
                    else {
                        $intVal = [int]$val
                        $status = if ($intVal -ge 4) { 'Pass' } else { 'Fail' }
                        $evidence = ('MinPasswordLength is {0} on the default mobile device mailbox policy.' -f $intVal)
                    }
                }
            }
            'EDCA-IAC-018' {
                $mdmPolicies = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'MobileDevicePolicies')) {
                    $mdmPolicies = @($CollectionData.Organization.MobileDevicePolicies)
                }
                if ($mdmPolicies.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mobile device mailbox policies found.'
                }
                else {
                    $defaultPolicy = $mdmPolicies | Where-Object { ($_.PSObject.Properties.Name -contains 'IsDefault') -and [bool]$_.IsDefault } | Select-Object -First 1
                    if ($null -eq $defaultPolicy) { $defaultPolicy = $mdmPolicies[0] }
                    $val = if ($defaultPolicy.PSObject.Properties.Name -contains 'MaxPasswordFailedAttempts') { $defaultPolicy.MaxPasswordFailedAttempts } else { $null }
                    if ($null -eq $val) {
                        $status = 'Unknown'
                        $evidence = 'MaxPasswordFailedAttempts not available on the default mobile device mailbox policy.'
                    }
                    elseif ([string]$val -eq 'Unlimited') {
                        $status = 'Fail'
                        $evidence = 'MaxPasswordFailedAttempts is Unlimited on the default mobile device mailbox policy.'
                    }
                    else {
                        $intVal = [int]$val
                        $status = if ($intVal -le 10) { 'Pass' } else { 'Fail' }
                        $evidence = ('MaxPasswordFailedAttempts is {0} on the default mobile device mailbox policy.' -f $intVal)
                    }
                }
            }
            'EDCA-IAC-019' {
                $mdmPolicies = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'MobileDevicePolicies')) {
                    $mdmPolicies = @($CollectionData.Organization.MobileDevicePolicies)
                }
                if ($mdmPolicies.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mobile device mailbox policies found.'
                }
                else {
                    $defaultPolicy = $mdmPolicies | Where-Object { ($_.PSObject.Properties.Name -contains 'IsDefault') -and [bool]$_.IsDefault } | Select-Object -First 1
                    if ($null -eq $defaultPolicy) { $defaultPolicy = $mdmPolicies[0] }
                    $val = if ($defaultPolicy.PSObject.Properties.Name -contains 'PasswordExpiration') { $defaultPolicy.PasswordExpiration } else { $null }
                    if ($null -eq $val) {
                        $status = 'Unknown'
                        $evidence = 'PasswordExpiration not available on the default mobile device mailbox policy.'
                    }
                    elseif ([string]$val -eq 'Unlimited') {
                        $status = 'Fail'
                        $evidence = 'PasswordExpiration is Unlimited on the default mobile device mailbox policy.'
                    }
                    else {
                        try {
                            $ts = [timespan]::Parse([string]$val)
                            $status = if ($ts.TotalDays -le 365) { 'Pass' } else { 'Fail' }
                            $evidence = ('PasswordExpiration is {0} days on the default mobile device mailbox policy.' -f [math]::Round($ts.TotalDays, 1))
                        }
                        catch {
                            $status = 'Unknown'
                            $evidence = ('PasswordExpiration value could not be parsed: {0}' -f [string]$val)
                        }
                    }
                }
            }
            'EDCA-IAC-020' {
                $mdmPolicies = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'MobileDevicePolicies')) {
                    $mdmPolicies = @($CollectionData.Organization.MobileDevicePolicies)
                }
                if ($mdmPolicies.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mobile device mailbox policies found.'
                }
                else {
                    $defaultPolicy = $mdmPolicies | Where-Object { ($_.PSObject.Properties.Name -contains 'IsDefault') -and [bool]$_.IsDefault } | Select-Object -First 1
                    if ($null -eq $defaultPolicy) { $defaultPolicy = $mdmPolicies[0] }
                    $val = if ($defaultPolicy.PSObject.Properties.Name -contains 'DevicePolicyRefreshInterval') { $defaultPolicy.DevicePolicyRefreshInterval } else { $null }
                    if ($null -eq $val) {
                        $status = 'Unknown'
                        $evidence = 'DevicePolicyRefreshInterval not available on the default mobile device mailbox policy.'
                    }
                    elseif ([string]$val -eq 'Unlimited') {
                        $status = 'Fail'
                        $evidence = 'DevicePolicyRefreshInterval is Unlimited on the default mobile device mailbox policy.'
                    }
                    else {
                        try {
                            $ts = [timespan]::Parse([string]$val)
                            $status = if ($ts.TotalDays -le 1) { 'Pass' } else { 'Fail' }
                            $evidence = ('DevicePolicyRefreshInterval is {0} hours on the default mobile device mailbox policy.' -f [math]::Round($ts.TotalHours, 2))
                        }
                        catch {
                            $status = 'Unknown'
                            $evidence = ('DevicePolicyRefreshInterval value could not be parsed: {0}' -f [string]$val)
                        }
                    }
                }
            }
            'EDCA-IAC-021' {
                $mdmPolicies = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'MobileDevicePolicies')) {
                    $mdmPolicies = @($CollectionData.Organization.MobileDevicePolicies)
                }
                if ($mdmPolicies.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mobile device mailbox policies found.'
                }
                else {
                    $defaultPolicy = $mdmPolicies | Where-Object { ($_.PSObject.Properties.Name -contains 'IsDefault') -and [bool]$_.IsDefault } | Select-Object -First 1
                    if ($null -eq $defaultPolicy) { $defaultPolicy = $mdmPolicies[0] }
                    $val = if ($defaultPolicy.PSObject.Properties.Name -contains 'AlphanumericPasswordRequired') { $defaultPolicy.AlphanumericPasswordRequired } else { $null }
                    if ($null -eq $val) {
                        $status = 'Unknown'
                        $evidence = 'AlphanumericPasswordRequired not available on the default mobile device mailbox policy.'
                    }
                    else {
                        $status = if ([bool]$val) { 'Pass' } else { 'Fail' }
                        $evidence = if ([bool]$val) { 'Compliant — AlphanumericPasswordRequired is True on the default mobile device mailbox policy.' } else { 'AlphanumericPasswordRequired is False on the default mobile device mailbox policy.' }
                    }
                }
            }
            'EDCA-IAC-022' {
                $mdmPolicies = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'MobileDevicePolicies')) {
                    $mdmPolicies = @($CollectionData.Organization.MobileDevicePolicies)
                }
                if ($mdmPolicies.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mobile device mailbox policies found.'
                }
                else {
                    $defaultPolicy = $mdmPolicies | Where-Object { ($_.PSObject.Properties.Name -contains 'IsDefault') -and [bool]$_.IsDefault } | Select-Object -First 1
                    if ($null -eq $defaultPolicy) { $defaultPolicy = $mdmPolicies[0] }
                    $val = if ($defaultPolicy.PSObject.Properties.Name -contains 'RequireDeviceEncryption') { $defaultPolicy.RequireDeviceEncryption } else { $null }
                    if ($null -eq $val) {
                        $status = 'Unknown'
                        $evidence = 'RequireDeviceEncryption not available on the default mobile device mailbox policy.'
                    }
                    else {
                        $status = if ([bool]$val) { 'Pass' } else { 'Fail' }
                        $evidence = if ([bool]$val) { 'Compliant — RequireDeviceEncryption is True on the default mobile device mailbox policy.' } else { 'RequireDeviceEncryption is False on the default mobile device mailbox policy.' }
                    }
                }
            }
            'EDCA-IAC-023' {
                $mdmPolicies = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'MobileDevicePolicies')) {
                    $mdmPolicies = @($CollectionData.Organization.MobileDevicePolicies)
                }
                if ($mdmPolicies.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mobile device mailbox policies found.'
                }
                else {
                    $defaultPolicy = $mdmPolicies | Where-Object { ($_.PSObject.Properties.Name -contains 'IsDefault') -and [bool]$_.IsDefault } | Select-Object -First 1
                    if ($null -eq $defaultPolicy) { $defaultPolicy = $mdmPolicies[0] }
                    $val = if ($defaultPolicy.PSObject.Properties.Name -contains 'PasswordEnabled') { $defaultPolicy.PasswordEnabled } else { $null }
                    if ($null -eq $val) {
                        $status = 'Unknown'
                        $evidence = 'PasswordEnabled not available on the default mobile device mailbox policy.'
                    }
                    else {
                        $status = if ([bool]$val) { 'Pass' } else { 'Fail' }
                        $evidence = if ([bool]$val) { 'Compliant — PasswordEnabled is True on the default mobile device mailbox policy.' } else { 'PasswordEnabled is False on the default mobile device mailbox policy.' }
                    }
                }
            }
            'EDCA-DATA-016' {
                $irmConfig = $null
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'IrmConfiguration')) {
                    $irmConfig = $CollectionData.Organization.IrmConfiguration
                }

                if ($null -eq $irmConfig) {
                    $status = 'Unknown'
                    $evidence = 'IRM configuration data unavailable; cannot determine whether AES256-CBC override is required.'
                }
                else {
                    $internalEnabled = ($irmConfig.PSObject.Properties.Name -contains 'InternalLicensingEnabled') -and [bool]$irmConfig.InternalLicensingEnabled
                    $externalEnabled = ($irmConfig.PSObject.Properties.Name -contains 'ExternalLicensingEnabled') -and [bool]$irmConfig.ExternalLicensingEnabled
                    $azureEnabled = ($irmConfig.PSObject.Properties.Name -contains 'AzureRMSLicensingEnabled') -and [bool]$irmConfig.AzureRMSLicensingEnabled
                    $irmInUse = $internalEnabled -or $externalEnabled -or $azureEnabled

                    if (-not $irmInUse) {
                        $status = 'Skipped'
                        $evidence = ('IRM is not in use (InternalLicensingEnabled={0}; ExternalLicensingEnabled={1}; AzureRMSLicensingEnabled={2}); control is not applicable.' -f $internalEnabled, $externalEnabled, $azureEnabled)
                    }
                    else {
                        # Check whether EnableEncryptionAlgorithmCBC override is present on any server.
                        $cbcOverridePresent = $false
                        if ($CollectionData.PSObject.Properties.Name -contains 'Servers') {
                            foreach ($srv in @($CollectionData.Servers)) {
                                if (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and
                                    ($srv.Exchange.PSObject.Properties.Name -contains 'SettingOverrides') -and $null -ne $srv.Exchange.SettingOverrides -and
                                    ($srv.Exchange.SettingOverrides.PSObject.Properties.Name -contains 'Names') -and $null -ne $srv.Exchange.SettingOverrides.Names) {
                                    if (@($srv.Exchange.SettingOverrides.Names) -contains 'EnableEncryptionAlgorithmCBC') {
                                        $cbcOverridePresent = $true
                                        break
                                    }
                                }
                            }
                        }

                        if ($cbcOverridePresent) {
                            $status = 'Pass'
                            $evidence = ('IRM is in use and the EnableEncryptionAlgorithmCBC setting override is present; AES256-CBC encryption mode is enabled for IRM-protected messages.')
                        }
                        else {
                            $status = 'Fail'
                            $irmState = @()
                            if ($internalEnabled) { $irmState += 'Internal' }
                            if ($externalEnabled) { $irmState += 'External' }
                            if ($azureEnabled) { $irmState += 'AzureRMS' }
                            $evidence = ('IRM is in use ({0}) but the EnableEncryptionAlgorithmCBC setting override is not present; AES256-CBC mode is not enabled for IRM-protected messages.' -f ($irmState -join ', '))
                        }
                    }
                }
            }
            'EDCA-IAC-024' {
                $mdmPolicies = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'MobileDevicePolicies')) {
                    $mdmPolicies = @($CollectionData.Organization.MobileDevicePolicies)
                }
                if ($mdmPolicies.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mobile device mailbox policies found.'
                }
                else {
                    $defaultPolicy = $mdmPolicies | Where-Object { ($_.PSObject.Properties.Name -contains 'IsDefault') -and [bool]$_.IsDefault } | Select-Object -First 1
                    if ($null -eq $defaultPolicy) { $defaultPolicy = $mdmPolicies[0] }
                    $val = if ($defaultPolicy.PSObject.Properties.Name -contains 'MaxInactivityTimeLock') { $defaultPolicy.MaxInactivityTimeLock } else { $null }
                    if ($null -eq $val) {
                        $status = 'Unknown'
                        $evidence = 'MaxInactivityTimeLock not available on the default mobile device mailbox policy.'
                    }
                    elseif ([string]$val -eq 'Unlimited') {
                        $status = 'Fail'
                        $evidence = 'MaxInactivityTimeLock is Unlimited on the default mobile device mailbox policy.'
                    }
                    else {
                        try {
                            $ts = [timespan]::Parse([string]$val)
                            $status = if ($ts.TotalMinutes -le 15) { 'Pass' } else { 'Fail' }
                            $evidence = ('MaxInactivityTimeLock is {0} minutes on the default mobile device mailbox policy.' -f [math]::Round($ts.TotalMinutes, 1))
                        }
                        catch {
                            $status = 'Unknown'
                            $evidence = ('MaxInactivityTimeLock value could not be parsed: {0}' -f [string]$val)
                        }
                    }
                }
            }
            'EDCA-TLS-019' {
                $transportConfig = $null
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'TransportConfig')) {
                    $transportConfig = $CollectionData.Organization.TransportConfig
                }
                if ($null -eq $transportConfig -or -not ($transportConfig.PSObject.Properties.Name -contains 'MaxRecipientEnvelopeLimit')) {
                    $status = 'Unknown'
                    $evidence = 'MaxRecipientEnvelopeLimit data unavailable.'
                }
                else {
                    $val = [string]$transportConfig.MaxRecipientEnvelopeLimit
                    if ($val -eq 'Unlimited') {
                        $status = 'Fail'
                        $evidence = 'MaxRecipientEnvelopeLimit is set to Unlimited (must be ≤ 5000).'
                    }
                    else {
                        $intVal = 0
                        if ([int]::TryParse($val, [ref]$intVal)) {
                            $status = if ($intVal -le 5000) { 'Pass' } else { 'Fail' }
                            $evidence = ('MaxRecipientEnvelopeLimit is {0} ({1} ≤ 5000).' -f $intVal, $(if ($intVal -le 5000) { 'compliant,' } else { 'non-compliant, exceeds' }))
                        }
                        else {
                            $status = 'Unknown'
                            $evidence = ('MaxRecipientEnvelopeLimit value could not be parsed: {0}' -f $val)
                        }
                    }
                }
            }
            'EDCA-RES-012' {
                $serverList = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Servers') -and $null -ne $CollectionData.Servers) {
                    $serverList = @($CollectionData.Servers)
                }
                $dagMembers = @($serverList | Where-Object {
                        ($_.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $_.Exchange -and
                        ($_.Exchange.PSObject.Properties.Name -contains 'IsDagMember') -and [bool]$_.Exchange.IsDagMember -and
                        ($_.Exchange.PSObject.Properties.Name -contains 'DagName') -and -not [string]::IsNullOrWhiteSpace([string]$_.Exchange.DagName)
                    })
                if ($dagMembers.Count -eq 0) {
                    $status = 'Skipped'
                    $evidence = 'No DAG members found in the collected server data. This control is not applicable if no DAG is deployed.'
                }
                else {
                    $dagGroups = $dagMembers | Group-Object -Property { [string]$_.Exchange.DagName }
                    $nonCompliantDags = @()
                    $passDags = @()
                    foreach ($dagGroup in $dagGroups) {
                        $sites = @($dagGroup.Group | ForEach-Object {
                                if ($_.Exchange.PSObject.Properties.Name -contains 'AdSite') { [string]$_.Exchange.AdSite } else { '' }
                            } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
                        if ($sites.Count -lt 2) {
                            $nonCompliantDags += ('{0}: {1} site(s) [{2}]' -f $dagGroup.Name, $sites.Count, ($sites -join ', '))
                        }
                        else {
                            $passDags += ('{0}: {1} sites [{2}]' -f $dagGroup.Name, $sites.Count, ($sites -join ', '))
                        }
                    }
                    if ($nonCompliantDags.Count -gt 0) {
                        $status = 'Fail'
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} DAG(s) do not span at least two Active Directory sites.' -f $nonCompliantDags.Count, @($dagGroups).Count) -Elements $nonCompliantDags
                    }
                    else {
                        $status = 'Pass'
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('All {0} DAG(s) span at least two Active Directory sites.' -f @($dagGroups).Count) -Elements $passDags
                    }
                }
            }
            'EDCA-RES-011' {
                # SingleItemRecoveryDisabledCount is collected via org-scoped Get-Mailbox on each server.
                # All servers store identical org-level data — take the first server's value to avoid multiplication.
                $disabledCount = $null
                foreach ($srv in @($CollectionData.Servers)) {
                    if (($srv.PSObject.Properties.Name -contains 'CollectionError') -and -not [string]::IsNullOrWhiteSpace([string]$srv.CollectionError)) { continue }
                    if (-not (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and
                            ($srv.Exchange.PSObject.Properties.Name -contains 'IsExchangeServer') -and [bool]$srv.Exchange.IsExchangeServer)) { continue }
                    if ($srv.Exchange.PSObject.Properties.Name -contains 'SingleItemRecoveryDisabledCount' -and $null -ne $srv.Exchange.SingleItemRecoveryDisabledCount) {
                        $disabledCount = [int]$srv.Exchange.SingleItemRecoveryDisabledCount
                        break
                    }
                }
                if ($null -eq $disabledCount) {
                    $status = 'Unknown'
                    $evidence = 'Single Item Recovery mailbox data unavailable.'
                }
                elseif ($disabledCount -eq 0) {
                    $status = 'Pass'
                    $evidence = 'Compliant — all user mailboxes have Single Item Recovery enabled.'
                }
                else {
                    $status = 'Fail'
                    $evidence = ('{0} user mailbox(es) have Single Item Recovery disabled.' -f $disabledCount)
                }
            }
            'EDCA-DATA-002' {
                $subjectLabel = 'Server'
                # Evaluate org-level auth cert validity from Organization.AuthCertificate (Get-AuthConfig)
                $orgCert = $null
                if (($CollectionData.Organization.PSObject.Properties.Name -contains 'AuthCertificate') -and $null -ne $CollectionData.Organization.AuthCertificate) {
                    $orgCert = $CollectionData.Organization.AuthCertificate
                }
                if ($null -eq $orgCert) {
                    $status = 'Unknown'
                    $evidence = 'Auth certificate data unavailable (Get-AuthConfig not collected).'
                }
                elseif ([string]::IsNullOrWhiteSpace([string]$orgCert.Thumbprint)) {
                    $status = 'Fail'
                    $evidence = 'No current auth certificate thumbprint configured (Get-AuthConfig.CurrentCertificateThumbprint is empty).'
                }
                elseif (-not [bool]$orgCert.Found) {
                    $status = 'Fail'
                    $evidence = ('Auth certificate thumbprint {0} not found in Exchange certificate store.' -f [string]$orgCert.Thumbprint)
                }
                else {
                    $daysRemaining = if ($orgCert.PSObject.Properties.Name -contains 'DaysRemaining' -and $null -ne $orgCert.DaysRemaining) { [int]$orgCert.DaysRemaining } else { $null }
                    if ([bool]$orgCert.IsExpired) {
                        $status = 'Fail'
                        $evidence = ('Auth certificate {0} has EXPIRED (expired {1}) — renew or replace the auth certificate.' -f [string]$orgCert.Thumbprint, [string]$orgCert.NotAfter)
                    }
                    elseif ($null -ne $daysRemaining -and $daysRemaining -lt 30) {
                        $status = 'Fail'
                        $evidence = ('Auth certificate {0} expires {1} — only {2} days remaining, within the 30-day expiry threshold. Renew or replace the auth certificate promptly.' -f [string]$orgCert.Thumbprint, [string]$orgCert.NotAfter, $daysRemaining)
                    }
                    elseif ($null -ne $daysRemaining -and $daysRemaining -lt 60) {
                        $status = 'Unknown'
                        $evidence = ('Auth certificate {0} expires {1} — {2} days remaining, within the 60-day advisory window. Plan renewal.' -f [string]$orgCert.Thumbprint, [string]$orgCert.NotAfter, $daysRemaining)
                    }
                    else {
                        $status = 'Pass'
                        $evidence = ('Auth certificate {0} is valid; expires {1} ({2} days remaining).' -f [string]$orgCert.Thumbprint, [string]$orgCert.NotAfter, $(if ($null -ne $daysRemaining) { $daysRemaining } else { 'unknown' }))
                    }
                }
                # Per-server presence check: auth cert must be in each Exchange server's local certificate store
                $exchServers = @($CollectionData.Servers | Where-Object {
                        ($_.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $_.Exchange -and
                        ($_.Exchange.PSObject.Properties.Name -contains 'IsExchangeServer') -and [bool]$_.Exchange.IsExchangeServer
                    })
                if ($exchServers.Count -gt 0) {
                    $domainServerResults = @()
                    foreach ($srv in $exchServers) {
                        $srvName = [string]$srv.Server
                        $srvCert = $null
                        if (($srv.Exchange.PSObject.Properties.Name -contains 'AuthCertificate') -and $null -ne $srv.Exchange.AuthCertificate) {
                            $srvCert = $srv.Exchange.AuthCertificate
                        }
                        if ($null -eq $srvCert) {
                            $domainServerResults += [pscustomobject]@{ Server = $srvName; Status = 'Unknown'; Evidence = 'Auth certificate store data not available for this server.' }
                        }
                        elseif ([bool]$srvCert.Found) {
                            $srvDays = if ($srvCert.PSObject.Properties.Name -contains 'DaysRemaining' -and $null -ne $srvCert.DaysRemaining) { [int]$srvCert.DaysRemaining } else { $null }
                            $srvNotAfter = if ($srvCert.PSObject.Properties.Name -contains 'NotAfter' -and $null -ne $srvCert.NotAfter) { [string]$srvCert.NotAfter } else { 'unknown' }
                            $srvExpired = ($srvCert.PSObject.Properties.Name -contains 'IsExpired') -and $null -ne $srvCert.IsExpired -and [bool]$srvCert.IsExpired
                            if ($srvExpired) {
                                $srvStatus = 'Fail'
                                $srvEvidence = ('Auth certificate {0} found in local store — EXPIRED (expired {1}).' -f [string]$srvCert.Thumbprint, $srvNotAfter)
                            }
                            elseif ($null -ne $srvDays -and $srvDays -lt 30) {
                                $srvStatus = 'Fail'
                                $srvEvidence = ('Auth certificate {0} found in local store — expires {1} ({2} days remaining, within 30-day threshold). Renew or replace the auth certificate promptly.' -f [string]$srvCert.Thumbprint, $srvNotAfter, $srvDays)
                            }
                            elseif ($null -ne $srvDays -and $srvDays -lt 60) {
                                $srvStatus = 'Unknown'
                                $srvEvidence = ('Auth certificate {0} found in local store — expires {1} ({2} days remaining, within 60-day advisory window). Plan renewal.' -f [string]$srvCert.Thumbprint, $srvNotAfter, $srvDays)
                            }
                            else {
                                $srvStatus = 'Pass'
                                $srvEvidence = ('Auth certificate {0} found in local store; expires {1} ({2} days remaining).' -f [string]$srvCert.Thumbprint, $srvNotAfter, $(if ($null -ne $srvDays) { $srvDays } else { 'unknown' }))
                            }
                            $domainServerResults += [pscustomobject]@{ Server = $srvName; Status = $srvStatus; Evidence = $srvEvidence }
                        }
                        else {
                            $configuredThumbprint = if (-not [string]::IsNullOrWhiteSpace([string]$srvCert.Thumbprint)) { [string]$srvCert.Thumbprint } elseif ($null -ne $orgCert) { [string]$orgCert.Thumbprint } else { 'unknown' }
                            $domainServerResults += [pscustomobject]@{ Server = $srvName; Status = 'Fail'; Evidence = ('Auth certificate {0} NOT found in local certificate store — potential misconfiguration.' -f $configuredThumbprint) }
                        }
                    }
                }
            }
            'EDCA-GOV-009' {
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'CustomerFeedbackEnabled')) {
                    $enabled = $CollectionData.Organization.CustomerFeedbackEnabled -eq $true
                    $cfDesc = if (-not $enabled) { 'non-compliant (must be False)' } else { 'compliant (disabled)' }
                    $status = if (-not $enabled) { 'Fail' } else { 'Pass' }
                    $evidence = ('CustomerFeedbackEnabled={0} — {1}.' -f $CollectionData.Organization.CustomerFeedbackEnabled, $cfDesc)
                }
                else {
                    $status = 'Unknown'
                    $evidence = 'CustomerFeedbackEnabled organization setting is unavailable (collection RBAC failure); cannot confirm compliance.'
                }
            }
            'EDCA-PERF-012' {
                $siteData = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                    ($CollectionData.Organization.PSObject.Properties.Name -contains 'DcCoreRatio') -and
                    $null -ne $CollectionData.Organization.DcCoreRatio) {
                    $siteData = @($CollectionData.Organization.DcCoreRatio)
                }
                $availableSites = @($siteData | Where-Object { ($_.PSObject.Properties.Name -contains 'Available') -and [bool]$_.Available })
                if ($siteData.Count -eq 0 -or $availableSites.Count -eq 0) {
                    $status = 'Skipped'
                    $evidence = 'DC/GC core ratio data could not be determined. Perform this check manually: verify that the Exchange-to-DC/GC core ratio does not exceed 8:1 in each AD site that hosts Exchange servers.'
                }
                else {
                    $domainServerResults = @($availableSites | ForEach-Object {
                            $site = $_
                            $siteName = if (-not [string]::IsNullOrWhiteSpace([string]$site.AdSite)) { [string]$site.AdSite } else { 'Unknown' }
                            $dcErr = if (($site.PSObject.Properties.Name -contains 'DcAccessError') -and -not [string]::IsNullOrWhiteSpace([string]$site.DcAccessError)) { [string]$site.DcAccessError } else { $null }
                            $ratio = if (($site.PSObject.Properties.Name -contains 'Ratio') -and $null -ne $site.Ratio) { [double]$site.Ratio } else { $null }
                            $exCores = if (($site.PSObject.Properties.Name -contains 'ExchangeCores')) { [int]$site.ExchangeCores } else { 0 }
                            $dcCores = if (($site.PSObject.Properties.Name -contains 'DcCores')) { [int]$site.DcCores } else { 0 }
                            if ($null -ne $dcErr) {
                                [pscustomobject]@{
                                    Server   = $siteName
                                    Status   = 'Unknown'
                                    Evidence = ('AD site {0}: could not query domain controllers — {1}' -f $siteName, $dcErr)
                                }
                            }
                            elseif ($null -eq $ratio) {
                                $dcDetailEntries = @()
                                if (($site.PSObject.Properties.Name -contains 'DomainControllers') -and $null -ne $site.DomainControllers) {
                                    $dcDetailEntries = @($site.DomainControllers)
                                }
                                $dcDetailLines = @($dcDetailEntries | ForEach-Object {
                                        if (-not [string]::IsNullOrWhiteSpace([string]$_.Error)) {
                                            ('  {0}: Cores={1} — Error: {2}' -f [string]$_.Name, [int]$_.Cores, [string]$_.Error)
                                        }
                                        else {
                                            ('  {0}: Cores={1}' -f [string]$_.Name, [int]$_.Cores)
                                        }
                                    })
                                $dcSummary = if ($dcDetailEntries.Count -eq 0) {
                                    'No Global Catalog servers were found in this AD site.'
                                }
                                elseif ((@($dcDetailEntries | Where-Object { [int]$_.Cores -eq 0 -and [string]::IsNullOrWhiteSpace([string]$_.Error) }).Count) -eq $dcDetailEntries.Count) {
                                    'CIM (Win32_Processor) returned 0 cores for all DC/GC servers (possible CIM/WMI access permission issue; verify the collection account has remote WMI access on domain controllers and perform this check manually).'
                                }
                                else {
                                    'DC/GC core data was incomplete.'
                                }
                                $extraLines = if ($dcDetailLines.Count -gt 0) { ("`n" + ($dcDetailLines -join "`n")) } else { '' }
                                [pscustomobject]@{
                                    Server   = $siteName
                                    Status   = 'Skipped'
                                    Evidence = ('AD site {0}: ratio could not be computed (ExchangeCores={1}, DcCores={2}). {3}{4} Perform this check manually.' -f $siteName, $exCores, $dcCores, $dcSummary, $extraLines)
                                }
                            }
                            elseif ($ratio -gt 8.0) {
                                [pscustomobject]@{
                                    Server   = $siteName
                                    Status   = 'Fail'
                                    Evidence = ('AD site {0}: Exchange-to-DC/GC core ratio is {1}:1 (ExchangeCores={2}, DcCores={3}) — exceeds recommended 8:1 maximum.' -f $siteName, $ratio, $exCores, $dcCores)
                                }
                            }
                            else {
                                [pscustomobject]@{
                                    Server   = $siteName
                                    Status   = 'Pass'
                                    Evidence = ('AD site {0}: Exchange-to-DC/GC core ratio is {1}:1 (ExchangeCores={2}, DcCores={3}) — within 8:1 limit.' -f $siteName, $ratio, $exCores, $dcCores)
                                }
                            }
                        })
                    if ($domainServerResults | Where-Object { $_.Status -eq 'Fail' }) {
                        $status = 'Fail'
                    }
                    elseif ($domainServerResults | Where-Object { $_.Status -eq 'Unknown' }) {
                        $status = 'Unknown'
                    }
                    elseif ($domainServerResults | Where-Object { $_.Status -eq 'Skipped' }) {
                        $status = 'Skipped'
                    }
                    else {
                        $status = 'Pass'
                    }
                }
            }
            'EDCA-MON-001' {
                $auditEnabled = $null
                foreach ($srv in @($CollectionData.Servers)) {
                    if (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and
                        ($srv.Exchange.PSObject.Properties.Name -contains 'AdminAuditLogEnabled') -and
                        $null -ne $srv.Exchange.AdminAuditLogEnabled) {
                        $auditEnabled = [bool]$srv.Exchange.AdminAuditLogEnabled
                        break
                    }
                }
                if ($null -eq $auditEnabled) {
                    $status = 'Unknown'
                    $evidence = 'Admin audit log configuration data unavailable.'
                }
                elseif ($auditEnabled) {
                    $status = 'Pass'
                    $evidence = 'AdminAuditLogEnabled is True.'
                }
                else {
                    $status = 'Fail'
                    $evidence = 'AdminAuditLogEnabled is False — admin audit logging is disabled.'
                }
            }
            'EDCA-GOV-011' {
                $status = 'Skipped'
                $evidence = 'Procedural control — assessment is not applicable.'
            }
            'EDCA-SEC-036' {
                $status = 'Skipped'
                $evidence = 'Partition layout cannot be assessed remotely — manual verification required.'
            }
            'EDCA-IAC-028' {
                # Minimum qualifying builds: Exchange 2016 CU12, Exchange 2019 CU1, ExchangeSE all builds
                $minBuild2016 = [System.Version]'15.1.1713.5'
                $minBuild2019 = [System.Version]'15.2.330.5'

                # Step 1: Not applicable under AD split permissions
                $splitPerms = $null
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization) {
                    if ($CollectionData.Organization.PSObject.Properties.Name -contains 'AdSplitPermissionEnabled') {
                        $splitPerms = $CollectionData.Organization.AdSplitPermissionEnabled
                    }
                }
                if ($null -ne $splitPerms -and [bool]$splitPerms) {
                    $status = 'Skipped'
                    $evidence = 'AD Split Permissions is enabled — the Exchange Windows Permissions group does not hold WriteDACL rights on the domain object; this control is not applicable.'
                }
                else {
                    # Step 2: Check collection data availability
                    $dacl = $null
                    if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and
                        ($CollectionData.Organization.PSObject.Properties.Name -contains 'DomainObjectDacl') -and
                        $null -ne $CollectionData.Organization.DomainObjectDacl) {
                        $dacl = $CollectionData.Organization.DomainObjectDacl
                    }

                    if ($null -eq $dacl) {
                        $status = 'Unknown'
                        $evidence = 'Domain object DACL data not collected — upgrade collection data by re-running with the current EDCA build.'
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace([string]$dacl.CollectionError)) {
                        $status = 'Unknown'
                        $evidence = ('Domain object DACL collection failed: {0}' -f [string]$dacl.CollectionError)
                    }
                    else {
                        # Step 3: Determine whether the fix has been applied
                        $ewpUserOk = $dacl.PSObject.Properties.Name -contains 'EwpUserAceInheritOnly' -and $null -ne $dacl.EwpUserAceInheritOnly
                        $ewpInetOk = $dacl.PSObject.Properties.Name -contains 'EwpInetOrgPersonAceInheritOnly' -and $null -ne $dacl.EwpInetOrgPersonAceInheritOnly
                        # Absent ACE (null) is compliant — no WriteDACL right on the domain object at all
                        $ewpUserCompliant = (-not $ewpUserOk) -or [bool]$dacl.EwpUserAceInheritOnly
                        $ewpInetCompliant = (-not $ewpInetOk) -or [bool]$dacl.EwpInetOrgPersonAceInheritOnly

                        # Determine whether AdminSDHolder check is applicable (any Exchange 2016+ server)
                        $has2016Plus = $false
                        foreach ($srv in @($CollectionData.Servers)) {
                            if (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and
                                ($srv.Exchange.PSObject.Properties.Name -contains 'IsExchangeServer') -and [bool]$srv.Exchange.IsExchangeServer) {
                                $pl = Get-EDCAProductLineFromServerData -Server $srv
                                if ($pl -in @('Exchange2016', 'Exchange2019', 'ExchangeSE')) {
                                    $has2016Plus = $true
                                    break
                                }
                            }
                        }

                        $adminSdCompliant = $true
                        $adminSdApplicable = $false
                        if ($has2016Plus) {
                            $adminSdApplicable = $true
                            $etsAbsent = $dacl.PSObject.Properties.Name -contains 'EtsGroupAceOnAdminSdHolderAbsent' -and $null -ne $dacl.EtsGroupAceOnAdminSdHolderAbsent
                            $adminSdCompliant = -not $etsAbsent -or [bool]$dacl.EtsGroupAceOnAdminSdHolderAbsent
                        }

                        $aclFixed = $ewpUserCompliant -and $ewpInetCompliant -and (-not $adminSdApplicable -or $adminSdCompliant)

                        if ($aclFixed) {
                            $status = 'Pass'
                            $ewpUserDisplay = if (-not $ewpUserOk) { 'absent (no WriteDACL on domain object)' } else { 'present, Inherit-Only flag set' }
                            $ewpInetDisplay = if (-not $ewpInetOk) { 'absent (no WriteDACL on domain object)' } else { 'present, Inherit-Only flag set' }
                            $adminSdDisplay = if ($adminSdApplicable) { (', ETS WriteDACL Group ACE on AdminSDHolder: absent') } else { '' }
                            $evidence = ('EWP WriteDACL User ACE: {0}; EWP WriteDACL inetOrgPerson ACE: {1}{2}.' -f $ewpUserDisplay, $ewpInetDisplay, $adminSdDisplay)
                        }
                        else {
                            # Build evidence detail lines
                            $issueLines = @()
                            if ($ewpUserOk -and -not $ewpUserCompliant) {
                                $issueLines += 'EWP WriteDACL ACE for User (bf967aba): Inherit-Only flag is NOT set — WriteDACL applies to the domain object itself.'
                            }
                            if ($ewpInetOk -and -not $ewpInetCompliant) {
                                $issueLines += 'EWP WriteDACL ACE for inetOrgPerson (4828cc14): Inherit-Only flag is NOT set — WriteDACL applies to the domain object itself.'
                            }
                            if ($adminSdApplicable -and -not $adminSdCompliant) {
                                $issueLines += 'ETS WriteDACL Group ACE on AdminSDHolder: present — must be removed (Exchange 2016+ environment).'
                            }

                            # Step 4: Determine if qualifying build exists
                            $qualifyingBuilds = @()
                            $nonQualifyingBuilds = @()
                            foreach ($srv in @($CollectionData.Servers)) {
                                if (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and
                                    ($srv.Exchange.PSObject.Properties.Name -contains 'IsExchangeServer') -and [bool]$srv.Exchange.IsExchangeServer) {
                                    $srvName = ([string]$srv.Server -split '\.')[0]
                                    $pl = Get-EDCAProductLineFromServerData -Server $srv
                                    $buildStr = if ($srv.Exchange.PSObject.Properties.Name -contains 'BuildNumber') { [string]$srv.Exchange.BuildNumber } else { '' }
                                    $buildVer = $null
                                    if (-not [string]::IsNullOrWhiteSpace($buildStr)) {
                                        try { $buildVer = [System.Version]$buildStr } catch {}
                                    }
                                    $qualifies = switch ($pl) {
                                        'ExchangeSE' { $true }
                                        'Exchange2019' { $null -ne $buildVer -and $buildVer -ge $minBuild2019 }
                                        'Exchange2016' { $null -ne $buildVer -and $buildVer -ge $minBuild2016 }
                                        default { $false }
                                    }
                                    if ($qualifies) {
                                        $qualifyingBuilds += ('{0} ({1} {2})' -f $srvName, $pl, $buildStr)
                                    }
                                    else {
                                        $nonQualifyingBuilds += ('{0} ({1} {2} — minimum: {3})' -f $srvName, $pl, $(if ([string]::IsNullOrWhiteSpace($buildStr)) { 'unknown build' } else { $buildStr }),
                                            $(switch ($pl) { 'Exchange2016' { $minBuild2016 } 'Exchange2019' { $minBuild2019 } default { 'N/A' } }))
                                    }
                                }
                            }

                            $summary = 'Domain object DACL WriteDACL ACE misconfiguration detected.'
                            if ($qualifyingBuilds.Count -gt 0) {
                                $status = 'Fail'
                                $remediationHint = ('Qualifying Exchange build(s) present — run Setup /PrepareAD then Setup /PrepareDomain in each forest domain: {0}.' -f ($qualifyingBuilds -join '; '))
                                $issueLines += $remediationHint
                            }
                            else {
                                $status = 'Warning'
                                $upgradeHint = 'No qualifying Exchange build found — install Exchange 2016 CU12 (15.1.1713.5) or Exchange 2019 CU1 (15.2.330.5) or later before running Setup /PrepareAD.'
                                if ($nonQualifyingBuilds.Count -gt 0) {
                                    $upgradeHint += (' Servers below minimum: {0}.' -f ($nonQualifyingBuilds -join '; '))
                                }
                                $issueLines += $upgradeHint
                            }
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $issueLines
                        }
                    }
                }
            }
        }

        return [pscustomobject]@{
            ControlId      = $Control.id
            Title          = $Control.title
            Description    = $Control.description
            Category       = $Control.category
            Severity       = $Control.severity
            SeverityWeight = [int]$Control.severityWeight
            Frameworks     = @($Control.frameworks)
            Verify         = [bool]$Control.verify
            OverallStatus  = $status
            Subject        = [string]$Control.subject
            Roles          = @($Control.roles | ForEach-Object { [string]$_ })
            ServerResults  = if ($null -ne $domainServerResults) { $domainServerResults } else {
                @([pscustomobject]@{ Server = 'Organization'; Status = $status; Evidence = $evidence })
            }
            SubjectLabel   = $subjectLabel
            References     = @($Control.references)
            Remediation    = $Control.remediation
            Considerations = [string]$Control.considerations
        }
    }

    $serverResults = @()
    $exchangeServerCount = @($CollectionData.Servers | Where-Object {
            ($_.PSObject.Properties.Name -contains 'Exchange') -and
            $null -ne $_.Exchange -and
            ($_.Exchange.PSObject.Properties.Name -contains 'IsExchangeServer') -and
            [bool]$_.Exchange.IsExchangeServer
        }).Count
    $exchangeOnlyControlIds = @(
        'EDCA-SEC-014',
        'EDCA-GOV-002',
        'EDCA-DATA-001',
        'EDCA-RES-001',
        'EDCA-RES-003',
        'EDCA-SEC-021',
        'EDCA-TLS-001',
        'EDCA-SEC-001',
        'EDCA-GOV-001',
        'EDCA-SEC-020',
        'EDCA-SEC-009',
        'EDCA-SEC-008',
        'EDCA-SEC-002',
        'EDCA-DATA-009',
        'EDCA-DATA-010',
        'EDCA-SEC-027',
        'EDCA-MON-003',
        'EDCA-SEC-028',
        'EDCA-SEC-029',
        'EDCA-SEC-030',
        'EDCA-SEC-031',
        'EDCA-IAC-007',
        'EDCA-MON-004',
        'EDCA-MON-005',
        'EDCA-MON-006',
        'EDCA-IAC-012',
        'EDCA-DATA-011',
        'EDCA-DATA-012',
        'EDCA-DATA-013',
        'EDCA-IAC-026',
        'EDCA-IAC-027',
        'EDCA-RES-004',
        'EDCA-RES-005',
        'EDCA-RES-006',
        'EDCA-MON-007',
        'EDCA-GOV-005',
        'EDCA-GOV-006',
        'EDCA-GOV-007',
        'EDCA-SEC-033',
        'EDCA-TLS-013',
        'EDCA-DATA-014',
        'EDCA-DATA-015',
        'EDCA-IAC-013',
        'EDCA-RES-007',
        'EDCA-MON-009',
        'EDCA-MON-010',
        'EDCA-MON-011',
        'EDCA-GOV-008',
        'EDCA-RES-008',
        'EDCA-RES-009',
        'EDCA-GOV-010',
        'EDCA-TLS-015',
        'EDCA-TLS-016',
        'EDCA-TLS-017',
        'EDCA-SEC-034',
        'EDCA-TLS-020',
        'EDCA-SEC-035',
        'EDCA-GOV-012',
        'EDCA-RES-010',
        'EDCA-SEC-038',
        'EDCA-TLS-021',
        'EDCA-TLS-022',
        'EDCA-SEC-039',
        'EDCA-MON-012',
        'EDCA-DATA-017',
        'EDCA-DATA-018',
        'EDCA-SEC-040',
        'EDCA-TLS-030',
        'EDCA-TLS-031',
        'EDCA-TLS-032',
        'EDCA-TLS-033',
        'EDCA-TLS-034',
        'EDCA-TLS-035',
        'EDCA-TLS-036',
        'EDCA-DATA-019',
        'EDCA-TLS-037',
        'EDCA-TLS-038',
        'EDCA-TLS-039',
        'EDCA-TLS-040',
        'EDCA-TLS-041',
        'EDCA-TLS-042',
        'EDCA-TLS-043',
        'EDCA-TLS-044',
        'EDCA-TLS-045',
        'EDCA-TLS-046',
        'EDCA-TLS-047',
        'EDCA-TLS-048'
    )

    $exchangeBuilds = $null
    if ($Control.id -in @('EDCA-GOV-002', 'EDCA-SEC-038')) {
        $exchangeBuildsPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Config\exchange.builds.json'
        if (Test-Path -LiteralPath $exchangeBuildsPath) {
            try { $exchangeBuilds = Get-Content -LiteralPath $exchangeBuildsPath -Raw | ConvertFrom-Json } catch {}
        }
    }

    $subjectLabel = 'Server'

    foreach ($server in $CollectionData.Servers) {
        $serverName = ([string]$server.Server -split '\.')[0]
        if ($server.PSObject.Properties.Name -contains 'CollectionError') {
            # Determine server role using org-level EdgeServers list (Exchange metadata is
            # unavailable when collection failed). If the control does not apply to this
            # server's role, skip silently rather than surfacing the connectivity error.
            $ceIsEdge = $false
            if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and
                $null -ne $CollectionData.Organization -and
                ($CollectionData.Organization.PSObject.Properties.Name -contains 'EdgeServers')) {
                $ceIsEdge = @(@($CollectionData.Organization.EdgeServers) |
                    Where-Object { [string]$_.Name -eq $serverName }).Count -gt 0
            }
            $ceServerRole = if ($ceIsEdge) { 'Edge' } else { 'Mailbox' }

            if (($Control.PSObject.Properties.Name -contains 'roles') -and
                $null -ne $Control.roles -and
                @($Control.roles).Count -gt 0 -and
                $ceServerRole -notin @($Control.roles | ForEach-Object { [string]$_ })) {
                continue
            }

            $serverResults += [pscustomobject]@{
                Server   = $serverName
                Status   = 'Unknown'
                Evidence = $server.CollectionError
            }
            continue
        }

        $status = 'Unknown'
        $evidence = ''
        $dbServerResults = $null
        $isExchangeServer = (
            ($server.PSObject.Properties.Name -contains 'Exchange') -and
            $null -ne $server.Exchange -and
            ($server.Exchange.PSObject.Properties.Name -contains 'IsExchangeServer') -and
            [bool]$server.Exchange.IsExchangeServer
        )
        $isEdge = $isExchangeServer -and
        ($server.Exchange.PSObject.Properties.Name -contains 'IsEdge') -and
        [bool]$server.Exchange.IsEdge
        $serverRole = if ($isEdge) { 'Edge' } elseif ($isExchangeServer) { 'Mailbox' } else { 'Unknown' }

        # Role-aware skip: control declares roles and this Exchange server's role is not in the list.
        # No entry is added to $serverResults; the overall-status logic treats an empty non-skipped
        # set as 'Skipped', so the finding is still correctly marked N/A for role-filtered servers.
        if ($isExchangeServer -and
            ($Control.PSObject.Properties.Name -contains 'roles') -and
            $null -ne $Control.roles -and
            @($Control.roles).Count -gt 0 -and
            $serverRole -ne 'Unknown' -and
            $serverRole -notin @($Control.roles | ForEach-Object { [string]$_ })) {
            continue
        }

        if (($Control.id -in $exchangeOnlyControlIds) -and -not $isExchangeServer) {
            $serverResults += [pscustomobject]@{
                Server   = $serverName
                Status   = 'Skipped'
                Evidence = 'Exchange not detected on this server; control is not applicable.'
            }
            continue
        }

        switch ($Control.id) {
            'EDCA-SEC-014' {
                $entries = @($server.Exchange.ExtendedProtectionStatus)
                $oaItems = @()
                if ($server.Exchange.PSObject.Properties.Name -contains 'OutlookAnywhereSSLOffloading') {
                    $oaItems = @($server.Exchange.OutlookAnywhereSSLOffloading)
                }
                $sslOffloadingEnabled = @($oaItems | Where-Object { $null -ne $_.SSLOffloading -and [bool]$_.SSLOffloading })

                if ($entries.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No virtual directory Extended Protection data available.'
                }
                else {
                    $nonCompliant = @($entries | Where-Object { $_.ExtendedProtectionTokenChecking -notin @('Allow', 'Require') })
                    $issueLines = @()
                    if ($nonCompliant.Count -gt 0) {
                        $issueLines += @($nonCompliant | ForEach-Object { [string]$_.Identity })
                    }
                    if ($sslOffloadingEnabled.Count -gt 0) {
                        $issueLines += @($sslOffloadingEnabled | ForEach-Object { ('{0} (SSL Offloading enabled — incompatible with Extended Protection)' -f [string]$_.Identity) })
                    }

                    $status = if ($issueLines.Count -eq 0) { 'Pass' } else { 'Fail' }
                    if ($issueLines.Count -gt 0) {
                        $summary = ('{0} virtual director{1} non-compliant.' -f $issueLines.Count, $(if ($issueLines.Count -eq 1) { 'y' } else { 'ies' }))
                        $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $issueLines
                    }
                    else {
                        $evidence = ('Compliant — Extended Protection configured on all {0} virtual directories; SSL Offloading disabled.' -f $entries.Count)
                    }
                }
            }
            'EDCA-IAC-012' {
                $targetVdirTypes = @('Get-MapiVirtualDirectory', 'Get-OwaVirtualDirectory', 'Get-EcpVirtualDirectory', 'Get-WebServicesVirtualDirectory', 'Get-AutodiscoverVirtualDirectory')
                $entries = @($server.Exchange.ExtendedProtectionStatus | Where-Object { $_.VirtualDirectoryType -in $targetVdirTypes })
                if ($entries.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No virtual directory authentication method data available.'
                }
                else {
                    $missing = @($entries | Where-Object {
                            if ($_.VirtualDirectoryType -eq 'Get-MapiVirtualDirectory') {
                                $auth = [string]$_.IISAuthenticationMethods
                                ($auth -notmatch '(?i)\bNtlm\b') -and ($auth -notmatch '(?i)\bNegotiate\b')
                            }
                            else {
                                $auth = [string]$_.InternalAuthenticationMethods
                                ($auth -notmatch '(?i)\bNtlm\b') -and ($auth -notmatch '(?i)\bWindowsIntegrated\b')
                            }
                        })
                    $status = if ($missing.Count -eq 0) { 'Pass' } else { 'Unknown' }
                    $summary = ('Evaluated {0} virtual directories; missing Windows Integrated Authentication (NTLM/Negotiate): {1}.' -f $entries.Count, $missing.Count)
                    if ($missing.Count -gt 0) {
                        $missingDetails = @($missing | ForEach-Object {
                                $authField = if ($_.VirtualDirectoryType -eq 'Get-MapiVirtualDirectory') {
                                    'IISAuthenticationMethods={0}' -f [string]$_.IISAuthenticationMethods
                                }
                                else {
                                    'InternalAuthenticationMethods={0}' -f [string]$_.InternalAuthenticationMethods
                                }
                                '{0} | {1} | {2}' -f [string]$_.VirtualDirectoryType, [string]$_.Identity, $authField
                            })
                        $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $missingDetails
                    }
                    else {
                        $evidence = $summary
                    }
                }
            }
            'EDCA-GOV-002' {
                $productLine = Get-EDCAProductLineFromServerData -Server $server
                $buildNumber = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'BuildNumber') -and
                    -not [string]::IsNullOrWhiteSpace([string]$server.Exchange.BuildNumber)) {
                    $buildNumber = [string]$server.Exchange.BuildNumber
                }
                if ([string]::IsNullOrWhiteSpace($buildNumber)) {
                    $status = 'Unknown'
                    $evidence = ('Exchange build number unavailable (product line: {0}).' -f $productLine)
                }
                elseif ($null -eq $exchangeBuilds -or -not ($exchangeBuilds.PSObject.Properties.Name -contains $productLine)) {
                    switch ($productLine) {
                        'ExchangeSE' {
                            $status = 'Pass'
                            $evidence = ('Running build: {0}. Product line: ExchangeSE (supported).' -f $buildNumber)
                        }
                        'Exchange2016' {
                            $status = 'Unknown'
                            $evidence = ('Running build: {0}. Exchange2016 is out of support; migration to Exchange SE is recommended.' -f $buildNumber)
                        }
                        'Exchange2019' {
                            $status = 'Unknown'
                            $evidence = ('Running build: {0}. Exchange2019 is out of support; migration to Exchange SE is recommended.' -f $buildNumber)
                        }
                        default {
                            $status = 'Fail'
                            $evidence = ('Running build: {0}. Unrecognized product line: {1}.' -f $buildNumber, $productLine)
                        }
                    }
                }
                else {
                    $latestBuild = [string]$exchangeBuilds.$productLine
                    $runningVersion = $null
                    $latestVersion = $null
                    try { $runningVersion = [System.Version]$buildNumber } catch {}
                    try { $latestVersion = [System.Version]$latestBuild } catch {}
                    if ($null -eq $runningVersion) {
                        $status = 'Unknown'
                        $evidence = ('Build number could not be parsed as a version: {0}.' -f $buildNumber)
                    }
                    elseif ($null -eq $latestVersion) {
                        $status = 'Unknown'
                        $evidence = ('Running build: {0}; latest build not available in exchange.builds.json for {1}.' -f $buildNumber, $productLine)
                    }
                    else {
                        $eolSuffix = if ($productLine -in @('Exchange2016', 'Exchange2019')) {
                            (' Note: {0} is out of extended support; migration to Exchange SE is recommended.' -f $productLine)
                        }
                        else { '' }
                        if ($runningVersion -ge $latestVersion) {
                            $status = if ($productLine -in @('Exchange2016', 'Exchange2019')) { 'Unknown' } else { 'Pass' }
                            $evidence = ('Running build {0} matches or exceeds the latest known approved update ({1}).{2}' -f $buildNumber, $latestBuild, $eolSuffix)
                        }
                        else {
                            $status = 'Fail'
                            $evidence = ('Running build {0} is not the latest approved update. Latest known: {1}.{2}' -f $buildNumber, $latestBuild, $eolSuffix)
                        }
                    }
                }
            }
            'EDCA-SEC-038' {
                $productLine = Get-EDCAProductLineFromServerData -Server $server
                $buildNumber = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'BuildNumber') -and
                    -not [string]::IsNullOrWhiteSpace([string]$server.Exchange.BuildNumber)) {
                    $buildNumber = [string]$server.Exchange.BuildNumber
                }
                if ([string]::IsNullOrWhiteSpace($buildNumber)) {
                    $status = 'Unknown'
                    $evidence = ('Exchange build number unavailable (product line: {0}).' -f $productLine)
                }
                elseif ($null -eq $exchangeBuilds -or -not ($exchangeBuilds.PSObject.Properties.Name -contains $productLine)) {
                    switch ($productLine) {
                        'ExchangeSE' {
                            $status = 'Pass'
                            $evidence = ('Running build: {0}. Product line: ExchangeSE (supported).' -f $buildNumber)
                        }
                        'Exchange2016' {
                            $status = 'Unknown'
                            $evidence = ('Running build: {0}. Exchange2016 is out of support; migration to Exchange SE is recommended.' -f $buildNumber)
                        }
                        'Exchange2019' {
                            $status = 'Unknown'
                            $evidence = ('Running build: {0}. Exchange2019 is out of support; migration to Exchange SE is recommended.' -f $buildNumber)
                        }
                        default {
                            $status = 'Fail'
                            $evidence = ('Running build: {0}. Unrecognized product line: {1}.' -f $buildNumber, $productLine)
                        }
                    }
                }
                else {
                    $latestBuild = [string]$exchangeBuilds.$productLine
                    $runningVersion = $null
                    $latestVersion = $null
                    try { $runningVersion = [System.Version]$buildNumber } catch {}
                    try { $latestVersion = [System.Version]$latestBuild } catch {}
                    if ($null -eq $runningVersion) {
                        $status = 'Unknown'
                        $evidence = ('Build number could not be parsed as a version: {0}.' -f $buildNumber)
                    }
                    elseif ($null -eq $latestVersion) {
                        $status = 'Unknown'
                        $evidence = ('Running build: {0}; latest build not available in exchange.builds.json for {1}.' -f $buildNumber, $productLine)
                    }
                    else {
                        $eolSuffix = if ($productLine -in @('Exchange2016', 'Exchange2019')) {
                            (' Note: {0} is out of extended support; migration to Exchange SE is recommended.' -f $productLine)
                        }
                        else { '' }
                        if ($runningVersion -ge $latestVersion) {
                            $status = if ($productLine -in @('Exchange2016', 'Exchange2019')) { 'Unknown' } else { 'Pass' }
                            $evidence = ('Running build {0} matches or exceeds the latest known approved update ({1}).{2}' -f $buildNumber, $latestBuild, $eolSuffix)
                        }
                        else {
                            $status = 'Fail'
                            $evidence = ('Running build {0} is not the latest approved update. Latest known: {1}.{2}' -f $buildNumber, $latestBuild, $eolSuffix)
                        }
                    }
                }
            }
            'EDCA-DATA-005' {
                $tls10 = [bool]$server.Tls.Tls10Enabled
                $tls11 = [bool]$server.Tls.Tls11Enabled
                $status = if (-not $tls10 -and -not $tls11) { 'Pass' } else { 'Fail' }
                $evidence = ('TLS 1.0 is {0}; TLS 1.1 is {1}.' -f
                    (Get-EDCAStateDescriptor -Value $tls10 -Expectation 'Disabled'),
                    (Get-EDCAStateDescriptor -Value $tls11 -Expectation 'Disabled'))
            }
            'EDCA-DATA-006' {
                $status = Get-EDCAFindingStatusFromBool -Value $server.Tls.Tls12Enabled
                if ($null -eq $server.Tls.Tls12Enabled) {
                    $evidence = 'TLS 1.2 state unavailable.'
                }
                else {
                    $evidence = ('TLS 1.2 is {0}.' -f (Get-EDCAStateDescriptor -Value ([bool]$server.Tls.Tls12Enabled) -Expectation 'Enabled'))
                }
            }
            'EDCA-DATA-001' {
                $expired = @($server.Certificates | Where-Object { $_.IsExpired -and -not [string]::IsNullOrWhiteSpace([string]$_.Services) -and [string]$_.Services -ne 'None' })
                $status = if ($expired.Count -eq 0) { 'Pass' } else { 'Fail' }
                $summary = ('Expired certificates with assigned services: {0}' -f $expired.Count)
                if ($expired.Count -gt 0) {
                    $expiredDetails = @($expired | ForEach-Object {
                            '{0} | Subject={1} | NotAfter={2} | Services={3}' -f [string]$_.Thumbprint, [string]$_.Subject, [string]$_.NotAfter, [string]$_.Services
                        })
                    $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $expiredDetails
                }
                else {
                    $evidence = 'Compliant - no expired certificates with assigned services found.'
                }
            }
            'EDCA-RES-001' {
                $serviceHealth = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'ServiceHealth') -and $null -ne $server.Exchange.ServiceHealth) {
                    $serviceHealth = @($server.Exchange.ServiceHealth)
                }

                if ($null -eq $serviceHealth -or $serviceHealth.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Service health data unavailable.'
                }
                else {
                    $failingRoles = @($serviceHealth | Where-Object { $_.RequiredServicesRunning -eq $false })
                    if ($failingRoles.Count -eq 0) {
                        $status = 'Pass'
                        $evidence = 'Compliant — all required Exchange services are running.'
                    }
                    else {
                        $status = 'Fail'
                        $problemDetails = @($failingRoles | ForEach-Object {
                                $roleName = [string]$_.Role
                                $notRunning = @($_.ServicesNotRunning | ForEach-Object { [string]$_ })
                                ('{0}: {1}' -f $roleName, ($notRunning -join ', '))
                            })
                        $summary = ('Required services not running across {0} role(s).' -f $failingRoles.Count)
                        $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $problemDetails
                    }
                }
            }
            'EDCA-RES-003' {
                $replicationWarnings = @()
                if (($server.Exchange.PSObject.Properties.Name -contains 'CollectionWarnings') -and $null -ne $server.Exchange.CollectionWarnings) {
                    $replicationWarnings = @($server.Exchange.CollectionWarnings | Where-Object { [string]$_ -match '(?i)^Test-ReplicationHealth failed:' })
                }

                $hasNoDagWarning = @($replicationWarnings | Where-Object {
                        [string]$_ -match '(?i)(not\s+(part|member).+database\s+availability\s+group|no\s+database\s+availability\s+group|no\s+replicated\s+mailbox\s+database|dag\s+not\s+configured|not\s+configured\s+for\s+high\s+availability)'
                    }).Count -gt 0

                $isDagMember = $null
                if ($server.Exchange.PSObject.Properties.Name -contains 'IsDagMember' -and $null -ne $server.Exchange.IsDagMember) {
                    $isDagMember = [bool]$server.Exchange.IsDagMember
                }

                if ($hasNoDagWarning -or ($isDagMember -eq $false) -or (($null -eq $isDagMember) -and ($exchangeServerCount -le 1) -and ($server.Exchange.ReplicationHealthPassed -ne $true))) {
                    $status = 'Skipped'
                    $evidence = 'No DAG detected for this server scope; replication health control is not applicable.'
                }
                elseif ($null -eq $server.Exchange.ReplicationHealthPassed) {
                    $status = 'Unknown'
                    if ($replicationWarnings.Count -gt 0) {
                        $evidence = ('Replication health data unavailable. {0}' -f [string]$replicationWarnings[0])
                    }
                    else {
                        $evidence = 'Replication health data unavailable.'
                    }
                }
                else {
                    $status = if ($server.Exchange.ReplicationHealthPassed) { 'Pass' } else { 'Fail' }
                    $evidence = ('Replication health has {0}.' -f (Get-EDCAStateDescriptor -Value ([bool]$server.Exchange.ReplicationHealthPassed) -Expectation 'Passed'))
                }
            }
            'EDCA-SEC-022' {
                $policy = [string]$server.OS.ExecutionPolicy
                if ([string]::IsNullOrWhiteSpace($policy)) {
                    $status = 'Unknown'
                    $evidence = 'Execution policy unavailable.'
                }
                else {
                    $status = if ($policy -eq 'Unrestricted') { 'Fail' } else { 'Pass' }
                    $evidence = if ($status -eq 'Pass') { ('Compliant — execution policy is {0}.' -f $policy) } else { ('Execution policy is {0}; Unrestricted is not recommended.' -f $policy) }
                }
            }
            'EDCA-PERF-002' {
                $hasPowerPlan = ($server.PSObject.Properties.Name -contains 'OS') -and ($server.OS.PSObject.Properties.Name -contains 'PowerPlan')
                if (-not $hasPowerPlan -or $null -eq $server.OS.PowerPlan -or -not ($server.OS.PowerPlan.PSObject.Properties.Name -contains 'HighPerformanceSet')) {
                    $status = 'Unknown'
                    $evidence = 'Power plan data unavailable.'
                }
                else {
                    $status = if ([bool]$server.OS.PowerPlan.HighPerformanceSet) { 'Pass' } else { 'Fail' }
                    $evidence = if ($status -eq 'Pass') { 'Compliant — High Performance power plan is active.' } else { ('Active power plan: {0}; High Performance plan is not active.' -f [string]$server.OS.PowerPlan.ActiveSchemeName) }
                }
            }
            'EDCA-PERF-008' {
                $pageFileCount = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and ($server.OS.PSObject.Properties.Name -contains 'PageFile') -and $null -ne $server.OS.PageFile -and ($server.OS.PageFile.PSObject.Properties.Name -contains 'Count')) {
                    $pageFileCount = [int]$server.OS.PageFile.Count
                }

                if ($null -eq $pageFileCount) {
                    $status = 'Unknown'
                    $evidence = 'Page file configuration unavailable.'
                }
                else {
                    $status = if ($pageFileCount -eq 1) { 'Pass' } else { 'Fail' }
                    $evidence = if ($status -eq 'Pass') { 'Compliant — single page file configured.' } else { ('Page file entries: {0} (expected exactly 1).' -f $pageFileCount) }
                }
            }
            'EDCA-PERF-007' {
                $adapterCount = $null
                $enabledCount = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and ($server.OS.PSObject.Properties.Name -contains 'NicRss') -and $null -ne $server.OS.NicRss) {
                    if ($server.OS.NicRss.PSObject.Properties.Name -contains 'AdapterCount') {
                        $adapterCount = $server.OS.NicRss.AdapterCount
                    }
                    if ($server.OS.NicRss.PSObject.Properties.Name -contains 'EnabledCount') {
                        $enabledCount = $server.OS.NicRss.EnabledCount
                    }
                }

                if ($null -eq $adapterCount -or $null -eq $enabledCount) {
                    $status = 'Unknown'
                    $evidence = 'NIC RSS data unavailable.'
                }
                else {
                    $status = if ([int]$enabledCount -ge 1) { 'Pass' } else { 'Fail' }
                    $evidence = if ($status -eq 'Pass') { ('Compliant — {0} of {1} active adapters have RSS enabled.' -f [int]$enabledCount, [int]$adapterCount) } else { ('RSS-enabled adapters: {0} of {1}. RSS is not enabled on any adapter.' -f [int]$enabledCount, [int]$adapterCount) }
                }
            }
            'EDCA-PERF-003' {
                $cores = 0
                $logical = 0
                if ($server.OS.PSObject.Properties.Name -contains 'NumberOfCores') {
                    $cores = [int]$server.OS.NumberOfCores
                }
                if ($server.OS.PSObject.Properties.Name -contains 'NumberOfLogicalProcessors') {
                    $logical = [int]$server.OS.NumberOfLogicalProcessors
                }

                if ($cores -le 0 -or $logical -le 0) {
                    $status = 'Unknown'
                    $evidence = 'Processor topology data unavailable.'
                }
                else {
                    $status = if ($logical -gt $cores) { 'Fail' } else { 'Pass' }
                    $evidence = if ($status -eq 'Pass') { ('Compliant — {0} physical cores, Hyper-Threading not detected.' -f $cores) } else { ('Cores: {0}; Logical processors: {1} — Hyper-Threading detected.' -f $cores, $logical) }
                }
            }
            'EDCA-PERF-011' {
                $vmx = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and ($server.OS.PSObject.Properties.Name -contains 'VmxNet3')) {
                    $vmx = $server.OS.VmxNet3
                }

                if ($null -eq $vmx) {
                    $status = 'Unknown'
                    $evidence = 'VMXNET3 data unavailable.'
                }
                elseif (-not [bool]$vmx.CommandAvailable) {
                    $status = 'Unknown'
                    $evidence = 'VMXNET3 checks unavailable because required NetAdapter cmdlets are missing.'
                }
                else {
                    $adapters = @($vmx.Adapters)
                    if ($adapters.Count -eq 0) {
                        $status = 'Skipped'
                        $evidence = 'No VMXNET3 adapters found; control is not applicable to this server.'
                    }
                    else {
                        # RAG thresholds per HealthChecker PacketsLossCheck:
                        #   Good    : PacketsReceivedDiscarded = 0        -> Pass (green)
                        #   Warning : PacketsReceivedDiscarded < 1000     -> Unknown (amber)
                        #   Error   : PacketsReceivedDiscarded >= 1000    -> Fail (red)
                        $redAdapters = @()
                        $amberAdapters = @()
                        $passAdapters = @()

                        foreach ($adapter in $adapters) {
                            $adapterName = [string]$adapter.Name

                            # Packet loss indicator
                            $discardedPackets = [int64]0
                            if ($adapter.PSObject.Properties.Name -contains 'DiscardedPacketsTotal') {
                                $discardedPackets = [int64]$adapter.DiscardedPacketsTotal
                            }

                            # Small Rx Buffers (recommended: 8192)
                            $smallRxBufDisplay = 'not found'
                            if (($adapter.PSObject.Properties.Name -contains 'HasBufferProperties') -and [bool]$adapter.HasBufferProperties -and
                                ($adapter.PSObject.Properties.Name -contains 'BufferProperties')) {
                                $smallRxEntry = @($adapter.BufferProperties | Where-Object { [string]$_.DisplayName -match 'Small' }) | Select-Object -First 1
                                if ($null -eq $smallRxEntry) { $smallRxEntry = @($adapter.BufferProperties) | Select-Object -First 1 }
                                if ($null -ne $smallRxEntry) { $smallRxBufDisplay = ('{0}={1}' -f [string]$smallRxEntry.DisplayName, [string]$smallRxEntry.DisplayValue) }
                            }

                            # Rx Ring #1 Size (recommended: 4096)
                            $rxRing1Display = 'not found'
                            if (($adapter.PSObject.Properties.Name -contains 'HasRingProperties') -and [bool]$adapter.HasRingProperties -and
                                ($adapter.PSObject.Properties.Name -contains 'RingProperties')) {
                                $rxRing1Entry = @($adapter.RingProperties | Where-Object { [string]$_.DisplayName -match '#\s*1|Ring\s*1' }) | Select-Object -First 1
                                if ($null -eq $rxRing1Entry) { $rxRing1Entry = @($adapter.RingProperties) | Select-Object -First 1 }
                                if ($null -ne $rxRing1Entry) { $rxRing1Display = ('{0}={1}' -f [string]$rxRing1Entry.DisplayName, [string]$rxRing1Entry.DisplayValue) }
                            }

                            $detail = ('{0}: PacketsReceivedDiscarded={1}; Small Rx Buffers: {2} (recommended: 8192); Rx Ring #1 Size: {3} (recommended: 4096)' -f
                                $adapterName, $discardedPackets, $smallRxBufDisplay, $rxRing1Display)

                            if ($discardedPackets -ge 1000) {
                                $redAdapters += $detail
                            }
                            elseif ($discardedPackets -gt 0) {
                                # Intentionally warning-oriented (amber) for BestPractice reporting.
                                $amberAdapters += $detail
                            }
                            else {
                                $passAdapters += $detail
                            }
                        }

                        if ($redAdapters.Count -gt 0) {
                            $status = 'Fail'
                            $summary = ('VMXNET3 adapters evaluated: {0}; {1} adapter(s) with high packet loss (>= 1000 discards).' -f $adapters.Count, $redAdapters.Count)
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements ($redAdapters + $amberAdapters + $passAdapters)
                        }
                        elseif ($amberAdapters.Count -gt 0) {
                            # Intentionally warning-oriented (amber) for BestPractice reporting.
                            $status = 'Unknown'
                            $summary = ('VMXNET3 adapters evaluated: {0}; {1} adapter(s) with packet loss detected (< 1000 discards).' -f $adapters.Count, $amberAdapters.Count)
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements ($amberAdapters + $passAdapters)
                        }
                        else {
                            $status = 'Pass'
                            $summary = ('VMXNET3 adapters evaluated: {0}; no discarded packets detected.' -f $adapters.Count)
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $passAdapters
                        }
                    }
                }
            }
            'EDCA-PERF-013' {
                $ramGB = $null
                $pfItems = $null
                $pfCount = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and ($server.OS.PSObject.Properties.Name -contains 'TotalPhysicalMemoryGB')) {
                    $ramGB = [double]$server.OS.TotalPhysicalMemoryGB
                }
                if (($server.PSObject.Properties.Name -contains 'OS') -and ($server.OS.PSObject.Properties.Name -contains 'PageFile') -and $null -ne $server.OS.PageFile) {
                    if ($server.OS.PageFile.PSObject.Properties.Name -contains 'Items') {
                        $pfItems = @($server.OS.PageFile.Items)
                    }
                    if ($server.OS.PageFile.PSObject.Properties.Name -contains 'Count') {
                        $pfCount = [int]$server.OS.PageFile.Count
                    }
                }

                if ($null -eq $ramGB -or $null -eq $pfItems -or $null -eq $pfCount) {
                    $status = 'Unknown'
                    $evidence = 'Page file or memory data unavailable.'
                }
                elseif ($pfCount -ne 1) {
                    $status = 'Skipped'
                    $evidence = ('Page file count is {0}; EDCA-PERF-013 requires exactly one page file (see EDCA-PERF-008).' -f $pfCount)
                }
                else {
                    $ramMB = [int][math]::Round($ramGB * 1024)

                    # Target size per Exchange version
                    $productLine = Get-EDCAProductLineFromServerData -Server $server
                    $targetMB = if ($productLine -eq 'Exchange2016') {
                        if ($ramMB -ge 32768) { 32778 } else { $ramMB + 10 }
                    }
                    else {
                        [int][math]::Ceiling($ramMB * 0.25)
                    }

                    $pf = $pfItems[0]
                    $initialSize = [int]$pf.InitialSize
                    $maximumSize = [int]$pf.MaximumSize
                    $pfName = [string]$pf.Name
                    $fixedSize = ($initialSize -eq $maximumSize)
                    $correctSize = ($initialSize -eq $targetMB)

                    if ($fixedSize -and $correctSize) {
                        $status = 'Pass'
                        $evidence = ('Compliant — page file is fixed-size at {0} MB (target: {1} MB) on {2}.' -f $initialSize, $targetMB, $pfName)
                    }
                    else {
                        $status = 'Fail'
                        $issues = @()
                        if (-not $fixedSize) {
                            $issues += ('Dynamic sizing detected (InitialSize={0} MB, MaximumSize={1} MB)' -f $initialSize, $maximumSize)
                        }
                        if (-not $correctSize) {
                            $issues += ('Non-compliant: Size is {0} MB (expected {1} MB)' -f $initialSize, $targetMB)
                        }
                        $evidence = ('{0}; location: {1}.' -f ($issues -join '; '), $pfName)
                    }
                }
            }
            'EDCA-PERF-014' {
                $ramGB = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and ($server.OS.PSObject.Properties.Name -contains 'TotalPhysicalMemoryGB')) {
                    $ramGB = [double]$server.OS.TotalPhysicalMemoryGB
                }

                if ($null -eq $ramGB) {
                    $status = 'Unknown'
                    $evidence = 'Memory data unavailable.'
                }
                else {
                    $productLine = Get-EDCAProductLineFromServerData -Server $server

                    if ($productLine -eq 'Unknown') {
                        $status = 'Unknown'
                        $evidence = ('Exchange version could not be determined; cannot evaluate memory requirements. Installed RAM: {0} GB.' -f $ramGB)
                    }
                    else {
                        # Detect Edge Transport role via org-level EdgeServers list
                        # (ServerRole is not stored in per-server collected data)
                        $isEdge = $false
                        if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and
                            $null -ne $CollectionData.Organization -and
                            ($CollectionData.Organization.PSObject.Properties.Name -contains 'EdgeServers')) {
                            $isEdge = @(@($CollectionData.Organization.EdgeServers) | Where-Object { [string]$_.Name -eq $serverName }).Count -gt 0
                        }

                        $roleLabel = if ($isEdge) { 'Edge Transport' } else { 'Mailbox' }

                        # Thresholds by version and role
                        # Edge Transport: Microsoft only documents a minimum; no upper limit published
                        if ($productLine -eq 'Exchange2016') {
                            $minGB = if ($isEdge) { 4 } else { 8 }
                            $maxGB = if ($isEdge) { $null } else { 192 }
                        }
                        else {
                            # Exchange2019 and ExchangeSE share the same published requirements
                            $minGB = if ($isEdge) { 8 } else { 32 }
                            $maxGB = if ($isEdge) { $null } else { 256 }
                        }

                        $belowMin = $ramGB -lt $minGB
                        $aboveMax = ($null -ne $maxGB) -and ($ramGB -gt $maxGB)

                        if (-not $belowMin -and -not $aboveMax) {
                            $status = 'Pass'
                            $rangeLabel = if ($null -ne $maxGB) { ('{0}–{1} GB' -f $minGB, $maxGB) } else { ('minimum {0} GB' -f $minGB) }
                            $evidence = ('Compliant — {0} GB RAM installed on {1} server ({2}); supported range: {3}.' -f $ramGB, $roleLabel, $productLine, $rangeLabel)
                        }
                        else {
                            $status = 'Fail'
                            $issues = @()
                            if ($belowMin) {
                                $issues += ('RAM ({0} GB) is below the {1} GB minimum for {2} {3}' -f $ramGB, $minGB, $productLine, $roleLabel)
                            }
                            if ($aboveMax) {
                                $issues += ('RAM ({0} GB) exceeds the {1} GB maximum supported for {2} {3}' -f $ramGB, $maxGB, $productLine, $roleLabel)
                            }
                            $evidence = ('{0}.' -f ($issues -join '; '))
                        }
                    }
                }
            }
            'EDCA-PERF-015' {
                $cores = $null
                $logical = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS) {
                    if ($server.OS.PSObject.Properties.Name -contains 'NumberOfCores') {
                        $cores = [int]$server.OS.NumberOfCores
                    }
                    if ($server.OS.PSObject.Properties.Name -contains 'NumberOfLogicalProcessors') {
                        $logical = [int]$server.OS.NumberOfLogicalProcessors
                    }
                }

                if ($null -eq $cores -or $null -eq $logical) {
                    $status = 'Unknown'
                    $evidence = 'Processor topology data unavailable.'
                }
                else {
                    $productLine = Get-EDCAProductLineFromServerData -Server $server

                    if ($productLine -eq 'Unknown') {
                        $status = 'Unknown'
                        $evidence = ('Exchange version could not be determined; cannot evaluate processor core limit. Physical cores: {0}; logical processors: {1}.' -f $cores, $logical)
                    }
                    else {
                        # Detect Edge Transport role via org-level EdgeServers list
                        # (ServerRole is not stored in per-server collected data)
                        $isEdge = $false
                        if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and
                            $null -ne $CollectionData.Organization -and
                            ($CollectionData.Organization.PSObject.Properties.Name -contains 'EdgeServers')) {
                            $isEdge = @(@($CollectionData.Organization.EdgeServers) | Where-Object { [string]$_.Name -eq $serverName }).Count -gt 0
                        }

                        $roleLabel = if ($isEdge) { 'Edge Transport' } else { 'Mailbox' }

                        # Maximum supported physical cores by version (same limit for both roles)
                        $maxCores = if ($productLine -eq 'Exchange2016') { 24 } else { 48 }

                        # Virtual processor over-allocation check: logical > physical cores indicates
                        # vCPUs exceeding pCPUs, which is not supported for Exchange VMs
                        $vRatio = if ($cores -gt 0) { [math]::Round($logical / $cores, 2) } else { $null }
                        $ratioExceed = ($null -ne $vRatio) -and ($vRatio -gt 2)

                        $coreExceed = $cores -gt $maxCores

                        if (-not $coreExceed -and -not $ratioExceed) {
                            $status = 'Pass'
                            $ratioNote = if ($null -ne $vRatio) { (' vCPU:pCore ratio: {0}:1.' -f $vRatio) } else { '' }
                            $evidence = ('Compliant — {0} physical cores on {1} server ({2}); maximum: {3}.{4}' -f $cores, $roleLabel, $productLine, $maxCores, $ratioNote)
                        }
                        else {
                            $status = 'Fail'
                            $issues = @()
                            if ($coreExceed) {
                                $issues += ('physical core count ({0}) exceeds the {1}-core maximum for {2} {3}' -f $cores, $maxCores, $productLine, $roleLabel)
                            }
                            if ($ratioExceed) {
                                $issues += ('virtual processor to physical core ratio ({0}:1) exceeds the supported 2:1 maximum ({1} logical processors, {2} physical cores)' -f $vRatio, $logical, $cores)
                            }
                            $evidence = ('{0}.' -f ($issues -join '; '))
                        }
                    }
                }
            }
            'EDCA-PERF-016' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; TcpAckFrequency optimisation is not applicable.'
                    break
                }

                $ackAdapters = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'TcpAckFrequencyAdapters')) {
                    $ackAdapters = @($server.Exchange.TcpAckFrequencyAdapters)
                }

                if ($null -eq $ackAdapters) {
                    $status = 'Unknown'
                    $evidence = 'TcpAckFrequency adapter data is unavailable.'
                    break
                }

                if ($ackAdapters.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No IP-enabled network adapters were found; cannot evaluate TcpAckFrequency.'
                    break
                }

                $badOne = @($ackAdapters | Where-Object { $null -ne $_.TcpAckFrequency -and [int]$_.TcpAckFrequency -eq 1 })
                $badHigh = @($ackAdapters | Where-Object { $null -ne $_.TcpAckFrequency -and [int]$_.TcpAckFrequency -ge 3 })

                if ($badHigh.Count -gt 0) {
                    $status = 'Fail'
                    $details = @($badHigh | ForEach-Object { ('{0} (TcpAckFrequency={1})' -f [string]$_.AdapterDescription, [int]$_.TcpAckFrequency) })
                    $evidence = ('{0} of {1} IP-enabled adapter(s) have TcpAckFrequency set to {2} or above (delayed ACK extended beyond default): {3}.' -f $badHigh.Count, $ackAdapters.Count, 3, ($details -join '; '))
                }
                elseif ($badOne.Count -gt 0) {
                    $status = 'Unknown'
                    $details = @($badOne | ForEach-Object { ('{0} (TcpAckFrequency=1)' -f [string]$_.AdapterDescription) })
                    $evidence = ('{0} of {1} IP-enabled adapter(s) have TcpAckFrequency=1 (delayed ACK disabled — increases ACK packet rate, CPU load, and network jitter): {2}.' -f $badOne.Count, $ackAdapters.Count, ($details -join '; '))
                }
                else {
                    $status = 'Pass'
                    $details = @($ackAdapters | ForEach-Object {
                            $val = if ($null -eq $_.TcpAckFrequency) { 'not set' } else { 'TcpAckFrequency={0}' -f [int]$_.TcpAckFrequency }
                            '{0} ({1})' -f [string]$_.AdapterDescription, $val
                        })
                    $evidence = ('TcpAckFrequency is at the default on all {0} IP-enabled adapter(s): {1}.' -f $ackAdapters.Count, ($details -join '; '))
                }
            }
            'EDCA-PERF-017' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; VMware Introspection check is not applicable.'
                    break
                }

                $introspection = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and ($server.OS.PSObject.Properties.Name -contains 'VmwareIntrospection')) {
                    $introspection = $server.OS.VmwareIntrospection
                }

                if ($null -eq $introspection) {
                    $status = 'Skipped'
                    $evidence = 'Server is not running on VMware; VMware Introspection drivers are not applicable.'
                    break
                }

                $vsepfltRunning = $false
                $vnetfltRunning = $false
                if ($introspection.PSObject.Properties.Name -contains 'VsepfltRunning') { $vsepfltRunning = [bool]$introspection.VsepfltRunning }
                if ($introspection.PSObject.Properties.Name -contains 'VnetfltRunning') { $vnetfltRunning = [bool]$introspection.VnetfltRunning }

                if (-not $vsepfltRunning -and -not $vnetfltRunning) {
                    $status = 'Pass'
                    $evidence = 'VMware NSX file introspection (vsepflt) and network introspection (vnetflt) drivers are not running.'
                }
                else {
                    $status = 'Fail'
                    $running = @()
                    if ($vsepfltRunning) { $running += 'vsepflt (file introspection)' }
                    if ($vnetfltRunning) { $running += 'vnetflt (network introspection)' }
                    $evidence = ('VMware NSX Introspection driver(s) are running and may introduce network latency: {0}.' -f ($running -join ', '))
                }
            }
            'EDCA-SEC-010' {
                $systemVolume = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and ($server.OS.PSObject.Properties.Name -contains 'SystemVolume')) {
                    $systemVolume = $server.OS.SystemVolume
                }

                if ($null -eq $systemVolume) {
                    $status = 'Unknown'
                    $evidence = 'System volume filesystem details are unavailable.'
                }
                else {
                    $fileSystem = ''
                    $blockSize = $null
                    if ($systemVolume.PSObject.Properties.Name -contains 'FileSystem') {
                        $fileSystem = [string]$systemVolume.FileSystem
                    }
                    if ($systemVolume.PSObject.Properties.Name -contains 'BlockSize') {
                        $blockSize = $systemVolume.BlockSize
                    }

                    if ([string]::IsNullOrWhiteSpace($fileSystem)) {
                        $status = 'Unknown'
                        $evidence = 'System volume filesystem value is empty.'
                    }
                    else {
                        $status = if ($fileSystem.Equals('NTFS', [System.StringComparison]::OrdinalIgnoreCase)) { 'Pass' } else { 'Fail' }
                        $evidence = if ($status -eq 'Pass') { ('Compliant — system drive {0} is NTFS.' -f [string]$server.OS.SystemDrive) } else { ('System drive {0} filesystem: {1} (expected NTFS); block size: {2}' -f [string]$server.OS.SystemDrive, $fileSystem, [string]$blockSize) }
                    }
                }
            }
            'EDCA-SEC-009' {
                $databaseStoragePaths = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and ($server.Exchange.PSObject.Properties.Name -contains 'DatabaseStoragePaths')) {
                    $databaseStoragePaths = @($server.Exchange.DatabaseStoragePaths)
                }

                if ($databaseStoragePaths.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Mailbox database/log storage paths unavailable (may not be a mailbox server role).'
                }
                else {
                    $dbDrives = @()
                    foreach ($storagePath in $databaseStoragePaths) {
                        $storagePathText = [string]$storagePath
                        if ($storagePathText -match '^([A-Za-z]:)') {
                            $dbDrives += $matches[1].ToUpperInvariant()
                        }
                    }

                    $dbDrives = @($dbDrives | Sort-Object -Unique)
                    if ($dbDrives.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = ('Could not resolve local drive letters from mailbox database/log paths: {0}' -f ($databaseStoragePaths -join ', '))
                    }
                    else {
                        $volumes = @()
                        if (($server.PSObject.Properties.Name -contains 'OS') -and ($server.OS.PSObject.Properties.Name -contains 'Volumes')) {
                            $volumes = @($server.OS.Volumes)
                        }

                        $unsupportedFileSystems = @()
                        $unmappedDrives = @()
                        foreach ($dbDrive in $dbDrives) {
                            $matchedVolume = @($volumes | Where-Object { ([string]$_.DriveLetter).Equals($dbDrive, [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1)
                            if ($matchedVolume.Count -eq 0) {
                                $unmappedDrives += $dbDrive
                                continue
                            }

                            $fileSystem = [string]$matchedVolume[0].FileSystem
                            if ([string]::IsNullOrWhiteSpace($fileSystem) -or ($fileSystem -notin @('NTFS', 'ReFS'))) {
                                $unsupportedFileSystems += ('{0}:{1}' -f $dbDrive, $fileSystem)
                            }
                        }

                        if ($unsupportedFileSystems.Count -gt 0) {
                            $status = 'Fail'
                            $summary = 'Unsupported database/log filesystem(s). Supported: NTFS/ReFS.'
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $unsupportedFileSystems
                        }
                        elseif ($unmappedDrives.Count -gt 0) {
                            $status = 'Unknown'
                            $evidence = ('Could not map database/log drive(s) to OS volume metadata: {0}' -f ($unmappedDrives -join ', '))
                        }
                        else {
                            $status = 'Pass'
                            $evidence = ('Database/log drives validated on supported filesystems (NTFS/ReFS): {0}' -f ($dbDrives -join ', '))
                        }
                    }
                }
            }
            'EDCA-SEC-008' {
                $databaseStoragePaths = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and ($server.Exchange.PSObject.Properties.Name -contains 'DatabaseStoragePaths')) {
                    $databaseStoragePaths = @($server.Exchange.DatabaseStoragePaths)
                }

                if ($databaseStoragePaths.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Mailbox database/log storage paths unavailable (may not be a mailbox server role).'
                }
                else {
                    $volumes = @()
                    if (($server.PSObject.Properties.Name -contains 'OS') -and ($server.OS.PSObject.Properties.Name -contains 'Volumes')) {
                        $volumes = @($server.OS.Volumes | Where-Object {
                                ($_.PSObject.Properties.Name -contains 'DeviceID') -and
                                -not [string]::IsNullOrWhiteSpace([string]$_.DeviceID) -and
                                ($_.PSObject.Properties.Name -contains 'Name') -and
                                -not [string]::IsNullOrWhiteSpace([string]$_.Name)
                            })
                    }
                    $getVolumeForPath = {
                        param([string]$Path, [object[]]$Vols)
                        $normPath = $Path.TrimEnd('\') + '\'
                        $bestMatch = $null
                        $bestLen = -1
                        foreach ($vol in $Vols) {
                            $mountPath = ([string]$vol.Name).TrimEnd('\') + '\'
                            if ($normPath.StartsWith($mountPath, [System.StringComparison]::OrdinalIgnoreCase) -and $mountPath.Length -gt $bestLen) {
                                $bestMatch = $vol
                                $bestLen = $mountPath.Length
                            }
                        }
                        return $bestMatch
                    }
                    $seenDeviceIds = @{}
                    $matchedVolumeInfos = @()
                    foreach ($storagePath in $databaseStoragePaths) {
                        $vol = & $getVolumeForPath -Path ([string]$storagePath) -Vols $volumes
                        if ($null -eq $vol) {
                            $key = [string]$storagePath
                            if (-not $seenDeviceIds.ContainsKey($key)) {
                                $seenDeviceIds[$key] = $true
                                $matchedVolumeInfos += [pscustomobject]@{ Path = [string]$storagePath; Vol = $null }
                            }
                        }
                        else {
                            $devId = [string]$vol.DeviceID
                            if (-not $seenDeviceIds.ContainsKey($devId)) {
                                $seenDeviceIds[$devId] = $true
                                $matchedVolumeInfos += [pscustomobject]@{ Path = [string]$vol.Name; Vol = $vol }
                            }
                        }
                    }
                    $nonCompliant = @()
                    $unknownPaths = @()
                    foreach ($info in $matchedVolumeInfos) {
                        if ($null -eq $info.Vol) { $unknownPaths += $info.Path; continue }
                        $blockSize = $info.Vol.BlockSize
                        if ($null -eq $blockSize) { $unknownPaths += $info.Path; continue }
                        if ([int64]$blockSize -ne 65536) {
                            $nonCompliant += ('{0}: block size {1}' -f $info.Path, [int64]$blockSize)
                        }
                    }
                    if ($matchedVolumeInfos.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = ('Could not resolve storage paths to volumes: {0}' -f ($databaseStoragePaths -join ', '))
                    }
                    elseif ($nonCompliant.Count -gt 0) {
                        $status = 'Fail'
                        $evidence = Format-EDCAEvidenceWithElements -Summary 'Database/log volume block size should be 65536 (64KB).' -Elements $nonCompliant
                    }
                    elseif ($unknownPaths.Count -gt 0) {
                        $status = 'Unknown'
                        $evidence = ('Could not determine block size for path(s): {0}' -f ($unknownPaths -join ', '))
                    }
                    else {
                        $volPaths = @($matchedVolumeInfos | ForEach-Object { $_.Path })
                        $status = 'Pass'
                        $evidence = ('Database/log volume block size validated at 65536 (64KB): {0}' -f ($volPaths -join ', '))
                    }
                }
            }
            'EDCA-SEC-021' {
                $pop = $null
                $imap = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and ($server.Exchange.PSObject.Properties.Name -contains 'Pop3ServiceStatus')) {
                    $pop = [string]$server.Exchange.Pop3ServiceStatus
                }
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and ($server.Exchange.PSObject.Properties.Name -contains 'Imap4ServiceStatus')) {
                    $imap = [string]$server.Exchange.Imap4ServiceStatus
                }

                if ([string]::IsNullOrWhiteSpace($pop) -and [string]::IsNullOrWhiteSpace($imap)) {
                    $status = 'Unknown'
                    $evidence = 'POP3/IMAP service status unavailable.'
                }
                else {
                    $legacyEnabled = @($pop, $imap | Where-Object { $_ -eq 'Running' }).Count -gt 0
                    $status = if ($legacyEnabled) { 'Fail' } else { 'Pass' }
                    $evidence = if ($status -eq 'Pass') { 'Compliant — POP3 and IMAP4 services are not running.' } else { ('POP3: {0}; IMAP4: {1}' -f $pop, $imap) }
                }
            }
            'EDCA-TLS-001' {
                $connectors = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and ($server.Exchange.PSObject.Properties.Name -contains 'ReceiveConnectors')) {
                    $connectors = @($server.Exchange.ReceiveConnectors)
                }

                if ($connectors.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Receive connector data unavailable.'
                }
                else {
                    $hasDedicatedExternal = @($connectors | Where-Object { ([string]$_.PermissionGroups -match 'AnonymousUsers') -and ([string]$_.AuthMechanism -match 'Tls') }).Count -gt 0
                    $hasDedicatedInternal = @($connectors | Where-Object { ([string]$_.PermissionGroups -match 'ExchangeServers|ExchangeUsers') -and ([string]$_.PermissionGroups -notmatch 'AnonymousUsers') }).Count -gt 0

                    if ($isEdge) {
                        # Edge Transport servers only accept inbound internet mail; no internal relay
                        # connector is expected or required.
                        $status = if ($hasDedicatedExternal) { 'Pass' } else { 'Fail' }
                        $summary = ('Connectors evaluated: {0}; external relay pattern is {1} (internal relay pattern not required on Edge Transport).' -f
                            $connectors.Count,
                            (Get-EDCAStateDescriptor -Value $hasDedicatedExternal -Expectation 'Present'))

                        if ($status -eq 'Fail') {
                            $connectorDetails = @($connectors | ForEach-Object {
                                    '{0} | PermissionGroups={1} | AuthMechanism={2}' -f [string]$_.Identity, [string]$_.PermissionGroups, [string]$_.AuthMechanism
                                })
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements (@('Missing external relay connector pattern: AnonymousUsers + TLS authentication.') + @($connectorDetails))
                        }
                        else {
                            $evidence = ('Compliant — external relay connector pattern detected ({0} connectors). Internal relay pattern not required on Edge Transport.' -f $connectors.Count)
                        }
                    }
                    else {
                        $status = if ($hasDedicatedExternal -and $hasDedicatedInternal) { 'Pass' } else { 'Fail' }
                        $summary = ('Connectors evaluated: {0}; external relay pattern is {1}; internal relay pattern is {2}.' -f
                            $connectors.Count,
                            (Get-EDCAStateDescriptor -Value $hasDedicatedExternal -Expectation 'Present'),
                            (Get-EDCAStateDescriptor -Value $hasDedicatedInternal -Expectation 'Present'))

                        if ($status -eq 'Fail') {
                            $missingPatterns = @()
                            if (-not $hasDedicatedExternal) {
                                $missingPatterns += 'Missing external relay connector pattern: AnonymousUsers + TLS authentication.'
                            }
                            if (-not $hasDedicatedInternal) {
                                $missingPatterns += 'Missing internal relay connector pattern: ExchangeServers/ExchangeUsers without AnonymousUsers.'
                            }

                            $connectorDetails = @($connectors | ForEach-Object {
                                    '{0} | PermissionGroups={1} | AuthMechanism={2}' -f [string]$_.Identity, [string]$_.PermissionGroups, [string]$_.AuthMechanism
                                })
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements (@($missingPatterns) + @($connectorDetails))
                        }
                        else {
                            $evidence = ('Compliant — external and internal relay connector patterns detected ({0} connectors).' -f $connectors.Count)
                        }
                    }
                }
            }
            'EDCA-SEC-001' {
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and ($server.Exchange.PSObject.Properties.Name -contains 'MapiHttpEnabled') -and $null -ne $server.Exchange.MapiHttpEnabled) {
                    $enabled = [bool]$server.Exchange.MapiHttpEnabled
                    $status = if ($enabled) { 'Pass' } else { 'Fail' }
                    $evidence = ('MAPI over HTTP is {0}.' -f (Get-EDCAStateDescriptor -Value $enabled -Expectation 'Enabled'))
                }
                else {
                    $status = 'Unknown'
                    $evidence = 'MAPI/HTTP baseline data unavailable.'
                }
            }
            'EDCA-GOV-001' {
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and ($server.Exchange.PSObject.Properties.Name -contains 'SharedMailboxTypeMismatchCount') -and $null -ne $server.Exchange.SharedMailboxTypeMismatchCount) {
                    $count = [int]$server.Exchange.SharedMailboxTypeMismatchCount
                    $status = if ($count -eq 0) { 'Pass' } else { 'Fail' }
                    $evidence = if ($count -eq 0) { 'Compliant — no non-user mailboxes with enabled accounts detected.' } else { ('Non-user mailboxes with enabled accounts: {0}' -f $count) }
                }
                else {
                    $status = 'Unknown'
                    $evidence = 'Mailbox type consistency data unavailable.'
                }
            }
            'EDCA-SEC-020' {
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and ($server.Exchange.PSObject.Properties.Name -contains 'OwaDownloadDomainsConfigured') -and $null -ne $server.Exchange.OwaDownloadDomainsConfigured) {
                    $configured = [bool]$server.Exchange.OwaDownloadDomainsConfigured
                    if (-not $configured) {
                        $status = 'Fail'
                        $evidence = 'OWA Download Domains are not configured.'
                    }
                    else {
                        # When HMA is active (EvoSTS IsDefaultAuthorizationEndpoint enabled), the
                        # OAuthIdentityCacheFixForDownloadDomains setting override is also required.
                        $hmaActive = ($server.Exchange.PSObject.Properties.Name -contains 'HybridApplication') -and
                        $null -ne $server.Exchange.HybridApplication -and
                        ($server.Exchange.HybridApplication.PSObject.Properties.Name -contains 'EvoStsIsDefaultAuthorizationEndpoint') -and
                        [bool]$server.Exchange.HybridApplication.EvoStsIsDefaultAuthorizationEndpoint -eq $true
                        if (-not $hmaActive) {
                            $status = 'Pass'
                            $evidence = 'OWA Download Domains are configured.'
                        }
                        else {
                            $overrideConfigured = $null
                            if ($server.Exchange.PSObject.Properties.Name -contains 'OAuthHmaDownloadDomainOverrideConfigured') {
                                $overrideConfigured = $server.Exchange.OAuthHmaDownloadDomainOverrideConfigured
                            }
                            if ($null -eq $overrideConfigured -or [bool]$overrideConfigured -eq $false) {
                                $status = 'Fail'
                                $evidence = 'OWA Download Domains are configured, but the OWA HMA Download Domain Support setting override (OAuthIdentityCacheFixForDownloadDomains) is missing. This override is required when Hybrid Modern Authentication is active.'
                            }
                            else {
                                $status = 'Pass'
                                $evidence = 'OWA Download Domains are configured and the OWA HMA Download Domain Support setting override is in place.'
                            }
                        }
                    }
                }
                else {
                    $status = 'Unknown'
                    $evidence = 'OWA Download Domains data unavailable.'
                }
            }
            'EDCA-SEC-023' {
                $smb1Value = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and ($server.OS.PSObject.Properties.Name -contains 'CisPolicy') -and $null -ne $server.OS.CisPolicy -and ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'Smb1Value')) {
                    $smb1Value = $server.OS.CisPolicy.Smb1Value
                }

                if ($null -eq $smb1Value) {
                    $status = 'Pass'
                    $evidence = 'SMB1 registry value not present (treated as disabled by default baseline).'
                }
                else {
                    $status = if ([int]$smb1Value -eq 0) { 'Pass' } else { 'Fail' }
                    $evidence = if ($status -eq 'Pass') { 'Compliant — SMB1 is disabled (LanmanServer value = 0).' } else { ('LanmanServer SMB1 value: {0} (expected 0 to disable SMB1).' -f [int]$smb1Value) }
                }
            }
            'EDCA-SEC-025' {
                $fwAllEnabled = $null
                $fwItems = @()
                if (($server.PSObject.Properties.Name -contains 'OS') -and ($server.OS.PSObject.Properties.Name -contains 'CisPolicy') -and $null -ne $server.OS.CisPolicy) {
                    if ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'FirewallAllProfilesEnabled') {
                        $fwAllEnabled = $server.OS.CisPolicy.FirewallAllProfilesEnabled
                    }
                    if ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'FirewallProfiles') {
                        $fwItems = @($server.OS.CisPolicy.FirewallProfiles)
                    }
                }

                if ($null -eq $fwAllEnabled) {
                    $status = 'Unknown'
                    $evidence = 'Firewall profile state unavailable.'
                }
                else {
                    $status = if ([bool]$fwAllEnabled) { 'Pass' } else { 'Fail' }
                    $fwItemEvidence = @()
                    foreach ($fwItem in $fwItems) {
                        $fwItemEvidence += ('{0}:{1}' -f [string]$fwItem.Name, (Get-EDCAStateDescriptor -Value ([bool]$fwItem.Enabled) -Expectation 'Enabled'))
                    }
                    $summary = ('All firewall profiles are {0}.' -f (Get-EDCAStateDescriptor -Value ([bool]$fwAllEnabled) -Expectation 'Enabled'))
                    $evidence = if ($fwItemEvidence.Count -gt 0) {
                        Format-EDCAEvidenceWithElements -Summary $summary -Elements $fwItemEvidence
                    }
                    else {
                        $summary
                    }
                }
            }
            'EDCA-SEC-018' {
                $llmnrValue = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and ($server.OS.PSObject.Properties.Name -contains 'CisPolicy') -and $null -ne $server.OS.CisPolicy -and ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'LlmnrEnableMulticast')) {
                    $llmnrValue = $server.OS.CisPolicy.LlmnrEnableMulticast
                }

                if ($null -eq $llmnrValue) {
                    $status = 'Fail'
                    $evidence = 'LLMNR policy value not configured.'
                }
                else {
                    $status = if ([int]$llmnrValue -eq 0) { 'Pass' } else { 'Fail' }
                    $evidence = if ($status -eq 'Pass') { 'Compliant — LLMNR multicast is disabled.' } else { ('DNSClient EnableMulticast value: {0} (expected 0 to disable LLMNR).' -f [int]$llmnrValue) }
                }
            }
            'EDCA-IAC-003' {
                $lmLevel = $null
                $clientSec = $null
                $serverSec = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and ($server.OS.PSObject.Properties.Name -contains 'CisPolicy') -and $null -ne $server.OS.CisPolicy) {
                    if ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'LmCompatibilityLevel') {
                        $lmLevel = $server.OS.CisPolicy.LmCompatibilityLevel
                    }
                    if ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'NtlmMinClientSec') {
                        $clientSec = $server.OS.CisPolicy.NtlmMinClientSec
                    }
                    if ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'NtlmMinServerSec') {
                        $serverSec = $server.OS.CisPolicy.NtlmMinServerSec
                    }
                }

                $failedSettings = @()

                if ($null -eq $lmLevel) {
                    $failedSettings += 'LmCompatibilityLevel not configured.'
                }
                elseif ([int]$lmLevel -lt 5) {
                    $failedSettings += ('LmCompatibilityLevel is {0}; expected >= 5 (NTLMv2 only).' -f [int]$lmLevel)
                }

                $requiredBit = 536870912
                if ($null -eq $clientSec) {
                    $failedSettings += 'NtlmMinClientSec not configured.'
                }
                elseif (((([int]$clientSec) -band $requiredBit) -ne $requiredBit)) {
                    $failedSettings += ('NtlmMinClientSec ({0}) is missing the required NTLMv2 session security bit.' -f [int]$clientSec)
                }

                if ($null -eq $serverSec) {
                    $failedSettings += 'NtlmMinServerSec not configured.'
                }
                elseif (((([int]$serverSec) -band $requiredBit) -ne $requiredBit)) {
                    $failedSettings += ('NtlmMinServerSec ({0}) is missing the required NTLMv2 session security bit.' -f [int]$serverSec)
                }

                if ($failedSettings.Count -eq 0) {
                    $status = 'Pass'
                    $summary = ('LmCompatibilityLevel: {0}; NtlmMinClientSec: {1}; NtlmMinServerSec: {2}' -f [int]$lmLevel, [int]$clientSec, [int]$serverSec)
                    $evidence = ('Compliant — NTLMv2 enforcement baseline configured. {0}' -f $summary)
                }
                else {
                    $status = 'Fail'
                    $summary = ('LmCompatibilityLevel: {0}; NtlmMinClientSec: {1}; NtlmMinServerSec: {2}' -f $lmLevel, $clientSec, $serverSec)
                    $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $failedSettings
                }
            }
            'EDCA-DATA-007' {
                $tls13Support = Test-EDCAIsTls13SupportedOs -Server $server
                if (-not $tls13Support.IsKnown) {
                    $status = 'Unknown'
                    $evidence = ('TLS 1.3 applicability unknown. {0}' -f $tls13Support.Evidence)
                }
                elseif (-not $tls13Support.IsSupported) {
                    $status = 'Skipped'
                    $evidence = ('TLS 1.3 not applicable on this OS baseline. {0}' -f $tls13Support.Evidence)
                }
                else {
                    $tls13Enabled = $null
                    $tls13Source = 'Unknown'
                    if (($server.PSObject.Properties.Name -contains 'Tls') -and ($server.Tls.PSObject.Properties.Name -contains 'Tls13Enabled')) {
                        $tls13Enabled = $server.Tls.Tls13Enabled
                    }
                    if (($server.PSObject.Properties.Name -contains 'Tls') -and ($server.Tls.PSObject.Properties.Name -contains 'Tls13EvidenceSource')) {
                        $tls13Source = [string]$server.Tls.Tls13EvidenceSource
                    }

                    if ($null -eq $tls13Enabled) {
                        $status = 'Unknown'
                        $evidence = ('TLS 1.3 state unavailable on supported OS. Evidence source: {0}. {1}' -f $tls13Source, $tls13Support.Evidence)
                    }
                    else {
                        $status = if ([bool]$tls13Enabled) { 'Fail' } else { 'Pass' }
                        $evidence = ('TLS 1.3 is {0}; evidence source: {1}; {2}' -f
                            (Get-EDCAStateDescriptor -Value ([bool]$tls13Enabled) -Expectation 'Disabled'),
                            $tls13Source,
                            $tls13Support.Evidence)
                    }
                }
            }
            'EDCA-MON-002' {
                $osInfo = Get-EDCAOsBuildInfo -Server $server
                if (-not $osInfo.IsKnown) {
                    $status = 'Unknown'
                    $evidence = ('PowerShell Script Block Logging applicability unknown. {0}' -f $osInfo.Evidence)
                }
                elseif ([int]$osInfo.Build -lt 17763) {
                    $status = 'Skipped'
                    $evidence = ('Not applicable for this baseline. {0}; expected Windows Server 2019/2022/2025 benchmark scope.' -f $osInfo.Evidence)
                }
                else {
                    $enabled = $null
                    if (($server.OS.PSObject.Properties.Name -contains 'CisPolicy') -and $null -ne $server.OS.CisPolicy -and ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'ScriptBlockLoggingEnabled')) {
                        $enabled = $server.OS.CisPolicy.ScriptBlockLoggingEnabled
                    }

                    if ($null -eq $enabled) {
                        $status = 'Fail'
                        $evidence = ('Script block logging policy registry value is absent — EnableScriptBlockLogging is not configured. {0}' -f $osInfo.Evidence)
                    }
                    else {
                        $status = if ([bool]$enabled) { 'Pass' } else { 'Fail' }
                        $evidence = ('PowerShell Script Block Logging is {0}; {1}' -f
                            (Get-EDCAStateDescriptor -Value ([bool]$enabled) -Expectation 'Enabled'),
                            $osInfo.Evidence)
                    }
                }
            }
            'EDCA-MON-014' {
                $osInfo = Get-EDCAOsBuildInfo -Server $server
                if (-not $osInfo.IsKnown) {
                    $status = 'Unknown'
                    $evidence = ('PowerShell Module Logging applicability unknown. {0}' -f $osInfo.Evidence)
                }
                elseif ([int]$osInfo.Build -lt 17763) {
                    $status = 'Skipped'
                    $evidence = ('Not applicable for this baseline. {0}; expected Windows Server 2019/2022/2025 benchmark scope.' -f $osInfo.Evidence)
                }
                else {
                    $modEnabled = $null
                    $modAllModules = $null
                    if (($server.OS.PSObject.Properties.Name -contains 'CisPolicy') -and $null -ne $server.OS.CisPolicy) {
                        if ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'ModuleLoggingEnabled') {
                            $modEnabled = $server.OS.CisPolicy.ModuleLoggingEnabled
                        }
                        if ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'ModuleLoggingAllModules') {
                            $modAllModules = $server.OS.CisPolicy.ModuleLoggingAllModules
                        }
                    }

                    if ($null -eq $modEnabled) {
                        $status = 'Fail'
                        $evidence = ('PowerShell Module Logging policy registry key is absent — EnableModuleLogging is not configured. {0}' -f $osInfo.Evidence)
                    }
                    elseif (-not [bool]$modEnabled) {
                        $status = 'Fail'
                        $evidence = ('PowerShell Module Logging is disabled (EnableModuleLogging = 0). {0}' -f $osInfo.Evidence)
                    }
                    elseif ($modAllModules -ne $true) {
                        $status = 'Fail'
                        $evidence = ('PowerShell Module Logging is enabled but the ModuleNames key does not contain ''*'' — not all modules are logged. {0}' -f $osInfo.Evidence)
                    }
                    else {
                        $status = 'Pass'
                        $evidence = ('PowerShell Module Logging is enabled for all modules (*). {0}' -f $osInfo.Evidence)
                    }
                }
            }
            'EDCA-IAC-006' {
                $osInfo = Get-EDCAOsBuildInfo -Server $server
                if (-not $osInfo.IsKnown) {
                    $status = 'Unknown'
                    $evidence = ('WDigest applicability unknown. {0}' -f $osInfo.Evidence)
                }
                elseif ([int]$osInfo.Build -lt 17763) {
                    $status = 'Skipped'
                    $evidence = ('Not applicable for this baseline. {0}; expected Windows Server 2019/2022/2025 benchmark scope.' -f $osInfo.Evidence)
                }
                else {
                    $wdigestValue = $null
                    if (($server.OS.PSObject.Properties.Name -contains 'CisPolicy') -and $null -ne $server.OS.CisPolicy -and ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'WdigestUseLogonCredential')) {
                        $wdigestValue = $server.OS.CisPolicy.WdigestUseLogonCredential
                    }

                    if ($null -eq $wdigestValue) {
                        $status = 'Pass'
                        $evidence = 'Compliant — WDigest UseLogonCredential not present (secure default).'
                    }
                    else {
                        $status = if ([int]$wdigestValue -eq 0) { 'Pass' } else { 'Fail' }
                        $evidence = if ($status -eq 'Pass') { 'Compliant — WDigest UseLogonCredential is 0.' } else { ('WDigest UseLogonCredential value: {0} (expected 0).' -f [int]$wdigestValue) }
                    }
                }
            }
            'EDCA-IAC-005' {
                $osInfo = Get-EDCAOsBuildInfo -Server $server
                if (-not $osInfo.IsKnown) {
                    $status = 'Unknown'
                    $evidence = ('RDP NLA applicability unknown. {0}' -f $osInfo.Evidence)
                }
                elseif ([int]$osInfo.Build -lt 17763) {
                    $status = 'Skipped'
                    $evidence = ('Not applicable for this baseline. {0}; expected Windows Server 2019/2022/2025 benchmark scope.' -f $osInfo.Evidence)
                }
                else {
                    $rdpNla = $null
                    if (($server.OS.PSObject.Properties.Name -contains 'CisPolicy') -and $null -ne $server.OS.CisPolicy -and ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'RdpNlaRequired')) {
                        $rdpNla = $server.OS.CisPolicy.RdpNlaRequired
                    }

                    if ($null -eq $rdpNla) {
                        $status = 'Unknown'
                        $evidence = ('RDP NLA configuration value unavailable. {0}' -f $osInfo.Evidence)
                    }
                    else {
                        $status = if ([bool]$rdpNla) { 'Pass' } else { 'Fail' }
                        $evidence = ('RDP NLA is {0}; {1}' -f
                            (Get-EDCAStateDescriptor -Value ([bool]$rdpNla) -Expectation 'Required'),
                            $osInfo.Evidence)
                    }
                }
            }
            'EDCA-SEC-026' {
                $osInfo = Get-EDCAOsBuildInfo -Server $server
                if (-not $osInfo.IsKnown) {
                    $status = 'Unknown'
                    $evidence = ('Windows Defender applicability unknown. {0}' -f $osInfo.Evidence)
                }
                elseif ([int]$osInfo.Build -lt 17763) {
                    $status = 'Skipped'
                    $evidence = ('Not applicable for this baseline. {0}; expected Windows Server 2019/2022/2025 benchmark scope.' -f $osInfo.Evidence)
                }
                else {
                    $defenderAvailable = $false
                    $rtpEnabled = $null
                    if (($server.OS.PSObject.Properties.Name -contains 'CisPolicy') -and $null -ne $server.OS.CisPolicy) {
                        if ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'DefenderAvailable') {
                            $defenderAvailable = [bool]$server.OS.CisPolicy.DefenderAvailable
                        }
                        if ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'DefenderRtpEnabled') {
                            $rtpEnabled = $server.OS.CisPolicy.DefenderRtpEnabled
                        }
                    }

                    if (-not $defenderAvailable) {
                        $status = 'Unknown'
                        $evidence = ('Defender cmdlets unavailable on this server. {0}' -f $osInfo.Evidence)
                    }
                    elseif ($null -eq $rtpEnabled) {
                        $status = 'Unknown'
                        $evidence = ('Defender real-time protection state unavailable. {0}' -f $osInfo.Evidence)
                    }
                    else {
                        $status = if ([bool]$rtpEnabled) { 'Pass' } else { 'Fail' }
                        $evidence = ('Defender real-time protection is {0}; {1}' -f
                            (Get-EDCAStateDescriptor -Value ([bool]$rtpEnabled) -Expectation 'Enabled'),
                            $osInfo.Evidence)
                    }
                }
            }
            'EDCA-SEC-013' {
                $osInfo = Get-EDCAOsBuildInfo -Server $server
                if (-not $osInfo.IsKnown) {
                    $status = 'Unknown'
                    $evidence = ('Credential Guard applicability unknown. {0}' -f $osInfo.Evidence)
                }
                elseif ([int]$osInfo.Build -lt 17763) {
                    $status = 'Skipped'
                    $evidence = ('Not applicable for this baseline. {0}; expected Windows Server 2019/2022/2025 benchmark scope.' -f $osInfo.Evidence)
                }
                else {
                    $credentialGuardEnabled = $null
                    if (($server.OS.PSObject.Properties.Name -contains 'CisPolicy') -and $null -ne $server.OS.CisPolicy -and ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'CredentialGuardEnabled')) {
                        $credentialGuardEnabled = $server.OS.CisPolicy.CredentialGuardEnabled
                    }

                    if ($null -eq $credentialGuardEnabled) {
                        $status = 'Unknown'
                        $evidence = ('Credential Guard state unavailable. {0}' -f $osInfo.Evidence)
                    }
                    else {
                        $status = if ([bool]$credentialGuardEnabled) { 'Fail' } else { 'Pass' }
                        $evidence = ('Credential Guard is {0}; {1}' -f
                            (Get-EDCAStateDescriptor -Value ([bool]$credentialGuardEnabled) -Expectation 'Disabled'),
                            $osInfo.Evidence)
                    }
                }
            }
            'EDCA-TLS-026' {
                $domainResults = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'EmailAuthentication') -and $null -ne $CollectionData.EmailAuthentication -and ($CollectionData.EmailAuthentication.PSObject.Properties.Name -contains 'DomainResults')) {
                    $domainResults = @($CollectionData.EmailAuthentication.DomainResults)
                }

                if ($domainResults.Count -eq 0) {
                    $status = 'Unknown'
                    if (($CollectionData.PSObject.Properties.Name -contains 'EmailAuthentication') -and ($CollectionData.EmailAuthentication.PSObject.Properties.Name -contains 'Reason')) {
                        $evidence = ('No domain-level SPF evidence available. {0}' -f [string]$CollectionData.EmailAuthentication.Reason)
                    }
                    else {
                        $evidence = 'No domain-level SPF evidence available.'
                    }
                }
                else {
                    $failed = @($domainResults | Where-Object { $_.Spf.Status -eq 'Fail' })
                    $unknown = @($domainResults | Where-Object { $_.Spf.Status -eq 'Unknown' })
                    if ($failed.Count -gt 0) {
                        $status = 'Fail'
                    }
                    elseif ($unknown.Count -gt 0) {
                        $status = 'Unknown'
                    }
                    else {
                        $status = 'Pass'
                    }

                    $failedDomains = @($failed | ForEach-Object { $_.Domain })
                    $evidence = ('SPF domains evaluated: {0}; fail: {1}; unknown: {2}; failed domains: {3}' -f $domainResults.Count, $failed.Count, $unknown.Count, ($failedDomains -join ', '))
                }
            }
            'EDCA-TLS-023' {
                $domainResults = @()
                if (($CollectionData.PSObject.Properties.Name -contains 'EmailAuthentication') -and $null -ne $CollectionData.EmailAuthentication -and ($CollectionData.EmailAuthentication.PSObject.Properties.Name -contains 'DomainResults')) {
                    $domainResults = @($CollectionData.EmailAuthentication.DomainResults)
                }

                if ($domainResults.Count -eq 0) {
                    $status = 'Unknown'
                    if (($CollectionData.PSObject.Properties.Name -contains 'EmailAuthentication') -and ($CollectionData.EmailAuthentication.PSObject.Properties.Name -contains 'Reason')) {
                        $evidence = ('No domain-level DMARC evidence available. {0}' -f [string]$CollectionData.EmailAuthentication.Reason)
                    }
                    else {
                        $evidence = 'No domain-level DMARC evidence available.'
                    }
                }
                else {
                    $failed = @($domainResults | Where-Object { $_.Dmarc.Status -eq 'Fail' })
                    $unknown = @($domainResults | Where-Object { $_.Dmarc.Status -eq 'Unknown' })
                    if ($failed.Count -gt 0) {
                        $status = 'Fail'
                    }
                    elseif ($unknown.Count -gt 0) {
                        $status = 'Unknown'
                    }
                    else {
                        $status = 'Pass'
                    }

                    $evidenceLines = @()
                    foreach ($dr in $domainResults) {
                        $evidenceLines += ('{0}: {1} - {2}' -f $dr.Domain, $dr.Dmarc.Status, [string]$dr.Dmarc.Evidence)
                    }
                    $evidence = $evidenceLines -join "`n"
                }
            }
            'EDCA-SEC-019' {
                $defenderAvailable = $false
                $rtpEnabled = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and ($server.OS.PSObject.Properties.Name -contains 'CisPolicy') -and $null -ne $server.OS.CisPolicy) {
                    if ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'DefenderAvailable') {
                        $defenderAvailable = [bool]$server.OS.CisPolicy.DefenderAvailable
                    }
                    if ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'DefenderRtpEnabled') {
                        $rtpEnabled = $server.OS.CisPolicy.DefenderRtpEnabled
                    }
                }

                if (-not $defenderAvailable) {
                    $status = 'Skipped'
                    $evidence = 'Defender not available on this server; antivirus exclusion check skipped.'
                }
                elseif ($null -eq $rtpEnabled -or -not [bool]$rtpEnabled) {
                    $status = 'Unknown'
                    $evidence = 'Defender real-time protection is not enabled; antivirus exclusion check not applicable.'
                }
                elseif (-not ($server.PSObject.Properties.Name -contains 'Exchange') -or -not [bool]$server.Exchange.IsExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; antivirus exclusion check skipped.'
                }
                else {
                    $installPath = ''
                    if (($server.Exchange.PSObject.Properties.Name -contains 'InstallPath') -and -not [string]::IsNullOrWhiteSpace([string]$server.Exchange.InstallPath)) {
                        $installPath = ([string]$server.Exchange.InstallPath).TrimEnd('\')
                    }

                    if ([string]::IsNullOrWhiteSpace($installPath)) {
                        $status = 'Unknown'
                        $evidence = 'Exchange install path unavailable; cannot verify antivirus exclusions.'
                    }
                    else {
                        $actualPaths = @()
                        $actualProcesses = @()
                        if ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'DefenderExclusionPaths') {
                            $actualPaths = @($server.OS.CisPolicy.DefenderExclusionPaths |
                                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                                ForEach-Object { ([string]$_).TrimEnd('\').ToLowerInvariant() })
                        }
                        if ($server.OS.CisPolicy.PSObject.Properties.Name -contains 'DefenderExclusionProcesses') {
                            $actualProcesses = @($server.OS.CisPolicy.DefenderExclusionProcesses |
                                Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } |
                                ForEach-Object { ([string]$_).ToLowerInvariant() })
                        }

                        $productLine = Get-EDCAProductLineFromServerData -Server $server

                        $expectedDirs = [System.Collections.Generic.List[string]]@(
                            "$installPath\Mailbox",
                            "$installPath\ClientAccess\OAB",
                            "$installPath\FIP-FS",
                            "$installPath\GroupMetrics",
                            "$installPath\Logging",
                            "$installPath\TransportRoles\Data\Queue",
                            "$installPath\TransportRoles\Data\SenderReputation",
                            "$installPath\TransportRoles\Data\Temp",
                            "$installPath\TransportRoles\Logs",
                            "$installPath\Working\OleConverter"
                        )
                        if ($productLine -eq 'Exchange2016') {
                            $expectedDirs.Add("$installPath\UnifiedMessaging\Grammars")
                            $expectedDirs.Add("$installPath\UnifiedMessaging\Prompts")
                            $expectedDirs.Add("$installPath\UnifiedMessaging\Temp")
                            $expectedDirs.Add("$installPath\UnifiedMessaging\Voicemail")
                        }

                        $expectedProcesses = @(
                            "$installPath\Bin\EdgeTransport.exe",
                            "$installPath\Bin\MSExchangeDelivery.exe",
                            "$installPath\Bin\MSExchangeFrontendTransport.exe",
                            "$installPath\Bin\MSExchangeHMHost.exe",
                            "$installPath\Bin\MSExchangeMailboxAssistants.exe",
                            "$installPath\Bin\MSExchangeMailboxReplication.exe",
                            "$installPath\Bin\MSExchangeRepl.exe",
                            "$installPath\Bin\MSExchangeSubmission.exe",
                            "$installPath\Bin\MSExchangeTransport.exe",
                            "$installPath\Bin\MSExchangeTransportLogSearch.exe",
                            "$installPath\Bin\MSExchangeThrottling.exe",
                            "$installPath\Bin\OleConverter.exe"
                        )

                        # A path is covered if it or any parent path is explicitly excluded.
                        $missingDirs = @()
                        foreach ($expectedDir in $expectedDirs) {
                            $tLower = $expectedDir.TrimEnd('\').ToLowerInvariant()
                            $covered = $false
                            foreach ($a in $actualPaths) {
                                if ($tLower -eq $a -or $tLower.StartsWith($a + '\')) { $covered = $true; break }
                            }
                            if (-not $covered) { $missingDirs += $expectedDir }
                        }

                        # A process is covered if its explicit path is excluded, or its directory is excluded,
                        # or a parent of its directory is excluded.
                        $allActual = @($actualPaths) + @($actualProcesses)
                        $missingProcs = @()
                        foreach ($expectedProc in $expectedProcesses) {
                            $tLower = $expectedProc.ToLowerInvariant()
                            $covered = $false
                            foreach ($a in $allActual) {
                                if ($tLower -eq $a -or $tLower.StartsWith($a + '\')) { $covered = $true; break }
                            }
                            if (-not $covered) { $missingProcs += $expectedProc }
                        }

                        if ($missingDirs.Count -eq 0 -and $missingProcs.Count -eq 0) {
                            $status = 'Pass'
                            $evidence = 'Compliant — all expected Exchange Defender exclusion paths and processes are configured.'
                        }
                        else {
                            $status = 'Fail'
                            $missingList = @($missingDirs | ForEach-Object { 'DIR: ' + $_ }) + @($missingProcs | ForEach-Object { 'PROC: ' + $_ })
                            $summary = ('Missing AV exclusions ({0}).' -f $missingList.Count)
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $missingList
                        }
                    }
                }
            }
            'EDCA-SEC-002' {
                $netRelease = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and ($server.OS.PSObject.Properties.Name -contains 'NetFrameworkRelease')) {
                    $netRelease = $server.OS.NetFrameworkRelease
                }

                if ($null -eq $netRelease) {
                    $status = 'Unknown'
                    $evidence = '.NET Framework release key data unavailable.'
                }
                else {
                    $netRelease = [int]$netRelease
                    $netFriendly = if ($netRelease -ge 533320) { '4.8.1' }
                    elseif ($netRelease -ge 528040) { '4.8' }
                    elseif ($netRelease -ge 461808) { '4.7.2' }
                    elseif ($netRelease -ge 461308) { '4.7.1' }
                    elseif ($netRelease -ge 460798) { '4.7' }
                    elseif ($netRelease -ge 394802) { '4.6.2' }
                    else { 'older than 4.6.2' }

                    $productLine = 'Unknown'
                    if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'ProductLine')) {
                        $productLine = [string]$server.Exchange.ProductLine
                    }

                    # Exchange 2016, 2019, and SE all require .NET Framework 4.8 minimum
                    $minRelease = 528040
                    $minFriendly = '4.8'
                    if ($netRelease -ge $minRelease) {
                        $status = 'Pass'
                        $evidence = ('Compliant — .NET Framework {0} installed; meets minimum requirement of {1}.' -f $netFriendly, $minFriendly)
                    }
                    else {
                        $status = 'Fail'
                        $evidence = ('.NET Framework {0} (release key {1}) does not meet the minimum requirement of {2} for {3}.' -f $netFriendly, $netRelease, $minFriendly, $productLine)
                    }
                }
            }
            'EDCA-SEC-011' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; RPC minimum connection timeout baseline is not applicable.'
                    break
                }

                $rpcMinConnectionTimeout = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'RpcMinConnectionTimeout')) {
                    $rpcMinConnectionTimeout = $server.Exchange.RpcMinConnectionTimeout
                }

                if ($null -eq $rpcMinConnectionTimeout) {
                    $status = 'Unknown'
                    $evidence = 'RPC minimum connection timeout data unavailable.'
                }
                elseif ([int]$rpcMinConnectionTimeout -lt 0) {
                    $status = 'Fail'
                    $evidence = ('RPC minimum connection timeout has an invalid value: {0}' -f [int]$rpcMinConnectionTimeout)
                }
                else {
                    $status = 'Pass'
                    $evidence = 'Compliant — RPC minimum connection timeout is configured.'
                }
            }
            'EDCA-PERF-010' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; TCP/IP Exchange baseline is not applicable.'
                    break
                }

                $tcpKeepAlive = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'TcpKeepAliveTime')) {
                    $tcpKeepAlive = $server.Exchange.TcpKeepAliveTime
                }

                if ($null -eq $tcpKeepAlive -or [int]$tcpKeepAlive -eq 0) {
                    $status = 'Fail'
                    $evidence = 'TCP KeepAliveTime is not set (defaults to 2 hours). Recommended range is 900000-1800000 ms.'
                }
                elseif ([int]$tcpKeepAlive -lt 900000 -or [int]$tcpKeepAlive -gt 1800000) {
                    $status = 'Unknown'
                    $evidence = ('TCP KeepAliveTime is {0}. Recommended range is 900000-1800000 ms.' -f [int]$tcpKeepAlive)
                }
                else {
                    $status = 'Pass'
                    $evidence = ('TCP KeepAliveTime is {0}, within the recommended 900000-1800000 ms range.' -f [int]$tcpKeepAlive)
                }
            }
            'EDCA-PERF-005' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; NUMA baseline is not applicable.'
                    break
                }

                $numaGroupSizeOptimization = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'NumaGroupSizeOptimization')) {
                    $numaGroupSizeOptimization = $server.Exchange.NumaGroupSizeOptimization
                }

                if ($null -eq $numaGroupSizeOptimization) {
                    $status = 'Skipped'
                    $evidence = 'NUMA group size optimization registry value is not configured; no NUMA optimization is in effect, so the baseline check is not applicable.'
                }
                elseif ([int]$numaGroupSizeOptimization -eq 0) {
                    $status = 'Pass'
                    $evidence = 'NUMA group size optimization is set to 0 (flat baseline).'
                }
                else {
                    $status = 'Fail'
                    $evidence = ('NUMA group size optimization is set to {0}. Expected baseline value is 0.' -f [int]$numaGroupSizeOptimization)
                }
            }
            'EDCA-PERF-006' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; processor baseline is not applicable.'
                    break
                }

                $logicalProcessors = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and ($server.OS.PSObject.Properties.Name -contains 'NumberOfLogicalProcessors')) {
                    $logicalProcessors = $server.OS.NumberOfLogicalProcessors
                }

                if ($null -eq $logicalProcessors) {
                    $status = 'Unknown'
                    $evidence = 'Logical processor count unavailable.'
                }
                else {
                    $productLine = Get-EDCAProductLineFromServerData -Server $server
                    $logicalCoreThreshold = if ($productLine -eq 'Exchange2016') { 24 } else { 48 }
                    if ([int]$logicalProcessors -gt $logicalCoreThreshold) {
                        $status = 'Fail'
                        $evidence = ('Logical processors: {0}. Recommended maximum for {1} baseline is {2}.' -f [int]$logicalProcessors, $productLine, $logicalCoreThreshold)
                    }
                    else {
                        $status = 'Pass'
                        $evidence = ('Compliant — {0} logical processors, within the {1} baseline of {2}.' -f [int]$logicalProcessors, $productLine, $logicalCoreThreshold)
                    }
                }
            }
            'EDCA-SEC-017' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; IPv6 Exchange baseline is not applicable.'
                    break
                }

                $ipv6DisabledComponents = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'IPv6DisabledComponents')) {
                    $ipv6DisabledComponents = $server.Exchange.IPv6DisabledComponents
                }

                if ($null -eq $ipv6DisabledComponents) {
                    $status = 'Pass'
                    $evidence = 'IPv6 disabled-components policy is not set (IPv6 enabled baseline by default).'
                }
                elseif ([int]$ipv6DisabledComponents -eq 255) {
                    $status = 'Fail'
                    $evidence = 'IPv6 is fully disabled (DisabledComponents=255), which is not recommended for Exchange.'
                }
                elseif ([int]$ipv6DisabledComponents -eq 0) {
                    $status = 'Pass'
                    $evidence = 'IPv6 disabled-components value is 0 (IPv6 enabled baseline).'
                }
                else {
                    $status = 'Unknown'
                    $evidence = ('IPv6 disabled-components value is {0}. Partial/custom IPv6 disablement should be reviewed.' -f [int]$ipv6DisabledComponents)
                }
            }
            'EDCA-PERF-009' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; Sleepy NIC baseline is not applicable.'
                    break
                }

                $sleepyNic = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'SleepyNic')) {
                    $sleepyNic = $server.Exchange.SleepyNic
                }

                if ($null -eq $sleepyNic) {
                    $status = 'Unknown'
                    $evidence = 'Sleepy NIC telemetry unavailable.'
                }
                elseif (-not [bool]$sleepyNic.CommandAvailable) {
                    $status = 'Unknown'
                    $evidence = 'Sleepy NIC check unavailable because required networking cmdlets are not present.'
                }
                elseif ([int]$sleepyNic.AdapterCount -eq 0) {
                    $status = 'Pass'
                    $evidence = 'No active adapters were evaluated for Sleepy NIC settings.'
                }
                elseif ([int]$sleepyNic.NonCompliantCount -gt 0) {
                    $status = 'Unknown'
                    $nonCompliantAdapters = @($sleepyNic.NonCompliantAdapters | ForEach-Object {
                            '{0} | PnPCapabilities={1}' -f [string]$_.Name, [string]$_.PnPCapabilities
                        })
                    $summary = ('Sleepy NIC warnings on {0} of {1} adapter(s).' -f [int]$sleepyNic.NonCompliantCount, [int]$sleepyNic.AdapterCount)
                    $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $nonCompliantAdapters
                }
                else {
                    $status = 'Pass'
                    $evidence = ('Sleepy NIC baseline validated on {0} adapter(s).' -f [int]$sleepyNic.AdapterCount)
                }
            }
            'EDCA-PERF-004' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; NodeRunner baseline is not applicable.'
                    break
                }

                $nodeRunner = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'NodeRunner')) {
                    $nodeRunner = $server.Exchange.NodeRunner
                }

                if ($null -eq $nodeRunner) {
                    $status = 'Unknown'
                    $evidence = 'NodeRunner configuration data unavailable.'
                }
                elseif (-not [bool]$nodeRunner.Present) {
                    $status = 'Fail'
                    $evidence = 'noderunner.exe.config is missing.'
                }
                elseif ($nodeRunner.ConfigValid -eq $false) {
                    $status = 'Fail'
                    $evidence = 'noderunner.exe.config could not be parsed.'
                }
                elseif ($null -eq $nodeRunner.MemoryLimitMB) {
                    $status = 'Unknown'
                    $evidence = 'NodeRunner memoryLimitMegabytes setting is not available.'
                }
                elseif ([int]$nodeRunner.MemoryLimitMB -eq 0) {
                    $status = 'Pass'
                    $evidence = 'NodeRunner memoryLimitMegabytes is set to 0 (baseline).'
                }
                elseif ([int]$nodeRunner.MemoryLimitMB -gt 0) {
                    $status = 'Unknown'
                    $evidence = ('NodeRunner memoryLimitMegabytes is set to {0}; baseline is 0.' -f [int]$nodeRunner.MemoryLimitMB)
                }
                else {
                    $status = 'Fail'
                    $evidence = ('NodeRunner memoryLimitMegabytes has an invalid value: {0}' -f [int]$nodeRunner.MemoryLimitMB)
                }
            }
            'EDCA-SEC-007' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; Visual C++ Exchange baseline is not applicable.'
                    break
                }

                $vcRedistributable = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'VisualCRedistributable')) {
                    $vcRedistributable = $server.Exchange.VisualCRedistributable
                }

                if ($null -eq $vcRedistributable) {
                    $status = 'Unknown'
                    $evidence = 'Visual C++ redistributable telemetry unavailable.'
                }
                else {
                    $has2012x64 = ($vcRedistributable.PSObject.Properties.Name -contains 'Has2012x64') -and [bool]$vcRedistributable.Has2012x64
                    $has2013x64 = ($vcRedistributable.PSObject.Properties.Name -contains 'Has2013x64') -and [bool]$vcRedistributable.Has2013x64
                    $status = if ($has2012x64 -and $has2013x64) { 'Pass' } else { 'Fail' }
                    $summary = ('Visual C++ baseline: 2012 x64 present={0}; 2013 x64 present={1}.' -f $has2012x64, $has2013x64)
                    if ($status -eq 'Fail') {
                        $missing = @()
                        if (-not $has2012x64) { $missing += 'Missing Visual C++ 2012 x64 runtime.' }
                        if (-not $has2013x64) { $missing += 'Missing Visual C++ 2013 x64 runtime.' }
                        $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $missing
                    }
                    else {
                        $evidence = 'Compliant — Visual C++ 2012 x64 and 2013 x64 redistributables are present.'
                    }
                }
            }
            'EDCA-DATA-004' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; serialized data signing baseline is not applicable.'
                    break
                }

                $serializedDataSigningEnabled = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'SerializedDataSigningEnabled')) {
                    $serializedDataSigningEnabled = $server.Exchange.SerializedDataSigningEnabled
                }

                if ($null -eq $serializedDataSigningEnabled) {
                    $status = 'Unknown'
                    $evidence = 'Serialized data signing state could not be determined (Exchange endpoint may be unavailable).'
                }
                else {
                    $status = if ([bool]$serializedDataSigningEnabled) { 'Pass' } else { 'Fail' }
                    $signingState = if ([bool]$serializedDataSigningEnabled) { 'enabled' } else { 'disabled' }
                    $evidence = ('SerializedDataSigning is {0}.' -f $signingState)
                }
            }
            'EDCA-SEC-006' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; setting override baseline is not applicable.'
                    break
                }

                $settingOverrides = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'SettingOverrides')) {
                    $settingOverrides = $server.Exchange.SettingOverrides
                }

                if ($null -eq $settingOverrides) {
                    $status = 'Unknown'
                    $evidence = 'Setting override telemetry unavailable.'
                }
                else {
                    $overrideCount = 0
                    if ($settingOverrides.PSObject.Properties.Name -contains 'Count' -and $null -ne $settingOverrides.Count) {
                        $overrideCount = [int]$settingOverrides.Count
                    }

                    $overrideNames = @()
                    if ($settingOverrides.PSObject.Properties.Name -contains 'Names' -and $null -ne $settingOverrides.Names) {
                        $overrideNames = @($settingOverrides.Names | ForEach-Object { [string]$_ })
                    }
                    $rawOverrideCount = $overrideNames.Count

                    # EnableSigningVerification is set by Exchange when serialized data signing is enabled; exclude it from flagging.
                    $signingEnabled = $false
                    if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'SerializedDataSigningEnabled')) {
                        $signingEnabled = [bool]$server.Exchange.SerializedDataSigningEnabled
                    }
                    if ($signingEnabled) {
                        $overrideNames = @($overrideNames | Where-Object { $_ -ne 'EnableSigningVerification' })
                        $overrideCount = $overrideNames.Count
                    }

                    # When the dedicated Exchange hybrid app is configured, EnableExchangeHybrid3PAppFeature and
                    # per-server FlightingServiceOverride_<Server>_F1.1[.x] overrides are expected; exclude from flagging.
                    if ($overrideNames -contains 'EnableExchangeHybrid3PAppFeature') {
                        $overrideNames = @($overrideNames | Where-Object { $_ -ne 'EnableExchangeHybrid3PAppFeature' -and $_ -notmatch '^FlightingServiceOverride_.+_F1\.1' })
                        $overrideCount = $overrideNames.Count
                    }

                    # AMSI body scanning enable overrides (EnableAMSIBodyScanFor*, EnableAMSIBodyScanAll*) are expected
                    # when body scanning is configured per-protocol or for all protocols; exclude from flagging.
                    $amsiBodyScanOverrides = @($overrideNames | Where-Object { $_ -match '^EnableAMSIBodyScan' })
                    if ($amsiBodyScanOverrides.Count -gt 0) {
                        $overrideNames = @($overrideNames | Where-Object { $_ -notmatch '^EnableAMSIBodyScan' })
                        $overrideCount = $overrideNames.Count
                    }

                    # EnableEncryptionAlgorithmCBC enables AES256-CBC encryption mode (best practice); exclude it from flagging when present.
                    if ($overrideNames -contains 'EnableEncryptionAlgorithmCBC') {
                        $overrideNames = @($overrideNames | Where-Object { $_ -ne 'EnableEncryptionAlgorithmCBC' })
                        $overrideCount = $overrideNames.Count
                    }

                    if ($overrideCount -eq 0) {
                        $status = 'Pass'
                        $evidence = if ($rawOverrideCount -eq 0) { 'No Exchange setting overrides detected.' } else { ('{0} setting override(s) detected; all within expected baseline.' -f $rawOverrideCount) }
                    }
                    else {
                        $status = 'Unknown'
                        $overrideDetails = @()
                        if ($settingOverrides.PSObject.Properties.Name -contains 'Details' -and $null -ne $settingOverrides.Details) {
                            $overrideDetails = @($settingOverrides.Details | Where-Object { $overrideNames -contains [string]$_.Name })
                        }
                        if ($overrideDetails.Count -gt 0) {
                            $orgLevelNames = @($overrideDetails | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.Server) } | ForEach-Object { [string]$_.Name } | Sort-Object)
                            $perServerEntries = @($overrideDetails | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.Server) } | ForEach-Object { ('{0} [server: {1}]' -f [string]$_.Name, [string]$_.Server) } | Sort-Object)
                            $elements = @()
                            if ($orgLevelNames.Count -gt 0) {
                                $elements += ('Org-level ({0}): {1}' -f $orgLevelNames.Count, ($orgLevelNames -join ', '))
                            }
                            foreach ($entry in $perServerEntries) { $elements += $entry }
                            $summary = ('Exchange setting overrides detected ({0}).' -f $overrideCount)
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $elements
                        }
                        else {
                            $summary = ('Exchange setting overrides detected ({0}).' -f $overrideCount)
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements ($overrideNames | Select-Object -First 20)
                        }
                    }
                }
            }
            'EDCA-DATA-003' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; internal transport certificate baseline is not applicable.'
                    break
                }

                $internalTransportCertificate = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'InternalTransportCertificate')) {
                    $internalTransportCertificate = $server.Exchange.InternalTransportCertificate
                }

                if ($null -eq $internalTransportCertificate) {
                    $status = 'Unknown'
                    $evidence = 'Internal transport certificate telemetry unavailable.'
                }
                elseif (-not [bool]$internalTransportCertificate.Found) {
                    $status = 'Fail'
                    $evidence = ('Internal transport certificate thumbprint not found in LocalMachine\My: {0}' -f [string]$internalTransportCertificate.Thumbprint)
                }
                else {
                    $daysRemaining = $null
                    if ($internalTransportCertificate.PSObject.Properties.Name -contains 'DaysRemaining' -and $null -ne $internalTransportCertificate.DaysRemaining) {
                        $daysRemaining = [int]$internalTransportCertificate.DaysRemaining
                    }

                    if ([bool]$internalTransportCertificate.IsExpired -or ($null -ne $daysRemaining -and $daysRemaining -lt 30)) {
                        $status = 'Fail'
                    }
                    elseif ($null -ne $daysRemaining -and $daysRemaining -lt 60) {
                        $status = 'Unknown'
                    }
                    else {
                        $status = 'Pass'
                    }

                    if ($status -eq 'Pass') {
                        $evidence = ('Compliant — internal transport certificate valid; expires {0} ({1} days remaining).' -f [string]$internalTransportCertificate.NotAfter, [string]$daysRemaining)
                    }
                    else {
                        $expiredLabel = if ([bool]$internalTransportCertificate.IsExpired) { 'EXPIRED' } elseif ($null -ne $daysRemaining -and $daysRemaining -lt 30) { 'expiring within 30 days' } else { 'expiring soon' }
                        $evidence = "Internal transport certificate $expiredLabel`n  Thumbprint  : $([string]$internalTransportCertificate.Thumbprint)`n  Expiry      : $([string]$internalTransportCertificate.NotAfter)`n  Days left   : $(if ($null -ne $daysRemaining) { $daysRemaining } else { 'unknown' })"
                    }
                }
            }
            'EDCA-DATA-008' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; trusted root certificate baseline is not applicable.'
                    break
                }

                $disableRootAutoUpdate = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'DisableRootAutoUpdate')) {
                    $disableRootAutoUpdate = $server.Exchange.DisableRootAutoUpdate
                }

                if ($null -eq $disableRootAutoUpdate) {
                    $status = 'Pass'
                    $evidence = 'Compliant — automatic root certificate updates use system default behavior.'
                }
                elseif ([int]$disableRootAutoUpdate -eq 0) {
                    $status = 'Pass'
                    $evidence = 'Compliant — automatic root certificate updates are enabled.'
                }
                elseif ([int]$disableRootAutoUpdate -eq 1) {
                    $status = 'Unknown'
                    $evidence = 'DisableRootAutoUpdate is 1 (automatic root updates disabled). Ensure root certificates are maintained manually.'
                }
                else {
                    $status = 'Fail'
                    $evidence = ('DisableRootAutoUpdate has an unexpected value: {0}' -f [int]$disableRootAutoUpdate)
                }
            }
            'EDCA-GOV-003' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; EEMS baseline is not applicable.'
                    break
                }

                $eems = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'Eems')) {
                    $eems = $server.Exchange.Eems
                }

                if ($null -eq $eems) {
                    $status = 'Unknown'
                    $evidence = 'EEMS telemetry unavailable.'
                }
                elseif (-not [bool]$eems.Present) {
                    $status = 'Unknown'
                    $evidence = 'MSExchangeMitigation service not found.'
                }
                else {
                    $isRunning = [string]$eems.Status -eq 'Running'
                    $isAutomatic = [string]$eems.StartMode -in @('Auto', 'Automatic')
                    $mitigationsEnabled = $null
                    if ($eems.PSObject.Properties.Name -contains 'MitigationsEnabled' -and $null -ne $eems.MitigationsEnabled) {
                        $mitigationsEnabled = [bool]$eems.MitigationsEnabled
                    }

                    if (-not $isRunning -or -not $isAutomatic -or ($null -ne $mitigationsEnabled -and -not $mitigationsEnabled)) {
                        $status = 'Fail'
                    }
                    else {
                        $status = 'Pass'
                    }

                    $evidence = if ($status -eq 'Pass') { 'Compliant — EEMS service is running, automatic start, mitigations enabled.' } else { ('EEMS service state: status={0}; start mode={1}; mitigations enabled={2}' -f [string]$eems.Status, [string]$eems.StartMode, [string]$mitigationsEnabled) }
                }
            }
            'EDCA-SEC-012' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; AMSI Exchange baseline is not applicable.'
                    break
                }

                $amsi = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'Amsi')) {
                    $amsi = $server.Exchange.Amsi
                }

                if ($null -eq $amsi) {
                    $status = 'Unknown'
                    $evidence = 'AMSI telemetry unavailable.'
                }
                else {
                    $providerCount = $null
                    if ($amsi.PSObject.Properties.Name -contains 'ProviderCount' -and $null -ne $amsi.ProviderCount) {
                        $providerCount = [int]$amsi.ProviderCount
                    }

                    $disabledBySettingOverride = $null
                    if ($amsi.PSObject.Properties.Name -contains 'DisabledBySettingOverride' -and $null -ne $amsi.DisabledBySettingOverride) {
                        $disabledBySettingOverride = [bool]$amsi.DisabledBySettingOverride
                    }

                    if ($disabledBySettingOverride -eq $true) {
                        $status = 'Fail'
                        $evidence = 'AMSI is disabled by Exchange setting override (Cafe/HttpRequestFiltering Enabled=false).'
                    }
                    elseif ($null -eq $providerCount) {
                        $status = 'Unknown'
                        $evidence = 'AMSI provider count unavailable.'
                    }
                    elseif ($providerCount -gt 0) {
                        $status = 'Pass'
                        $evidence = ('Compliant — {0} AMSI provider(s) registered.' -f $providerCount)
                    }
                    else {
                        $status = 'Fail'
                        $evidence = 'No AMSI providers detected on the server.'
                    }
                }
            }
            'EDCA-SEC-024' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; vulnerability baseline is not applicable.'
                    break
                }

                $productLine = Get-EDCAProductLineFromServerData -Server $server
                switch ($productLine) {
                    'ExchangeSE' {
                        $status = 'Pass'
                        $evidence = 'Exchange SE detected. Dedicated vulnerability report data is not available in this run; maintain Security Update currency.'
                    }
                    'Exchange2016' {
                        $status = 'Fail'
                        $evidence = 'Exchange 2016 detected. This product line is out of support and vulnerable by baseline lifecycle policy.'
                    }
                    'Exchange2019' {
                        $status = 'Fail'
                        $evidence = 'Exchange 2019 detected. This product line is out of support and vulnerable by baseline lifecycle policy.'
                    }
                    default {
                        $status = 'Unknown'
                        $evidence = ('Unable to determine product line for vulnerability baseline evaluation (detected: {0}).' -f $productLine)
                    }
                }
            }
            'EDCA-SEC-015' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; FIP-FS baseline is not applicable.'
                    break
                }

                $fipFs = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'FipFs')) {
                    $fipFs = $server.Exchange.FipFs
                }

                if ($null -eq $fipFs) {
                    $status = 'Unknown'
                    $evidence = 'FIP-FS telemetry unavailable.'
                }
                elseif (-not [bool]$fipFs.EnginePathPresent) {
                    $status = 'Unknown'
                    $evidence = 'FIP-FS engine folder path not found.'
                }
                elseif ([int]$fipFs.ProblematicEngineCount -gt 0) {
                    $status = 'Unknown'
                    $summary = ('Potentially problematic FIP-FS engine version folder(s) detected: {0}' -f [int]$fipFs.ProblematicEngineCount)
                    $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements @($fipFs.ProblematicEngineNames)
                }
                else {
                    $status = 'Pass'
                    $evidence = 'FIP-FS engine folders do not include known problematic version markers.'
                }
            }
            'EDCA-SEC-016' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; IIS web.config baseline is not applicable.'
                    break
                }

                $iisWebConfig = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'IisWebConfig')) {
                    $iisWebConfig = $server.Exchange.IisWebConfig
                }

                if ($null -eq $iisWebConfig) {
                    $status = 'Unknown'
                    $evidence = 'IIS web.config telemetry unavailable.'
                }
                else {
                    $missingCount = if ($iisWebConfig.PSObject.Properties.Name -contains 'MissingCount' -and $null -ne $iisWebConfig.MissingCount) { [int]$iisWebConfig.MissingCount } else { 0 }
                    $invalidCount = if ($iisWebConfig.PSObject.Properties.Name -contains 'InvalidCount' -and $null -ne $iisWebConfig.InvalidCount) { [int]$iisWebConfig.InvalidCount } else { 0 }
                    $checkedCount = if ($iisWebConfig.PSObject.Properties.Name -contains 'CheckedCount' -and $null -ne $iisWebConfig.CheckedCount) { [int]$iisWebConfig.CheckedCount } else { 0 }

                    if ($missingCount -gt 0 -or $invalidCount -gt 0) {
                        $status = 'Fail'
                    }
                    else {
                        $status = 'Pass'
                    }

                    $summary = ('IIS web.config files checked: {0}; missing: {1}; invalid XML: {2}' -f $checkedCount, $missingCount, $invalidCount)
                    if ($status -eq 'Fail') {
                        $detailLines = @()
                        if ($iisWebConfig.PSObject.Properties.Name -contains 'MissingFiles' -and $null -ne $iisWebConfig.MissingFiles) {
                            $detailLines += @($iisWebConfig.MissingFiles | ForEach-Object { 'Missing: ' + [string]$_ })
                        }
                        if ($iisWebConfig.PSObject.Properties.Name -contains 'InvalidFiles' -and $null -ne $iisWebConfig.InvalidFiles) {
                            $detailLines += @($iisWebConfig.InvalidFiles | ForEach-Object { 'Invalid XML: ' + [string]$_ })
                        }
                        $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $detailLines
                    }
                    else {
                        $evidence = ('Compliant — all {0} IIS web.config files are present and valid.' -f $checkedCount)
                    }
                }
            }
            'EDCA-IAC-002' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; computer membership baseline is not applicable.'
                    break
                }

                $exchangeComputerMembership = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'ExchangeComputerMembership')) {
                    $exchangeComputerMembership = $server.Exchange.ExchangeComputerMembership
                }

                if ($null -eq $exchangeComputerMembership) {
                    $status = 'Unknown'
                    $evidence = 'Exchange computer membership telemetry unavailable.'
                }
                elseif (-not [bool]$exchangeComputerMembership.QuerySucceeded) {
                    $status = 'Unknown'
                    $evidence = 'Unable to query AD computer object group membership.'
                }
                else {
                    $missingGroups = @()
                    if ($exchangeComputerMembership.PSObject.Properties.Name -contains 'MissingGroups' -and $null -ne $exchangeComputerMembership.MissingGroups) {
                        $missingGroups = @($exchangeComputerMembership.MissingGroups | ForEach-Object { [string]$_ })
                    }

                    if ($missingGroups.Count -eq 0) {
                        $status = 'Pass'
                        $evidence = 'Computer account membership includes Exchange Trusted Subsystem and Exchange Servers.'
                    }
                    else {
                        $status = 'Fail'
                        $summary = ('Missing required AD group membership(s): {0}' -f $missingGroups.Count)
                        $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $missingGroups
                    }
                }
            }
            'EDCA-RES-002' {
                if (-not $isExchangeServer) {
                    $status = 'Skipped'
                    $evidence = 'Exchange not detected on this server; UnifiedContent cleanup baseline is not applicable.'
                    break
                }

                $unifiedContentCleanup = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'UnifiedContentCleanup')) {
                    $unifiedContentCleanup = $server.Exchange.UnifiedContentCleanup
                }

                if ($null -eq $unifiedContentCleanup) {
                    $status = 'Unknown'
                    $evidence = 'UnifiedContent cleanup telemetry unavailable.'
                }
                elseif ($unifiedContentCleanup.Configured -eq $true) {
                    $status = 'Pass'
                    $evidence = [string]$unifiedContentCleanup.Details
                }
                elseif ($unifiedContentCleanup.Configured -eq $false) {
                    $status = 'Fail'
                    $evidence = [string]$unifiedContentCleanup.Details
                }
                else {
                    $status = 'Unknown'
                    $evidence = [string]$unifiedContentCleanup.Details
                }
            }
            'EDCA-TLS-002' {
                if (-not $isExchangeServer) {
                    $status = 'Unknown'
                    $evidence = 'Exchange not detected on this server; transport retry baseline is not applicable.'
                    break
                }

                $transportRetryConfig = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'TransportRetryConfig')) {
                    $transportRetryConfig = $server.Exchange.TransportRetryConfig
                }

                if ($null -eq $transportRetryConfig) {
                    $status = 'Unknown'
                    $evidence = 'Transport retry configuration telemetry unavailable.'
                }
                else {
                    $maxPerDomainOutboundConnections = $null
                    if ($transportRetryConfig.PSObject.Properties.Name -contains 'MaxPerDomainOutboundConnections' -and $null -ne $transportRetryConfig.MaxPerDomainOutboundConnections) {
                        $maxPerDomainOutboundConnections = [int]$transportRetryConfig.MaxPerDomainOutboundConnections
                    }

                    $messageRetryIntervalMinutes = $null
                    if ($transportRetryConfig.PSObject.Properties.Name -contains 'MessageRetryIntervalMinutes' -and $null -ne $transportRetryConfig.MessageRetryIntervalMinutes) {
                        $messageRetryIntervalMinutes = [double]$transportRetryConfig.MessageRetryIntervalMinutes
                    }

                    if ($null -eq $maxPerDomainOutboundConnections -or $null -eq $messageRetryIntervalMinutes) {
                        $status = 'Unknown'
                        $evidence = 'Transport retry settings are incomplete.'
                    }
                    elseif ($maxPerDomainOutboundConnections -lt 40 -or $messageRetryIntervalMinutes -gt 5) {
                        $status = 'Unknown'
                        $evidence = ('MaxPerDomainOutboundConnections={0} (recommended >= 40); MessageRetryInterval={1} minute(s) (recommended <= 5).' -f $maxPerDomainOutboundConnections, [math]::Round($messageRetryIntervalMinutes, 2))
                    }
                    else {
                        $status = 'Pass'
                        $evidence = 'Compliant — transport retry settings are within recommended thresholds.'
                    }
                }
            }
            'EDCA-MON-004' {
                if (-not $isExchangeServer) {
                    $status = 'Unknown'
                    $evidence = 'Exchange not detected on this server; connectivity logging control is not applicable.'
                    break
                }

                $transportRetryConfig = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'TransportRetryConfig')) {
                    $transportRetryConfig = $server.Exchange.TransportRetryConfig
                }

                if ($null -eq $transportRetryConfig -or -not ($transportRetryConfig.PSObject.Properties.Name -contains 'ConnectivityLogEnabled') -or $null -eq $transportRetryConfig.ConnectivityLogEnabled) {
                    $status = 'Unknown'
                    $evidence = 'Connectivity logging telemetry unavailable.'
                }
                else {
                    $connectivityLogEnabled = [bool]$transportRetryConfig.ConnectivityLogEnabled
                    $status = if ($connectivityLogEnabled) { 'Pass' } else { 'Fail' }
                    $evidence = ('ConnectivityLogEnabled is {0}.' -f (Get-EDCAStateDescriptor -Value $connectivityLogEnabled -Expectation 'Enabled'))
                }
            }
            'EDCA-MON-005' {
                if (-not $isExchangeServer) {
                    $status = 'Unknown'
                    $evidence = 'Exchange not detected on this server; message tracking logging control is not applicable.'
                    break
                }

                $transportRetryConfig = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'TransportRetryConfig')) {
                    $transportRetryConfig = $server.Exchange.TransportRetryConfig
                }

                if ($null -eq $transportRetryConfig -or -not ($transportRetryConfig.PSObject.Properties.Name -contains 'MessageTrackingLogEnabled') -or $null -eq $transportRetryConfig.MessageTrackingLogEnabled) {
                    $status = 'Unknown'
                    $evidence = 'Message tracking logging telemetry unavailable.'
                }
                else {
                    $messageTrackingLogEnabled = [bool]$transportRetryConfig.MessageTrackingLogEnabled
                    $status = if ($messageTrackingLogEnabled) { 'Pass' } else { 'Fail' }
                    $evidence = ('MessageTrackingLogEnabled is {0}.' -f (Get-EDCAStateDescriptor -Value $messageTrackingLogEnabled -Expectation 'Enabled'))
                }
            }
            'EDCA-MON-006' {
                if (-not $isExchangeServer) {
                    $status = 'Unknown'
                    $evidence = 'Exchange not detected on this server; message subject logging control is not applicable.'
                    break
                }

                $transportRetryConfig = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'TransportRetryConfig')) {
                    $transportRetryConfig = $server.Exchange.TransportRetryConfig
                }

                if ($null -eq $transportRetryConfig -or -not ($transportRetryConfig.PSObject.Properties.Name -contains 'MessageTrackingLogSubjectLoggingEnabled') -or $null -eq $transportRetryConfig.MessageTrackingLogSubjectLoggingEnabled) {
                    $status = 'Unknown'
                    $evidence = 'Message subject logging telemetry unavailable.'
                }
                else {
                    $messageTrackingLogSubjectLoggingEnabled = [bool]$transportRetryConfig.MessageTrackingLogSubjectLoggingEnabled
                    $status = if (-not $messageTrackingLogSubjectLoggingEnabled) { 'Pass' } else { 'Fail' }
                    $evidence = ('MessageTrackingLogSubjectLoggingEnabled is {0}.' -f (Get-EDCAStateDescriptor -Value $messageTrackingLogSubjectLoggingEnabled -Expectation 'Disabled'))
                }
            }
            'EDCA-PERF-001' {
                if (-not $isExchangeServer) {
                    $status = 'Unknown'
                    $evidence = 'Exchange not detected on this server; CTS processor affinity baseline is not applicable.'
                    break
                }

                $ctsProcessorAffinityPercentage = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'CtsProcessorAffinityPercentage')) {
                    $ctsProcessorAffinityPercentage = $server.Exchange.CtsProcessorAffinityPercentage
                }

                if ($null -eq $ctsProcessorAffinityPercentage) {
                    $status = 'Pass'
                    $evidence = 'CtsProcessorAffinityPercentage is not configured (baseline default is 0).'
                }
                elseif ([int]$ctsProcessorAffinityPercentage -eq 0) {
                    $status = 'Pass'
                    $evidence = 'CtsProcessorAffinityPercentage is set to 0 (baseline).'
                }
                elseif ([int]$ctsProcessorAffinityPercentage -gt 0) {
                    $status = 'Fail'
                    $evidence = ('CtsProcessorAffinityPercentage is set to {0}. This can negatively impact search performance.' -f [int]$ctsProcessorAffinityPercentage)
                }
                else {
                    $status = 'Fail'
                    $evidence = ('CtsProcessorAffinityPercentage has an invalid value: {0}' -f [int]$ctsProcessorAffinityPercentage)
                }
            }
            'EDCA-DATA-009' {
                $hsts = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'Hsts')) {
                    $hsts = $server.Exchange.Hsts
                }

                if ($null -eq $hsts) {
                    $status = 'Unknown'
                    $evidence = 'HSTS telemetry unavailable.'
                }
                else {
                    $sites = @()
                    if ($hsts.PSObject.Properties.Name -contains 'Sites' -and $null -ne $hsts.Sites) {
                        $sites = @($hsts.Sites)
                    }

                    if ($sites.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = 'No IIS site HSTS telemetry found.'
                    }
                    else {
                        $enabledSites = @($sites | Where-Object { $_.Enabled -eq $true })
                        if ($enabledSites.Count -eq 0) {
                            $status = 'Pass'
                            $evidence = ('HSTS is not enabled on evaluated IIS sites ({0} total).' -f $sites.Count)
                        }
                        else {
                            $issues = @()
                            $warnings = @()
                            foreach ($site in $enabledSites) {
                                $siteName = [string]$site.SiteName
                                if ([string]::Equals($siteName, 'Exchange Back End', [System.StringComparison]::OrdinalIgnoreCase)) {
                                    $issues += ('{0}: HSTS enabled on Exchange Back End is unsupported.' -f $siteName)
                                }
                                if ($site.PSObject.Properties.Name -contains 'RedirectHttpToHttps' -and $site.RedirectHttpToHttps -eq $true) {
                                    $issues += ('{0}: redirectHttpToHttps is enabled.' -f $siteName)
                                }
                                if ($site.PSObject.Properties.Name -contains 'MaxAge' -and $null -ne $site.MaxAge -and [int]$site.MaxAge -lt 31536000) {
                                    $warnings += ('{0}: max-age is {1} (recommended >= 31536000).' -f $siteName, [int]$site.MaxAge)
                                }
                            }

                            $summary = ('HSTS enabled on {0} site(s): {1}' -f $enabledSites.Count, ([string]::Join(', ', @($enabledSites | ForEach-Object { [string]$_.SiteName }))))
                            if ($issues.Count -gt 0) {
                                $status = 'Fail'
                                $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements @($issues + $warnings)
                            }
                            elseif ($warnings.Count -gt 0) {
                                $status = 'Unknown'
                                $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $warnings
                            }
                            else {
                                $status = 'Pass'
                                $evidence = $summary
                            }
                        }
                    }
                }
            }
            'EDCA-DATA-010' {
                $tlsHardening = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and ($server.OS.PSObject.Properties.Name -contains 'TlsHardening')) {
                    $tlsHardening = $server.OS.TlsHardening
                }

                if ($null -eq $tlsHardening) {
                    $status = 'Unknown'
                    $evidence = 'TLS hardening telemetry unavailable.'
                }
                else {
                    $clientValue = if ($tlsHardening.PSObject.Properties.Name -contains 'AllowInsecureRenegoClients') { $tlsHardening.AllowInsecureRenegoClients } else { $null }
                    $serverValue = if ($tlsHardening.PSObject.Properties.Name -contains 'AllowInsecureRenegoServers') { $tlsHardening.AllowInsecureRenegoServers } else { $null }

                    if ($null -eq $clientValue -or $null -eq $serverValue) {
                        $status = 'Unknown'
                        $evidence = ('AllowInsecureRenego values are incomplete. Clients={0}; Servers={1}' -f $clientValue, $serverValue)
                    }
                    else {
                        $issues = @()
                        if ([int]$clientValue -ne 0) {
                            $issues += ('AllowInsecureRenegoClients={0} (expected 0).' -f [int]$clientValue)
                        }
                        if ([int]$serverValue -ne 0) {
                            $issues += ('AllowInsecureRenegoServers={0} (expected 0).' -f [int]$serverValue)
                        }

                        if ($issues.Count -gt 0) {
                            $status = 'Fail'
                            $evidence = Format-EDCAEvidenceWithElements -Summary 'TLS hardening registry values are not aligned.' -Elements $issues
                        }
                        else {
                            $status = 'Pass'
                            $evidence = 'Compliant — AllowInsecureRenegoClients and AllowInsecureRenegoServers are both 0.'
                        }
                    }
                }
            }
            'EDCA-DATA-011' {
                $tlsHardening = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and ($server.OS.PSObject.Properties.Name -contains 'TlsHardening')) {
                    $tlsHardening = $server.OS.TlsHardening
                }
                $entries = $null
                if ($null -ne $tlsHardening -and $tlsHardening.PSObject.Properties.Name -contains 'WeakCiphers') {
                    $entries = @($tlsHardening.WeakCiphers)
                }
                if ($null -eq $entries -or $entries.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Schannel cipher configuration data unavailable.'
                }
                else {
                    $explicitlyEnabled = @($entries | Where-Object { $null -ne $_.Enabled -and [int]$_.Enabled -ne 0 })
                    $notConfigured = @($entries | Where-Object { $null -eq $_.Enabled })
                    if ($explicitlyEnabled.Count -gt 0) {
                        $status = 'Fail'
                        $details = @($explicitlyEnabled | ForEach-Object { '{0}: Enabled={1} (expected 0)' -f [string]$_.Name, [int]$_.Enabled })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} weak cipher(s) are explicitly enabled.' -f $explicitlyEnabled.Count) -Elements $details
                    }
                    elseif ($notConfigured.Count -gt 0) {
                        $status = 'Unknown'
                        $details = @($notConfigured | ForEach-Object { '{0}: not explicitly configured (registry key absent)' -f [string]$_.Name })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} weak cipher(s) are not explicitly disabled via registry; explicit configuration is recommended.' -f $notConfigured.Count) -Elements $details
                    }
                    else {
                        $status = 'Pass'
                        $evidence = ('All {0} checked weak ciphers (NULL, DES, RC4, 3DES) are explicitly disabled via SCHANNEL registry.' -f $entries.Count)
                    }
                }
            }
            'EDCA-DATA-012' {
                $tlsHardening = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and ($server.OS.PSObject.Properties.Name -contains 'TlsHardening')) {
                    $tlsHardening = $server.OS.TlsHardening
                }
                $entries = $null
                if ($null -ne $tlsHardening -and $tlsHardening.PSObject.Properties.Name -contains 'WeakHashes') {
                    $entries = @($tlsHardening.WeakHashes)
                }
                if ($null -eq $entries -or $entries.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Schannel hash algorithm configuration data unavailable.'
                }
                else {
                    $explicitlyEnabled = @($entries | Where-Object { $null -ne $_.Enabled -and [int]$_.Enabled -ne 0 })
                    $notConfigured = @($entries | Where-Object { $null -eq $_.Enabled })
                    if ($explicitlyEnabled.Count -gt 0) {
                        $status = 'Fail'
                        $details = @($explicitlyEnabled | ForEach-Object { '{0}: Enabled={1} (expected 0)' -f [string]$_.Name, [int]$_.Enabled })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} weak hash algorithm(s) are explicitly enabled.' -f $explicitlyEnabled.Count) -Elements $details
                    }
                    elseif ($notConfigured.Count -gt 0) {
                        $status = 'Unknown'
                        $details = @($notConfigured | ForEach-Object { '{0}: not explicitly configured (registry key absent)' -f [string]$_.Name })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} weak hash algorithm(s) are not explicitly disabled via registry; explicit configuration is recommended.' -f $notConfigured.Count) -Elements $details
                    }
                    else {
                        $status = 'Pass'
                        $evidence = ('All {0} checked weak hash algorithms (MD5, SHA-1) are explicitly disabled via SCHANNEL registry.' -f $entries.Count)
                    }
                }
            }
            'EDCA-DATA-013' {
                $tlsHardening = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and ($server.OS.PSObject.Properties.Name -contains 'TlsHardening')) {
                    $tlsHardening = $server.OS.TlsHardening
                }
                $entries = $null
                if ($null -ne $tlsHardening -and $tlsHardening.PSObject.Properties.Name -contains 'WeakKeyExchange') {
                    $entries = @($tlsHardening.WeakKeyExchange)
                }
                if ($null -eq $entries -or $entries.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Schannel key exchange algorithm configuration data unavailable.'
                }
                else {
                    $explicitlyEnabled = @($entries | Where-Object { $null -ne $_.Enabled -and [int]$_.Enabled -ne 0 })
                    $notConfigured = @($entries | Where-Object { $null -eq $_.Enabled })
                    if ($explicitlyEnabled.Count -gt 0) {
                        $status = 'Fail'
                        $details = @($explicitlyEnabled | ForEach-Object { '{0}: Enabled={1} (expected 0)' -f [string]$_.Name, [int]$_.Enabled })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} non-forward-secret key exchange algorithm(s) are explicitly enabled.' -f $explicitlyEnabled.Count) -Elements $details
                    }
                    elseif ($notConfigured.Count -gt 0) {
                        $status = 'Unknown'
                        $details = @($notConfigured | ForEach-Object { '{0}: not explicitly configured (registry key absent)' -f [string]$_.Name })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} non-forward-secret key exchange algorithm(s) are not explicitly disabled via registry; explicit configuration is recommended.' -f $notConfigured.Count) -Elements $details
                    }
                    else {
                        $status = 'Pass'
                        $evidence = ('All {0} checked non-forward-secret key exchange algorithms (PKCS) are explicitly disabled via SCHANNEL registry.' -f $entries.Count)
                    }
                }
            }
            'EDCA-IAC-026' {
                $kerberosEncryptionTypes = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and
                    ($server.OS.PSObject.Properties.Name -contains 'KerberosEncryptionTypes')) {
                    $kerberosEncryptionTypes = $server.OS.KerberosEncryptionTypes
                }
                if ($null -eq $kerberosEncryptionTypes) {
                    # Registry key absent: Windows uses its own defaults, which include RC4.
                    $status = 'Fail'
                    $evidence = 'KerberosEncryptionTypes registry value (HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes) is not set. Windows default includes RC4-HMAC. Set to 24 (AES128 + AES256 only).'
                }
                else {
                    $encVal = [int]$kerberosEncryptionTypes
                    $weakTypes = @()
                    if ($encVal -band 1) { $weakTypes += 'DES-CBC-CRC (bit 0)' }
                    if ($encVal -band 2) { $weakTypes += 'DES-CBC-MD5 (bit 1)' }
                    if ($encVal -band 4) { $weakTypes += 'RC4-HMAC (bit 2)' }
                    $hasAes128 = ($encVal -band 8) -ne 0
                    $hasAes256 = ($encVal -band 16) -ne 0
                    if ($weakTypes.Count -gt 0) {
                        $status = 'Fail'
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('SupportedEncryptionTypes={0}: {1} weak Kerberos encryption type(s) are enabled. AES128={2}, AES256={3}.' -f $encVal, $weakTypes.Count, $hasAes128, $hasAes256) -Elements $weakTypes
                    }
                    elseif (-not $hasAes128 -or -not $hasAes256) {
                        $status = 'Fail'
                        $evidence = ('SupportedEncryptionTypes={0}: no weak types enabled, but AES coverage is incomplete (AES128={1}, AES256={2}). Expected value: 24 (AES128 + AES256).' -f $encVal, $hasAes128, $hasAes256)
                    }
                    else {
                        $status = 'Pass'
                        $evidence = ('SupportedEncryptionTypes={0}: AES128 and AES256 are enabled; DES and RC4 are not set.' -f $encVal)
                    }
                }
            }
            'EDCA-SEC-027' {
                $iisModules = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'IisModules')) {
                    $iisModules = $server.Exchange.IisModules
                }

                if ($null -eq $iisModules -or $iisModules.QuerySucceeded -ne $true) {
                    $status = 'Unknown'
                    $evidence = 'IIS module signature telemetry unavailable.'
                }
                else {
                    $unsignedCount = if ($iisModules.PSObject.Properties.Name -contains 'UnsignedCount' -and $null -ne $iisModules.UnsignedCount) { [int]$iisModules.UnsignedCount } else { 0 }
                    $nonMicrosoftCount = if ($iisModules.PSObject.Properties.Name -contains 'NonMicrosoftSignedCount' -and $null -ne $iisModules.NonMicrosoftSignedCount) { [int]$iisModules.NonMicrosoftSignedCount } else { 0 }
                    $invalidSignatureCount = if ($iisModules.PSObject.Properties.Name -contains 'InvalidSignatureCount' -and $null -ne $iisModules.InvalidSignatureCount) { [int]$iisModules.InvalidSignatureCount } else { 0 }

                    if ($unsignedCount -gt 0) {
                        $status = 'Fail'
                    }
                    elseif ($nonMicrosoftCount -gt 0 -or $invalidSignatureCount -gt 0) {
                        $status = 'Unknown'
                    }
                    else {
                        $status = 'Pass'
                    }

                    $summary = ('IIS modules analyzed. Unsigned={0}; Non-Microsoft signed={1}; Invalid signatures={2}.' -f $unsignedCount, $nonMicrosoftCount, $invalidSignatureCount)
                    if ($status -eq 'Pass') {
                        $evidence = $summary
                    }
                    else {
                        $modules = @()
                        if ($iisModules.PSObject.Properties.Name -contains 'Modules' -and $null -ne $iisModules.Modules) {
                            $modules = @($iisModules.Modules)
                        }

                        $detailLines = @($modules | Where-Object {
                                ($_.Signed -eq $false) -or
                                ($_.Signed -eq $true -and $_.IsMicrosoftSigned -eq $false) -or
                                ($_.Signed -eq $true -and $null -ne $_.SignatureStatus -and $_.SignatureStatus -ne 'Valid')
                            } | ForEach-Object {
                                '{0} | Signed={1} | MicrosoftSigned={2} | SignatureStatus={3}' -f [string]$_.Name, [string]$_.Signed, [string]$_.IsMicrosoftSigned, [string]$_.SignatureStatus
                            })

                        $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $detailLines
                    }
                }
            }
            'EDCA-MON-003' {
                $pendingReboot = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and ($server.OS.PSObject.Properties.Name -contains 'PendingReboot')) {
                    $pendingReboot = $server.OS.PendingReboot
                }

                if ($null -eq $pendingReboot) {
                    $status = 'Unknown'
                    $evidence = 'Pending reboot telemetry unavailable.'
                }
                elseif ($pendingReboot.Pending -eq $true) {
                    $status = 'Fail'
                    $locations = @()
                    if ($pendingReboot.PSObject.Properties.Name -contains 'Locations' -and $null -ne $pendingReboot.Locations) {
                        $locations = @($pendingReboot.Locations | ForEach-Object { [string]$_ })
                    }
                    $evidence = Format-EDCAEvidenceWithElements -Summary 'Server has a pending reboot state.' -Elements $locations
                }
                else {
                    $status = 'Pass'
                    $evidence = 'No pending reboot indicators detected.'
                }
            }
            'EDCA-SEC-028' {
                $dynamicMemory = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and ($server.OS.PSObject.Properties.Name -contains 'DynamicMemory')) {
                    $dynamicMemory = $server.OS.DynamicMemory
                }

                if ($null -eq $dynamicMemory) {
                    $status = 'Unknown'
                    $evidence = 'Dynamic memory telemetry unavailable.'
                }
                elseif ($dynamicMemory.IsVirtual -ne $true) {
                    $status = 'Pass'
                    $evidence = ('Dynamic memory check not applicable for server type {0}.' -f [string]$dynamicMemory.ServerType)
                }
                elseif ($dynamicMemory.Detected -eq $true) {
                    $status = 'Fail'
                    $evidence = [string]$dynamicMemory.Details
                }
                elseif ($dynamicMemory.Detected -eq $false) {
                    $status = 'Pass'
                    $evidence = [string]$dynamicMemory.Details
                }
                else {
                    $status = 'Unknown'
                    $evidence = [string]$dynamicMemory.Details
                }
            }
            'EDCA-SEC-029' {
                $msmqFeature = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and ($server.OS.PSObject.Properties.Name -contains 'MsmqFeature')) {
                    $msmqFeature = $server.OS.MsmqFeature
                }

                if ($null -eq $msmqFeature -or $msmqFeature.QuerySucceeded -ne $true) {
                    $status = 'Unknown'
                    $evidence = 'MSMQ feature telemetry unavailable.'
                }
                elseif ($msmqFeature.Installed -eq $true) {
                    $status = 'Fail'
                    $installedFeatures = @()
                    if ($msmqFeature.PSObject.Properties.Name -contains 'InstalledFeatures' -and $null -ne $msmqFeature.InstalledFeatures) {
                        $installedFeatures = @($msmqFeature.InstalledFeatures | ForEach-Object { [string]$_ })
                    }
                    $evidence = Format-EDCAEvidenceWithElements -Summary 'MSMQ-related Windows features are installed.' -Elements $installedFeatures
                }
                else {
                    $status = 'Pass'
                    $evidence = 'MSMQ-related Windows features are not installed.'
                }
            }
            'EDCA-SEC-030' {
                $disableAsyncNotification = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'DisableAsyncNotification')) {
                    $disableAsyncNotification = $server.Exchange.DisableAsyncNotification
                }

                if ($null -eq $disableAsyncNotification) {
                    $status = 'Pass'
                    $evidence = 'DisableAsyncNotification is not configured (baseline default behavior).'
                }
                elseif ([int]$disableAsyncNotification -eq 0) {
                    $status = 'Pass'
                    $evidence = 'DisableAsyncNotification is set to 0.'
                }
                else {
                    $status = 'Unknown'
                    $evidence = ('DisableAsyncNotification is set to {0}. This is typically temporary and should be reset to 0 after workaround usage.' -f [int]$disableAsyncNotification)
                }
            }
            'EDCA-SEC-031' {
                $tokenCacheModuleLoaded = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'TokenCacheModuleLoaded')) {
                    $tokenCacheModuleLoaded = $server.Exchange.TokenCacheModuleLoaded
                }

                if ($null -eq $tokenCacheModuleLoaded) {
                    $status = 'Unknown'
                    $evidence = 'TokenCacheModule telemetry unavailable.'
                }
                elseif ([bool]$tokenCacheModuleLoaded) {
                    $status = 'Pass'
                    $evidence = 'TokenCacheModule is loaded in IIS global modules.'
                }
                else {
                    $status = 'Unknown'
                    $evidence = 'TokenCacheModule is not loaded. Review CVE-2023-21709 / CVE-2023-36434 mitigation and rollback guidance before changing state.'
                }
            }
            'EDCA-IAC-027' {
                $computerMembership = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'ExchangeComputerMembership')) {
                    $computerMembership = $server.Exchange.ExchangeComputerMembership
                }

                if ($null -eq $computerMembership) {
                    $status = 'Unknown'
                    $evidence = 'Exchange computer membership telemetry unavailable.'
                }
                elseif (-not ($computerMembership.PSObject.Properties.Name -contains 'QuerySucceeded') -or -not [bool]$computerMembership.QuerySucceeded) {
                    $status = 'Unknown'
                    $evidence = 'Active Directory query for computer account attributes did not succeed — unable to determine delegation state.'
                }
                elseif (-not ($computerMembership.PSObject.Properties.Name -contains 'TrustedForDelegation') -or $null -eq $computerMembership.TrustedForDelegation) {
                    $status = 'Unknown'
                    $evidence = 'TrustedForDelegation attribute not collected — re-run collection with the current EDCA build to evaluate this control.'
                }
                elseif ([bool]$computerMembership.TrustedForDelegation) {
                    $status = 'Fail'
                    $evidence = 'Unconstrained Kerberos delegation is enabled (TRUSTED_FOR_DELEGATION flag set in userAccountControl). Any Kerberos TGT presented to this server can be captured and replayed, enabling full domain compromise. Remove the flag using Set-ADComputer or Active Directory Users and Computers (Account tab: clear "Trust this computer for delegation to any service (Kerberos only)"). If delegation is required for a specific integration, configure constrained or resource-based constrained delegation targeting only the required SPNs.'
                }
                else {
                    $status = 'Pass'
                    $evidence = 'Unconstrained Kerberos delegation is not enabled (TRUSTED_FOR_DELEGATION flag not set).'
                }
            }
            'EDCA-IAC-007' {
                $alternateServiceAccount = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'AlternateServiceAccount')) {
                    $alternateServiceAccount = $server.Exchange.AlternateServiceAccount
                }

                if ($null -eq $alternateServiceAccount) {
                    $status = 'Unknown'
                    $evidence = 'Alternate Service Account telemetry unavailable.'
                }
                else {
                    $querySucceeded = $null
                    if ($alternateServiceAccount.PSObject.Properties.Name -contains 'QuerySucceeded') {
                        $querySucceeded = $alternateServiceAccount.QuerySucceeded
                    }

                    if ($querySucceeded -eq $false) {
                        $status = 'Unknown'
                        $evidence = 'Alternate Service Account telemetry collection failed.'
                    }
                    else {
                        $configured = $null
                        if ($alternateServiceAccount.PSObject.Properties.Name -contains 'Configured') {
                            $configured = $alternateServiceAccount.Configured
                        }

                        $sourceCommand = 'unknown command'
                        if (($alternateServiceAccount.PSObject.Properties.Name -contains 'SourceCommand') -and -not [string]::IsNullOrWhiteSpace([string]$alternateServiceAccount.SourceCommand)) {
                            $sourceCommand = [string]$alternateServiceAccount.SourceCommand
                        }

                        $credentialCount = 0
                        if (($alternateServiceAccount.PSObject.Properties.Name -contains 'CredentialCount') -and $null -ne $alternateServiceAccount.CredentialCount) {
                            $credentialCount = [int]$alternateServiceAccount.CredentialCount
                        }

                        $credentials = @()
                        if (($alternateServiceAccount.PSObject.Properties.Name -contains 'Credentials') -and $null -ne $alternateServiceAccount.Credentials) {
                            $credentials = @($alternateServiceAccount.Credentials | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)
                        }

                        if ($configured -eq $false) {
                            $status = 'Skipped'
                            $evidence = 'No Alternate Service Account (ASA) credentials detected. ASA is only required in load-balanced Client Access deployments using Kerberos; this control is not applicable when ASA is not in use.'
                        }
                        elseif ($configured -eq $true) {
                            $summary = ('ASA is configured via {0}; parsed effective credentials: {1}.' -f $sourceCommand, $credentialCount)
                            $details = @()
                            if ($credentials.Count -gt 0) {
                                $details += ('Effective credentials: {0}' -f ($credentials -join ', '))
                            }

                            $issues = @()
                            if ($credentialCount -gt 2) {
                                $issues += ('Detected {0} ASA credentials. Keep only current and previous credentials during rollover.' -f $credentialCount)
                            }

                            if ($exchangeServerCount -gt 1) {
                                $peerCredentialSets = @()
                                foreach ($peerServer in @($CollectionData.Servers | Where-Object {
                                            ($_.PSObject.Properties.Name -contains 'Exchange') -and
                                            $null -ne $_.Exchange -and
                                            ($_.Exchange.PSObject.Properties.Name -contains 'IsExchangeServer') -and
                                            [bool]$_.Exchange.IsExchangeServer
                                        })) {
                                    if (-not ($peerServer.Exchange.PSObject.Properties.Name -contains 'AlternateServiceAccount') -or $null -eq $peerServer.Exchange.AlternateServiceAccount) {
                                        continue
                                    }

                                    $peerAsa = $peerServer.Exchange.AlternateServiceAccount
                                    $peerQuerySucceeded = if ($peerAsa.PSObject.Properties.Name -contains 'QuerySucceeded') { $peerAsa.QuerySucceeded } else { $null }
                                    $peerConfigured = if ($peerAsa.PSObject.Properties.Name -contains 'Configured') { $peerAsa.Configured } else { $null }
                                    if ($peerQuerySucceeded -eq $false -or $peerConfigured -ne $true) {
                                        continue
                                    }

                                    $peerCredentials = @()
                                    if (($peerAsa.PSObject.Properties.Name -contains 'Credentials') -and $null -ne $peerAsa.Credentials) {
                                        $peerCredentials = @($peerAsa.Credentials | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)
                                    }

                                    if ($peerCredentials.Count -gt 0) {
                                        $peerCredentialSets += [string]::Join('|', $peerCredentials)
                                    }
                                }

                                $distinctPeerCredentialSets = @($peerCredentialSets | Sort-Object -Unique)
                                if ($distinctPeerCredentialSets.Count -gt 1) {
                                    $issues += 'ASA credential sets differ between Exchange servers. Keep shared Client Access namespaces on the same ASA credential set.'
                                }
                            }

                            $bestPracticeNotes = @(
                                'Best practice: use a dedicated ASA account with least privilege (computer account is recommended by Microsoft).',
                                'Best practice: keep one active and at most one previous credential during password rollover.',
                                'Best practice: deploy and rotate ASA with RollAlternateServiceAccountPassword.ps1 and remove stale credentials.',
                                'Best practice: keep ASA configuration consistent across all servers that share the same client access namespaces.'
                            )

                            if ($issues.Count -gt 0) {
                                $status = 'Fail'
                                $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements @($issues + $details + $bestPracticeNotes)
                            }
                            else {
                                $status = 'Pass'
                                $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements @($details + $bestPracticeNotes)
                            }
                        }
                        else {
                            $status = 'Unknown'
                            $evidence = 'Alternate Service Account telemetry is present but configuration state could not be determined.'
                        }
                    }
                }
            }
            'EDCA-RES-004' {
                $databases = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'MailboxDatabases')) {
                    $databases = @($server.Exchange.MailboxDatabases)
                }
                if ($databases.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mailbox database data available for this server.'
                }
                else {
                    $dbServerResults = @($databases | ForEach-Object {
                            $db = $_
                            $dbStatus = if ($null -eq $db.ItemRetentionDays -or [int]$db.ItemRetentionDays -lt 14) { 'Fail' } else { 'Pass' }
                            $dbEvidence = if ($dbStatus -eq 'Pass') {
                                ('ItemRetentionDays={0} — compliant (>= 14 days).' -f $db.ItemRetentionDays)
                            }
                            else {
                                ('ItemRetentionDays={0} — non-compliant (expected >= 14 days).' -f $db.ItemRetentionDays)
                            }
                            [pscustomobject]@{ Server = [string]$db.Name; Status = $dbStatus; Evidence = $dbEvidence }
                        })
                }
            }
            'EDCA-RES-005' {
                $databases = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'MailboxDatabases')) {
                    $databases = @($server.Exchange.MailboxDatabases)
                }
                if ($databases.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mailbox database data available for this server.'
                }
                else {
                    $dbServerResults = @($databases | ForEach-Object {
                            $db = $_
                            $dbStatus = if ($null -eq $db.MailboxRetentionDays -or [int]$db.MailboxRetentionDays -lt 30) { 'Fail' } else { 'Pass' }
                            $dbEvidence = if ($dbStatus -eq 'Pass') {
                                ('MailboxRetentionDays={0} — compliant (>= 30 days).' -f $db.MailboxRetentionDays)
                            }
                            else {
                                ('MailboxRetentionDays={0} — non-compliant (expected >= 30 days).' -f $db.MailboxRetentionDays)
                            }
                            [pscustomobject]@{ Server = [string]$db.Name; Status = $dbStatus; Evidence = $dbEvidence }
                        })
                }
            }
            'EDCA-RES-006' {
                $databases = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'MailboxDatabases')) {
                    $databases = @($server.Exchange.MailboxDatabases)
                }
                if ($databases.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mailbox database data available for this server.'
                }
                else {
                    $dbServerResults = @($databases | ForEach-Object {
                            $db = $_
                            $retainEnabled = ($db.PSObject.Properties.Name -contains 'RetainDeletedItemsUntilBackup') -and ($null -ne $db.RetainDeletedItemsUntilBackup) -and ([bool]$db.RetainDeletedItemsUntilBackup -eq $true)
                            $dbStatus = if ($retainEnabled) { 'Pass' } else { 'Fail' }
                            $retainValue = if (($db.PSObject.Properties.Name -contains 'RetainDeletedItemsUntilBackup') -and $null -ne $db.RetainDeletedItemsUntilBackup) { [string]$db.RetainDeletedItemsUntilBackup } else { 'N/A' }
                            $dbEvidence = if ($dbStatus -eq 'Pass') {
                                'RetainDeletedItemsUntilBackup=True — compliant.'
                            }
                            else {
                                ('RetainDeletedItemsUntilBackup={0} — non-compliant (expected True).' -f $retainValue)
                            }
                            [pscustomobject]@{ Server = [string]$db.Name; Status = $dbStatus; Evidence = $dbEvidence }
                        })
                }
            }
            'EDCA-MON-007' {
                $connectors = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'ReceiveConnectors')) {
                    $connectors = @($server.Exchange.ReceiveConnectors)
                }
                if ($connectors.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No receive connector data available for this server.'
                }
                else {
                    $nonCompliant = @($connectors | Where-Object { $null -eq $_.ProtocolLoggingLevel -or [string]$_.ProtocolLoggingLevel -ne 'Verbose' })
                    if ($nonCompliant.Count -gt 0) {
                        $status = 'Fail'
                        $details = @($nonCompliant | ForEach-Object { ('{0}: ProtocolLoggingLevel={1} (expected Verbose)' -f [string]$_.Identity, [string]$_.ProtocolLoggingLevel) })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} receive connector(s) do not have Verbose protocol logging.' -f $nonCompliant.Count, $connectors.Count) -Elements $details
                    }
                    else {
                        $status = 'Pass'
                        $evidence = ('All {0} receive connector(s) have Verbose protocol logging enabled.' -f $connectors.Count)
                    }
                }
            }
            'EDCA-GOV-005' {
                $dbs = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'MailboxDatabases')) {
                    $dbs = @($server.Exchange.MailboxDatabases)
                }
                if ($dbs.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mailbox databases found on this server.'
                }
                else {
                    $dbServerResults = @($dbs | ForEach-Object {
                            $db = $_
                            $isUnlimited = ($db.PSObject.Properties.Name -contains 'IssueWarningQuotaIsUnlimited') -and [bool]$db.IssueWarningQuotaIsUnlimited
                            $dbStatus = if ($isUnlimited) { 'Fail' } else { 'Pass' }
                            $dbEvidence = if ($isUnlimited) {
                                'IssueWarningQuota=Unlimited — non-compliant (a quota must be configured).'
                            }
                            else {
                                'IssueWarningQuota is configured (not Unlimited) — compliant.'
                            }
                            [pscustomobject]@{ Server = [string]$db.Name; Status = $dbStatus; Evidence = $dbEvidence }
                        })
                }
            }
            'EDCA-GOV-006' {
                $dbs = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'MailboxDatabases')) {
                    $dbs = @($server.Exchange.MailboxDatabases)
                }
                if ($dbs.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mailbox databases found on this server.'
                }
                else {
                    $dbServerResults = @($dbs | ForEach-Object {
                            $db = $_
                            $isUnlimited = ($db.PSObject.Properties.Name -contains 'ProhibitSendReceiveQuotaIsUnlimited') -and [bool]$db.ProhibitSendReceiveQuotaIsUnlimited
                            $dbStatus = if ($isUnlimited) { 'Fail' } else { 'Pass' }
                            $dbEvidence = if ($isUnlimited) {
                                'ProhibitSendReceiveQuota=Unlimited — non-compliant (a quota must be configured).'
                            }
                            else {
                                'ProhibitSendReceiveQuota is configured (not Unlimited) — compliant.'
                            }
                            [pscustomobject]@{ Server = [string]$db.Name; Status = $dbStatus; Evidence = $dbEvidence }
                        })
                }
            }
            'EDCA-GOV-007' {
                $dbs = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'MailboxDatabases')) {
                    $dbs = @($server.Exchange.MailboxDatabases)
                }
                if ($dbs.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mailbox databases found on this server.'
                }
                else {
                    $dbServerResults = @($dbs | ForEach-Object {
                            $db = $_
                            $isUnlimited = ($db.PSObject.Properties.Name -contains 'ProhibitSendQuotaIsUnlimited') -and [bool]$db.ProhibitSendQuotaIsUnlimited
                            $dbStatus = if ($isUnlimited) { 'Fail' } else { 'Pass' }
                            $dbEvidence = if ($isUnlimited) {
                                'ProhibitSendQuota=Unlimited — non-compliant (a quota must be configured).'
                            }
                            else {
                                'ProhibitSendQuota is configured (not Unlimited) — compliant.'
                            }
                            [pscustomobject]@{ Server = [string]$db.Name; Status = $dbStatus; Evidence = $dbEvidence }
                        })
                }
            }
            'EDCA-SEC-033' {
                $trc = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'TransportRetryConfig')) {
                    $trc = $server.Exchange.TransportRetryConfig
                }
                if ($null -eq $trc) {
                    $status = 'Unknown'
                    $evidence = 'TransportRetryConfig data unavailable on this server.'
                }
                else {
                    $path = if ($trc.PSObject.Properties.Name -contains 'PickupDirectoryPath') { $trc.PickupDirectoryPath } else { $null }
                    $status = if ([string]::IsNullOrWhiteSpace($path)) { 'Pass' } else { 'Fail' }
                    $evidence = if ([string]::IsNullOrWhiteSpace($path)) { 'Compliant — PickupDirectoryPath is not set on this server.' } else { ('PickupDirectoryPath is configured on this server: {0}' -f $path) }
                }
            }
            'EDCA-TLS-013' {
                $allConnectors = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'ReceiveConnectors')) {
                    $allConnectors = @($server.Exchange.ReceiveConnectors)
                }
                if ($allConnectors.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No receive connectors found on this server.'
                }
                else {
                    $limit = 26214400 # 25 MB in bytes
                    $nonCompliant = @()
                    $unknownCount = 0
                    foreach ($rc in $allConnectors) {
                        $maxMsgStr = if ($rc.PSObject.Properties.Name -contains 'MaxMessageSize') { [string]$rc.MaxMessageSize } else { $null }
                        if ([string]::IsNullOrWhiteSpace($maxMsgStr)) { $unknownCount++; continue }
                        $match = [regex]::Match($maxMsgStr, '\(([\d,]+)\s*bytes\)')
                        if ($match.Success) {
                            $bytes = [long]($match.Groups[1].Value -replace ',', '')
                            if ($bytes -gt $limit) { $nonCompliant += $rc }
                        }
                        else { $unknownCount++ }
                    }
                    if ($nonCompliant.Count -gt 0) {
                        $status = 'Fail'
                        $details = @($nonCompliant | ForEach-Object { ('{0}: MaxMessageSize exceeds 25 MB' -f [string]$_.Identity) })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} receive connector(s) exceed the 25 MB limit.' -f $nonCompliant.Count, $allConnectors.Count) -Elements $details
                    }
                    elseif ($unknownCount -gt 0) {
                        $status = 'Unknown'
                        $evidence = ('MaxMessageSize data unavailable or could not be parsed for {0} receive connector(s).' -f $unknownCount)
                    }
                    else {
                        $status = 'Pass'
                        $evidence = ('All {0} receive connector(s) have MaxMessageSize at or below 25 MB.' -f $allConnectors.Count)
                    }
                }
            }
            'EDCA-DATA-014' {
                $val = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'OwaSmimeEnabled')) {
                    $val = $server.Exchange.OwaSmimeEnabled
                }
                if ($null -eq $val) {
                    $status = 'Unknown'
                    $evidence = 'OWA S/MIME data unavailable on this server.'
                }
                else {
                    $status = if ([bool]$val) { 'Pass' } else { 'Fail' }
                    $evidence = if ([bool]$val) { 'Compliant — S/MIME is enabled on at least one OWA virtual directory on this server.' } else { 'S/MIME is not enabled on any OWA virtual directory on this server.' }
                }
            }
            'EDCA-DATA-015' {
                $rpc = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'RpcClientAccessConfig')) {
                    $rpc = $server.Exchange.RpcClientAccessConfig
                }
                if ($null -eq $rpc) {
                    $status = 'Unknown'
                    $evidence = 'RPC client access configuration unavailable on this server.'
                }
                else {
                    $enc = if ($rpc.PSObject.Properties.Name -contains 'EncryptionRequired') { $rpc.EncryptionRequired } else { $null }
                    if ($null -eq $enc) {
                        $status = 'Unknown'
                        $evidence = 'EncryptionRequired property not available in RPC client access configuration.'
                    }
                    else {
                        $status = if ([bool]$enc) { 'Pass' } else { 'Fail' }
                        $evidence = if ([bool]$enc) { 'Compliant — EncryptionRequired is True for RPC client access on this server.' } else { 'EncryptionRequired is False for RPC client access on this server.' }
                    }
                }
            }
            'EDCA-TLS-015' {
                $connectors = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'ReceiveConnectors')) {
                    $connectors = @($server.Exchange.ReceiveConnectors)
                }
                if ($connectors.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No receive connector data available for this server.'
                }
                else {
                    $nonCompliant = @($connectors | Where-Object {
                            -not ($_.PSObject.Properties.Name -contains 'MaxHopCount') -or
                            $null -eq $_.MaxHopCount -or
                            [int]$_.MaxHopCount -ne 60
                        })
                    if ($nonCompliant.Count -gt 0) {
                        $status = 'Fail'
                        $details = @($nonCompliant | ForEach-Object { ('{0}: MaxHopCount={1} (expected 60)' -f [string]$_.Identity, $(if ($_.PSObject.Properties.Name -contains 'MaxHopCount') { $_.MaxHopCount } else { 'N/A' })) })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} receive connector(s) do not have MaxHopCount set to 60.' -f $nonCompliant.Count, $connectors.Count) -Elements $details
                    }
                    else {
                        $status = 'Pass'
                        $evidence = ('All {0} receive connector(s) have MaxHopCount set to 60.' -f $connectors.Count)
                    }
                }
            }
            'EDCA-TLS-016' {
                $trc = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'TransportRetryConfig')) {
                    $trc = $server.Exchange.TransportRetryConfig
                }
                if ($null -eq $trc -or -not ($trc.PSObject.Properties.Name -contains 'MaxOutboundConnections') -or $null -eq $trc.MaxOutboundConnections) {
                    $status = 'Unknown'
                    $evidence = 'MaxOutboundConnections data unavailable on this server.'
                }
                else {
                    $val = [int]$trc.MaxOutboundConnections
                    if ($val -eq -1) {
                        $status = 'Fail'
                        $evidence = 'MaxOutboundConnections is Unlimited (expected 1000).'
                    }
                    elseif ($val -ne 1000) {
                        $status = 'Fail'
                        $evidence = ('MaxOutboundConnections is {0} (expected 1000).' -f $val)
                    }
                    else {
                        $status = 'Pass'
                        $evidence = 'Compliant — MaxOutboundConnections is 1000.'
                    }
                }
            }
            'EDCA-TLS-017' {
                $trc = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'TransportRetryConfig')) {
                    $trc = $server.Exchange.TransportRetryConfig
                }
                if ($null -eq $trc -or -not ($trc.PSObject.Properties.Name -contains 'MaxPerDomainOutboundConnections') -or $null -eq $trc.MaxPerDomainOutboundConnections) {
                    $status = 'Unknown'
                    $evidence = 'MaxPerDomainOutboundConnections data unavailable on this server.'
                }
                else {
                    $val = [int]$trc.MaxPerDomainOutboundConnections
                    if ($val -eq -1) {
                        $status = 'Fail'
                        $evidence = 'MaxPerDomainOutboundConnections is Unlimited (expected 20).'
                    }
                    elseif ($val -ne 20) {
                        $status = 'Fail'
                        $evidence = ('MaxPerDomainOutboundConnections is {0} (expected 20).' -f $val)
                    }
                    else {
                        $status = 'Pass'
                        $evidence = 'Compliant — MaxPerDomainOutboundConnections is 20.'
                    }
                }
            }
            'EDCA-IAC-013' {
                $owaAuth = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'OwaFormsAuthentication')) {
                    $owaAuth = @($server.Exchange.OwaFormsAuthentication)
                }
                if ($owaAuth.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'OWA virtual directory data unavailable on this server.'
                }
                else {
                    $productLine = Get-EDCAProductLineFromServerData -Server $server
                    if ($productLine -eq 'Exchange2016') {
                        $nonCompliant = @($owaAuth | Where-Object { ($_.PSObject.Properties.Name -contains 'FormsAuthentication') -and [bool]$_.FormsAuthentication })
                        if ($nonCompliant.Count -gt 0) {
                            $status = 'Fail'
                            $details = @($nonCompliant | ForEach-Object { ('{0}: FormsAuthentication=True (Exchange 2016 requires False)' -f [string]$_.Identity) })
                            $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} OWA virtual director(ies) have forms-based authentication enabled (Exchange 2016 requires disabled).' -f $nonCompliant.Count, $owaAuth.Count) -Elements $details
                        }
                        else {
                            $status = 'Pass'
                            $evidence = ('Compliant — all {0} OWA virtual director(ies) have forms-based authentication disabled (Exchange 2016).' -f $owaAuth.Count)
                        }
                    }
                    else {
                        $nonCompliant = @($owaAuth | Where-Object { -not ($_.PSObject.Properties.Name -contains 'FormsAuthentication') -or -not [bool]$_.FormsAuthentication })
                        if ($nonCompliant.Count -gt 0) {
                            $status = 'Fail'
                            $details = @($nonCompliant | ForEach-Object { ('{0}: FormsAuthentication=False (Exchange 2019/SE requires True)' -f [string]$_.Identity) })
                            $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} OWA virtual director(ies) do not have forms-based authentication enabled (Exchange 2019/SE requires enabled).' -f $nonCompliant.Count, $owaAuth.Count) -Elements $details
                        }
                        else {
                            $status = 'Pass'
                            $evidence = ('Compliant — all {0} OWA virtual director(ies) have forms-based authentication enabled (Exchange 2019/SE).' -f $owaAuth.Count)
                        }
                    }
                }
            }
            'EDCA-RES-007' {
                $databases = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'MailboxDatabases')) {
                    $databases = @($server.Exchange.MailboxDatabases)
                }
                if ($databases.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mailbox database data available for this server.'
                }
                else {
                    $dbServerResults = @($databases | ForEach-Object {
                            $db = $_
                            $hasProperty = $db.PSObject.Properties.Name -contains 'CircularLoggingEnabled'
                            if (-not $hasProperty -or $null -eq $db.CircularLoggingEnabled) {
                                $dbStatus = 'Unknown'
                                $dbEvidence = 'CircularLoggingEnabled data unavailable.'
                            }
                            elseif ([bool]$db.CircularLoggingEnabled) {
                                $dbStatus = 'Fail'
                                $dbEvidence = 'CircularLoggingEnabled=True — non-compliant (expected False).'
                            }
                            else {
                                $dbStatus = 'Pass'
                                $dbEvidence = 'CircularLoggingEnabled=False — compliant.'
                            }
                            [pscustomobject]@{ Server = [string]$db.Name; Status = $dbStatus; Evidence = $dbEvidence }
                        })
                }
            }
            'EDCA-GOV-008' {
                $errReporting = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'ErrorReportingEnabled') -and
                    $null -ne $server.Exchange.ErrorReportingEnabled) {
                    $errReporting = [bool]$server.Exchange.ErrorReportingEnabled
                }
                if ($null -eq $errReporting) {
                    $status = 'Unknown'
                    $evidence = 'ErrorReportingEnabled data not available.'
                }
                else {
                    $status = if (-not $errReporting) { 'Pass' } else { 'Fail' }
                    $errDesc = if (-not $errReporting) { 'compliant (disabled)' } else { 'non-compliant (must be False)' }
                    $evidence = ('ErrorReportingEnabled={0} — {1}.' -f $errReporting, $errDesc)
                }
            }
            'EDCA-RES-008' {
                $databases = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'MailboxDatabases')) {
                    $databases = @($server.Exchange.MailboxDatabases)
                }
                $volumes = @()
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and
                    ($server.OS.PSObject.Properties.Name -contains 'Volumes')) {
                    $volumes = @($server.OS.Volumes | Where-Object {
                            ($_.PSObject.Properties.Name -contains 'DeviceID') -and
                            -not [string]::IsNullOrWhiteSpace([string]$_.DeviceID) -and
                            ($_.PSObject.Properties.Name -contains 'Name') -and
                            -not [string]::IsNullOrWhiteSpace([string]$_.Name)
                        })
                }
                if ($databases.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mailbox database data available for this server.'
                }
                elseif ($volumes.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Volume inventory not available; cannot evaluate storage isolation.'
                }
                else {
                    # Return the volume whose mount path (Name) is the longest prefix of $Path.
                    # This correctly handles both drive-letter volumes (D:\) and directory mount
                    # points (C:\MountedVolumes\DB1\) under the same drive letter.
                    $getVolumeForPath = {
                        param([string]$Path, [object[]]$Vols)
                        $normPath = $Path.TrimEnd('\') + '\'
                        $bestMatch = $null
                        $bestLen = -1
                        foreach ($vol in $Vols) {
                            $mountPath = ([string]$vol.Name).TrimEnd('\') + '\'
                            if ($normPath.StartsWith($mountPath, [System.StringComparison]::OrdinalIgnoreCase) -and $mountPath.Length -gt $bestLen) {
                                $bestMatch = $vol
                                $bestLen = $mountPath.Length
                            }
                        }
                        return $bestMatch
                    }

                    # Resolve the OS system volume
                    $osVolDeviceId = $null
                    $osVolLabel = $null
                    if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and
                        ($server.OS.PSObject.Properties.Name -contains 'SystemDrive') -and
                        -not [string]::IsNullOrWhiteSpace([string]$server.OS.SystemDrive)) {
                        $osVol = & $getVolumeForPath -Path ([string]$server.OS.SystemDrive) -Vols $volumes
                        if ($null -ne $osVol) {
                            $osVolDeviceId = [string]$osVol.DeviceID
                            $osVolLabel = [string]$osVol.Name
                        }
                    }

                    # Resolve the Exchange binaries volume
                    $exchVolDeviceId = $null
                    $exchVolLabel = $null
                    $exchInstallPath = $null
                    if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                        ($server.Exchange.PSObject.Properties.Name -contains 'InstallPath') -and
                        -not [string]::IsNullOrWhiteSpace([string]$server.Exchange.InstallPath)) {
                        $exchInstallPath = [string]$server.Exchange.InstallPath
                        $exchVol = & $getVolumeForPath -Path $exchInstallPath -Vols $volumes
                        if ($null -ne $exchVol) {
                            $exchVolDeviceId = [string]$exchVol.DeviceID
                            $exchVolLabel = [string]$exchVol.Name
                        }
                    }

                    $dbServerResults = @($databases | ForEach-Object {
                            $db = $_
                            $edbPath = if (($db.PSObject.Properties.Name -contains 'EdbFilePath') -and -not [string]::IsNullOrWhiteSpace([string]$db.EdbFilePath)) { [string]$db.EdbFilePath } else { $null }
                            if ([string]::IsNullOrWhiteSpace($edbPath)) {
                                [pscustomobject]@{ Server = [string]$db.Name; Status = 'Unknown'; Evidence = 'EdbFilePath not available; cannot evaluate storage isolation.' }
                            }
                            else {
                                $dbVol = & $getVolumeForPath -Path $edbPath -Vols $volumes
                                if ($null -eq $dbVol) {
                                    [pscustomobject]@{ Server = [string]$db.Name; Status = 'Unknown'; Evidence = ('EdbFilePath={0}: volume not found in inventory.' -f $edbPath) }
                                }
                                else {
                                    $dbVolDeviceId = [string]$dbVol.DeviceID
                                    $dbVolName = [string]$dbVol.Name
                                    $conflicts = @()
                                    if (-not [string]::IsNullOrWhiteSpace($osVolDeviceId) -and $dbVolDeviceId -eq $osVolDeviceId) {
                                        $conflicts += ('OS system volume ({0})' -f $osVolLabel)
                                    }
                                    if (-not [string]::IsNullOrWhiteSpace($exchVolDeviceId) -and $dbVolDeviceId -eq $exchVolDeviceId) {
                                        $conflicts += ('Exchange binaries volume ({0}, {1})' -f $exchVolLabel, $exchInstallPath)
                                    }
                                    if ($conflicts.Count -gt 0) {
                                        [pscustomobject]@{
                                            Server   = [string]$db.Name
                                            Status   = 'Fail'
                                            Evidence = ('EdbFilePath={0} shares volume {1} with: {2}.' -f $edbPath, $dbVolName, ($conflicts -join '; '))
                                        }
                                    }
                                    else {
                                        $caveats = @()
                                        if ([string]::IsNullOrWhiteSpace($osVolDeviceId)) { $caveats += 'OS volume could not be resolved' }
                                        if ([string]::IsNullOrWhiteSpace($exchVolDeviceId)) { $caveats += 'Exchange binaries volume could not be resolved' }
                                        $note = if ($caveats.Count -gt 0) { ' (caveat: {0})' -f ($caveats -join '; ') } else { '' }
                                        [pscustomobject]@{
                                            Server   = [string]$db.Name
                                            Status   = if ($caveats.Count -gt 0) { 'Unknown' } else { 'Pass' }
                                            Evidence = ('EdbFilePath={0} is on dedicated volume {1}, separate from OS and Exchange binaries{2}.' -f $edbPath, $dbVolName, $note)
                                        }
                                    }
                                }
                            }
                        })
                }
            }
            'EDCA-RES-009' {
                $databases = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'MailboxDatabases')) {
                    $databases = @($server.Exchange.MailboxDatabases)
                }
                if ($databases.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mailbox database data available for this server.'
                }
                else {
                    $dbServerResults = @($databases | ForEach-Object {
                            $db = $_
                            $mountAtStartup = ($db.PSObject.Properties.Name -contains 'MountAtStartup') -and ($null -ne $db.MountAtStartup) -and ([bool]$db.MountAtStartup)
                            $dbStatus = if ($mountAtStartup) { 'Pass' } else { 'Fail' }
                            $mountValue = if (($db.PSObject.Properties.Name -contains 'MountAtStartup') -and $null -ne $db.MountAtStartup) { [string]$db.MountAtStartup } else { 'N/A' }
                            $dbEvidence = if ($dbStatus -eq 'Pass') {
                                'MountAtStartup=True — compliant.'
                            }
                            else {
                                ('MountAtStartup={0} — non-compliant (expected True).' -f $mountValue)
                            }
                            [pscustomobject]@{ Server = [string]$db.Name; Status = $dbStatus; Evidence = $dbEvidence }
                        })
                }
            }
            'EDCA-SEC-034' {
                $agents = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'TransportAgents')) {
                    $agents = @($server.Exchange.TransportAgents)
                }
                if ($agents.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Transport agent data unavailable on this server.'
                }
                else {
                    # Build a map of agent name -> config-level Enabled state from whichever
                    # data source is available.  Edge servers store these in EdgeData; Mailbox
                    # servers populate AntiSpamConfigs when the agents are installed.
                    $configEnabled = @{}
                    $edgeData = $null
                    if ($null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'EdgeData')) {
                        $edgeData = $server.Exchange.EdgeData
                    }
                    if ($null -ne $edgeData) {
                        if (($edgeData.PSObject.Properties.Name -contains 'ContentFilterConfig') -and $null -ne $edgeData.ContentFilterConfig) { $configEnabled['Content Filter Agent'] = [bool]$edgeData.ContentFilterConfig.Enabled }
                        if (($edgeData.PSObject.Properties.Name -contains 'SenderFilterConfig') -and $null -ne $edgeData.SenderFilterConfig) { $configEnabled['Sender Filter Agent'] = [bool]$edgeData.SenderFilterConfig.Enabled }
                        if (($edgeData.PSObject.Properties.Name -contains 'SenderIdConfig') -and $null -ne $edgeData.SenderIdConfig) { $configEnabled['Sender Id Agent'] = [bool]$edgeData.SenderIdConfig.Enabled }
                        if (($edgeData.PSObject.Properties.Name -contains 'SenderReputationConfig') -and $null -ne $edgeData.SenderReputationConfig) { $configEnabled['Protocol Analysis Agent'] = [bool]$edgeData.SenderReputationConfig.Enabled }
                    }
                    else {
                        $antiSpam = $null
                        if ($null -ne $server.Exchange -and ($server.Exchange.PSObject.Properties.Name -contains 'AntiSpamConfigs')) {
                            $antiSpam = $server.Exchange.AntiSpamConfigs
                        }
                        if ($null -ne $antiSpam) {
                            if (($antiSpam.PSObject.Properties.Name -contains 'ContentFilter') -and $null -ne $antiSpam.ContentFilter) { $configEnabled['Content Filter Agent'] = [bool]$antiSpam.ContentFilter.Enabled }
                            if (($antiSpam.PSObject.Properties.Name -contains 'SenderFilter') -and $null -ne $antiSpam.SenderFilter) { $configEnabled['Sender Filter Agent'] = [bool]$antiSpam.SenderFilter.Enabled }
                            if (($antiSpam.PSObject.Properties.Name -contains 'SenderIdConfig') -and $null -ne $antiSpam.SenderIdConfig) { $configEnabled['Sender Id Agent'] = [bool]$antiSpam.SenderIdConfig.Enabled }
                            if (($antiSpam.PSObject.Properties.Name -contains 'SenderReputation') -and $null -ne $antiSpam.SenderReputation) { $configEnabled['Protocol Analysis Agent'] = [bool]$antiSpam.SenderReputation.Enabled }
                        }
                    }

                    # Agent name  ->  managed via
                    # Content Filter Agent   Get-/Set-ContentFilterConfig
                    # Sender Filter Agent    Get-/Set-SenderFilterConfig
                    # Sender Id Agent        Get-/Set-SenderIdConfig
                    # Protocol Analysis Agent Get-/Set-SenderReputationConfig
                    $required = @('Content Filter Agent', 'Sender Filter Agent', 'Sender Id Agent', 'Protocol Analysis Agent')
                    $missing = @()
                    $disabled = @()
                    $configDisabled = @()
                    foreach ($agentName in $required) {
                        $found = @($agents | Where-Object { [string]$_.Identity -eq $agentName })
                        if ($found.Count -eq 0) {
                            $missing += $agentName
                        }
                        elseif (-not [bool]$found[0].Enabled) {
                            $disabled += $agentName
                        }
                        elseif ($configEnabled.ContainsKey($agentName) -and -not $configEnabled[$agentName]) {
                            $configDisabled += $agentName
                        }
                    }
                    if ($missing.Count -gt 0 -or $disabled.Count -gt 0 -or $configDisabled.Count -gt 0) {
                        $status = 'Fail'
                        $issues = @()
                        if ($missing.Count -gt 0) { $issues += ('Missing agents: {0}' -f ($missing -join ', ')) }
                        if ($disabled.Count -gt 0) { $issues += ('Disabled agents (transport layer): {0}' -f ($disabled -join ', ')) }
                        if ($configDisabled.Count -gt 0) { $issues += ('Filtering disabled in config: {0}' -f ($configDisabled -join ', ')) }
                        $evidence = Format-EDCAEvidenceWithElements -Summary 'One or more required anti-spam transport agents are missing, disabled, or have filtering disabled at the configuration level.' -Elements $issues
                    }
                    else {
                        $status = 'Pass'
                        $evidence = 'All required anti-spam agents (Content Filter, Sender Filter, Sender ID, Protocol Analysis) are present, enabled, and configured.'
                    }
                }
            }
            'EDCA-TLS-020' {
                $connectors = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'ReceiveConnectors')) {
                    $connectors = @($server.Exchange.ReceiveConnectors)
                }
                if ($connectors.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No receive connector data available for this server.'
                }
                else {
                    $nonCompliant = @($connectors | Where-Object {
                            $ts = if ($_.PSObject.Properties.Name -contains 'ConnectionTimeout') { [string]$_.ConnectionTimeout } else { $null }
                            if ([string]::IsNullOrWhiteSpace($ts)) { $false }
                            else { $parsed = $null; try { $parsed = [timespan]$ts } catch {}; ($null -ne $parsed) -and ($parsed.TotalMinutes -gt 5) }
                        })
                    $unknown = @($connectors | Where-Object {
                            -not ($_.PSObject.Properties.Name -contains 'ConnectionTimeout') -or [string]::IsNullOrWhiteSpace([string]$_.ConnectionTimeout)
                        })
                    if ($nonCompliant.Count -gt 0) {
                        $status = 'Fail'
                        $details = @($nonCompliant | ForEach-Object { ('{0}: ConnectionTimeout={1} (must be ≤ 00:05:00)' -f [string]$_.Identity, [string]$_.ConnectionTimeout) })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} receive connector(s) have ConnectionTimeout exceeding 5 minutes.' -f $nonCompliant.Count, $connectors.Count) -Elements $details
                    }
                    elseif ($unknown.Count -gt 0) {
                        $status = 'Unknown'
                        $evidence = ('ConnectionTimeout data unavailable for {0} of {1} receive connector(s).' -f $unknown.Count, $connectors.Count)
                    }
                    else {
                        $status = 'Pass'
                        $evidence = ('All {0} receive connector(s) have ConnectionTimeout set to 5 minutes or less.' -f $connectors.Count)
                    }
                }
            }
            'EDCA-RES-010' {
                $databases = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'MailboxDatabases')) {
                    $databases = @($server.Exchange.MailboxDatabases)
                }
                if ($databases.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mailbox database data available for this server.'
                }
                else {
                    $dbServerResults = @($databases | ForEach-Object {
                            $db = $_
                            $hasEnoughCopies = ($db.PSObject.Properties.Name -contains 'DatabaseCopiesCount') -and ($null -ne $db.DatabaseCopiesCount) -and ([int]$db.DatabaseCopiesCount -ge 2)
                            $dbStatus = if ($hasEnoughCopies) { 'Pass' } else { 'Fail' }
                            $copiesValue = if (($db.PSObject.Properties.Name -contains 'DatabaseCopiesCount') -and $null -ne $db.DatabaseCopiesCount) { [string]$db.DatabaseCopiesCount } else { 'N/A' }
                            $dbEvidence = if ($dbStatus -eq 'Pass') {
                                ('DatabaseCopiesCount={0} — compliant (>= 2 copies).' -f $copiesValue)
                            }
                            else {
                                ('DatabaseCopiesCount={0} — non-compliant (expected >= 2 copies for high availability).' -f $copiesValue)
                            }
                            [pscustomobject]@{ Server = [string]$db.Name; Status = $dbStatus; Evidence = $dbEvidence }
                        })
                }
            }
            'EDCA-TLS-021' {
                $connectors = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'ReceiveConnectors')) {
                    $connectors = @($server.Exchange.ReceiveConnectors)
                }
                $internalConnectors = @($connectors | Where-Object {
                        $role = if ($_.PSObject.Properties.Name -contains 'TransportRole') { [string]$_.TransportRole } else { '' }
                        $role -ne 'FrontendTransport'
                    })
                if ($internalConnectors.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No internal (non-FrontendTransport) receive connectors found on this server.'
                }
                else {
                    $nonCompliant = @($internalConnectors | Where-Object { -not ($_.PSObject.Properties.Name -contains 'RequireTLS') -or $null -eq $_.RequireTLS -or -not [bool]$_.RequireTLS })
                    if ($nonCompliant.Count -gt 0) {
                        $status = 'Fail'
                        $details = @($nonCompliant | ForEach-Object { ('{0}: RequireTLS=False (expected True)' -f [string]$_.Identity) })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} internal receive connector(s) do not require TLS.' -f $nonCompliant.Count, $internalConnectors.Count) -Elements $details
                    }
                    else {
                        $status = 'Pass'
                        $evidence = ('All {0} internal receive connector(s) require TLS.' -f $internalConnectors.Count)
                    }
                }
            }
            'EDCA-TLS-022' {
                $connectors = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'ReceiveConnectors')) {
                    $connectors = @($server.Exchange.ReceiveConnectors)
                }
                if ($connectors.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No receive connector data available for this server.'
                }
                else {
                    $nonCompliant = @($connectors | Where-Object {
                            $val = if ($_.PSObject.Properties.Name -contains 'MaxRecipientsPerMessage') { [string]$_.MaxRecipientsPerMessage } else { $null }
                            [string]::IsNullOrWhiteSpace($val) -or $val -eq 'Unlimited' -or ($val -match '^\d+$' -and [int]$val -eq 0)
                        })
                    if ($nonCompliant.Count -gt 0) {
                        $status = 'Fail'
                        $details = @($nonCompliant | ForEach-Object { ('{0}: MaxRecipientsPerMessage={1} (must not be Unlimited or 0)' -f [string]$_.Identity, $(if ($_.PSObject.Properties.Name -contains 'MaxRecipientsPerMessage') { [string]$_.MaxRecipientsPerMessage } else { 'N/A' })) })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} receive connector(s) have MaxRecipientsPerMessage set to Unlimited or 0.' -f $nonCompliant.Count, $connectors.Count) -Elements $details
                    }
                    else {
                        $status = 'Pass'
                        $evidence = ('All {0} receive connector(s) have MaxRecipientsPerMessage set to a specific limit.' -f $connectors.Count)
                    }
                }
            }
            'EDCA-SEC-039' {
                $agents = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'TransportAgents')) {
                    $agents = @($server.Exchange.TransportAgents)
                }
                if ($agents.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Transport agent data unavailable on this server.'
                }
                else {
                    $malwareAgent = @($agents | Where-Object { [string]$_.Identity -eq 'Malware Agent' }) | Select-Object -First 1
                    if ($null -eq $malwareAgent) {
                        $status = 'Unknown'
                        $evidence = 'Malware Agent not found in the transport agent list; third-party scanning software may be in use or the agent may not be installed.'
                    }
                    elseif ([bool]$malwareAgent.Enabled) {
                        $status = 'Pass'
                        $evidence = 'Compliant — Malware Agent is present and enabled.'
                    }
                    else {
                        $status = 'Fail'
                        $evidence = 'Malware Agent is present but disabled. Enable it with Enable-TransportAgent -Identity ''Malware Agent'' or run Enable-AntimalwareScanning.ps1.'
                    }
                }
            }
            'EDCA-MON-012' {
                $levels = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'EventLogLevels')) {
                    $levels = @($server.Exchange.EventLogLevels)
                }
                if ($levels.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Event log level data unavailable on this server.'
                }
                else {
                    $nonCompliant = @($levels | Where-Object { ($_.PSObject.Properties.Name -contains 'EventLevel') -and [string]$_.EventLevel -ne 'Lowest' })
                    if ($nonCompliant.Count -gt 0) {
                        $status = 'Fail'
                        $details = @($nonCompliant | ForEach-Object { ('{0}: EventLevel={1} (expected Lowest)' -f [string]$_.Identity, [string]$_.EventLevel) })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} Exchange event log categor(ies) are not set to Lowest.' -f $nonCompliant.Count, $levels.Count) -Elements $details
                    }
                    else {
                        $status = 'Pass'
                        $evidence = ('All {0} Exchange event log categories are set to Lowest.' -f $levels.Count)
                    }
                }
            }
            'EDCA-DATA-017' {
                $databaseStoragePaths = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'DatabaseStoragePaths')) {
                    $databaseStoragePaths = @($server.Exchange.DatabaseStoragePaths)
                }
                if ($databaseStoragePaths.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mailbox database or log storage paths found (may not be a mailbox server role).'
                }
                else {
                    $volumes = @()
                    if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and
                        ($server.OS.PSObject.Properties.Name -contains 'Volumes')) {
                        $volumes = @($server.OS.Volumes | Where-Object {
                                ($_.PSObject.Properties.Name -contains 'DeviceID') -and
                                -not [string]::IsNullOrWhiteSpace([string]$_.DeviceID) -and
                                ($_.PSObject.Properties.Name -contains 'Name') -and
                                -not [string]::IsNullOrWhiteSpace([string]$_.Name)
                            })
                    }
                    $getVolumeForPath = {
                        param([string]$Path, [object[]]$Vols)
                        $normPath = $Path.TrimEnd('\') + '\'
                        $bestMatch = $null
                        $bestLen = -1
                        foreach ($vol in $Vols) {
                            $mountPath = ([string]$vol.Name).TrimEnd('\') + '\'
                            if ($normPath.StartsWith($mountPath, [System.StringComparison]::OrdinalIgnoreCase) -and $mountPath.Length -gt $bestLen) {
                                $bestMatch = $vol
                                $bestLen = $mountPath.Length
                            }
                        }
                        return $bestMatch
                    }
                    $seenDeviceIds = @{}
                    $matchedVolumeInfos = @()
                    foreach ($storagePath in $databaseStoragePaths) {
                        $vol = & $getVolumeForPath -Path ([string]$storagePath) -Vols $volumes
                        if ($null -eq $vol) {
                            $key = [string]$storagePath
                            if (-not $seenDeviceIds.ContainsKey($key)) {
                                $seenDeviceIds[$key] = $true
                                $matchedVolumeInfos += [pscustomobject]@{ Path = [string]$storagePath; Vol = $null }
                            }
                        }
                        else {
                            $devId = [string]$vol.DeviceID
                            if (-not $seenDeviceIds.ContainsKey($devId)) {
                                $seenDeviceIds[$devId] = $true
                                $matchedVolumeInfos += [pscustomobject]@{ Path = [string]$vol.Name; Vol = $vol }
                            }
                        }
                    }
                    $notProtected = @()
                    $unmapped = @()
                    foreach ($info in $matchedVolumeInfos) {
                        if ($null -eq $info.Vol) { $unmapped += $info.Path; continue }
                        if (-not [bool]$info.Vol.BitLockerProtected) { $notProtected += $info.Path }
                    }
                    $totalVols = $matchedVolumeInfos.Count
                    if ($matchedVolumeInfos.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = ('Could not resolve storage paths to volumes: {0}' -f ($databaseStoragePaths -join ', '))
                    }
                    elseif ($notProtected.Count -gt 0) {
                        $status = 'Fail'
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} database or log volume(s) are not BitLocker-protected.' -f $notProtected.Count, $totalVols) -Elements $notProtected
                    }
                    elseif ($unmapped.Count -gt 0) {
                        $status = 'Unknown'
                        $evidence = ('Could not map the following path(s) to volume metadata: {0}' -f ($unmapped -join ', '))
                    }
                    else {
                        $volPaths = @($matchedVolumeInfos | ForEach-Object { $_.Path })
                        $status = 'Pass'
                        $evidence = ('All database and log volumes are BitLocker-protected: {0}' -f ($volPaths -join ', '))
                    }
                }
            }
            'EDCA-DATA-018' {
                $cipherSuiteOrder = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and
                    ($server.OS.PSObject.Properties.Name -contains 'TlsHardening') -and $null -ne $server.OS.TlsHardening -and
                    ($server.OS.TlsHardening.PSObject.Properties.Name -contains 'CipherSuiteOrder')) {
                    $cipherSuiteOrder = $server.OS.TlsHardening.CipherSuiteOrder
                }
                if ($null -eq $cipherSuiteOrder) {
                    $status = 'Unknown'
                    $evidence = 'Cipher suite order data unavailable (Get-TlsCipherSuite not supported on this OS).'
                }
                elseif ($cipherSuiteOrder.QuerySucceeded -ne $true) {
                    $status = 'Unknown'
                    $evidence = ('Cipher suite order query failed: {0}' -f [string]$cipherSuiteOrder.Error)
                }
                else {
                    $nonPfs = @($cipherSuiteOrder.NonPfsSuites)
                    $dheFirst = @($cipherSuiteOrder.DheBeforeEcdhe)
                    $total = @($cipherSuiteOrder.Tls12Suites).Count
                    if ($nonPfs.Count -gt 0) {
                        $status = 'Fail'
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} active TLS 1.2 cipher suite(s) lack forward secrecy (no ECDHE/DHE key exchange).' -f $nonPfs.Count, $total) -Elements $nonPfs
                    }
                    elseif ($dheFirst.Count -gt 0) {
                        $status = 'Fail'
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} DHE cipher suite(s) appear before the first ECDHE suite; ECDHE suites must be prioritised over DHE.' -f $dheFirst.Count) -Elements $dheFirst
                    }
                    else {
                        $status = 'Pass'
                        $evidence = ('All {0} active TLS 1.2 cipher suites provide forward secrecy and ECDHE suites are prioritised over DHE suites.' -f $total)
                    }
                }
            }
            'EDCA-SEC-040' {
                $databaseStoragePaths = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'DatabaseStoragePaths')) {
                    $databaseStoragePaths = @($server.Exchange.DatabaseStoragePaths)
                }
                if ($databaseStoragePaths.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mailbox database or log storage paths found (may not be a mailbox server role).'
                }
                else {
                    $volumes = @()
                    if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and
                        ($server.OS.PSObject.Properties.Name -contains 'Volumes')) {
                        $volumes = @($server.OS.Volumes | Where-Object {
                                ($_.PSObject.Properties.Name -contains 'DeviceID') -and
                                -not [string]::IsNullOrWhiteSpace([string]$_.DeviceID) -and
                                ($_.PSObject.Properties.Name -contains 'Name') -and
                                -not [string]::IsNullOrWhiteSpace([string]$_.Name)
                            })
                    }
                    $getVolumeForPath = {
                        param([string]$Path, [object[]]$Vols)
                        $normPath = $Path.TrimEnd('\') + '\'
                        $bestMatch = $null
                        $bestLen = -1
                        foreach ($vol in $Vols) {
                            $mountPath = ([string]$vol.Name).TrimEnd('\') + '\'
                            if ($normPath.StartsWith($mountPath, [System.StringComparison]::OrdinalIgnoreCase) -and $mountPath.Length -gt $bestLen) {
                                $bestMatch = $vol
                                $bestLen = $mountPath.Length
                            }
                        }
                        return $bestMatch
                    }
                    $seenDeviceIds = @{}
                    $matchedVolumeInfos = @()
                    foreach ($storagePath in $databaseStoragePaths) {
                        $vol = & $getVolumeForPath -Path ([string]$storagePath) -Vols $volumes
                        if ($null -eq $vol) {
                            $key = [string]$storagePath
                            if (-not $seenDeviceIds.ContainsKey($key)) {
                                $seenDeviceIds[$key] = $true
                                $matchedVolumeInfos += [pscustomobject]@{ Path = [string]$storagePath; Vol = $null }
                            }
                        }
                        else {
                            $devId = [string]$vol.DeviceID
                            if (-not $seenDeviceIds.ContainsKey($devId)) {
                                $seenDeviceIds[$devId] = $true
                                $matchedVolumeInfos += [pscustomobject]@{ Path = [string]$vol.Name; Vol = $vol }
                            }
                        }
                    }
                    $notReFS = @()
                    $unmapped = @()
                    foreach ($info in $matchedVolumeInfos) {
                        if ($null -eq $info.Vol) { $unmapped += $info.Path; continue }
                        if ([string]$info.Vol.FileSystem -ne 'ReFS') { $notReFS += ('{0}: {1}' -f $info.Path, [string]$info.Vol.FileSystem) }
                    }
                    $totalVols = $matchedVolumeInfos.Count
                    if ($matchedVolumeInfos.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = ('Could not resolve storage paths to volumes: {0}' -f ($databaseStoragePaths -join ', '))
                    }
                    elseif ($notReFS.Count -gt 0) {
                        $status = 'Fail'
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} database or log volume(s) are not formatted with ReFS.' -f $notReFS.Count, $totalVols) -Elements $notReFS
                    }
                    elseif ($unmapped.Count -gt 0) {
                        $status = 'Unknown'
                        $evidence = ('Could not map the following path(s) to volume metadata: {0}' -f ($unmapped -join ', '))
                    }
                    else {
                        $volPaths = @($matchedVolumeInfos | ForEach-Object { $_.Path })
                        $status = 'Pass'
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('All {0} database and log volume(s) are formatted with ReFS.' -f $volPaths.Count) -Elements $volPaths
                    }
                }
            }
            'EDCA-MON-009' {
                $bp = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'TransportBackPressure')) {
                    $bp = $server.Exchange.TransportBackPressure
                }

                if ($null -eq $bp) {
                    $status = 'Unknown'
                    $evidence = 'Transport back pressure configuration data unavailable.'
                }
                elseif ($bp.ConfigPresent -eq $false) {
                    $status = 'Fail'
                    $evidence = 'EdgeTransport.exe.config is missing — back pressure cannot be configured.'
                }
                elseif ($null -eq $bp.ConfigPresent) {
                    $status = 'Unknown'
                    $evidence = 'EdgeTransport.exe.config could not be parsed — back pressure configuration unverified.'
                }
                else {
                    $normalVal = if (-not [string]::IsNullOrWhiteSpace([string]$bp.NormalPriorityMessageExpirationTimeout)) { [string]$bp.NormalPriorityMessageExpirationTimeout }   else { '2.00:00:00 (default)' }
                    $criticalVal = if (-not [string]::IsNullOrWhiteSpace([string]$bp.CriticalPriorityMessageExpirationTimeout)) { [string]$bp.CriticalPriorityMessageExpirationTimeout } else { '0.04:00:00 (default)' }
                    $status = 'Pass'
                    $evidence = ('Back pressure active (EdgeTransport.exe.config present). Queue growth is disk-bounded via back pressure, not message-count-bounded. Message expiration is time-bounded by priority.' + "`n" +
                        ('  NormalPriorityMessageExpirationTimeout  : {0}' -f $normalVal) + "`n" +
                        ('  CriticalPriorityMessageExpirationTimeout: {0}' -f $criticalVal))
                }
            }
            'EDCA-MON-010' {
                $auditAcl = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'AuditLogPathAcl')) {
                    $auditAcl = @($server.Exchange.AuditLogPathAcl)
                }
                $auditPath129 = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'AuditLogPath') -and
                    -not [string]::IsNullOrWhiteSpace([string]$server.Exchange.AuditLogPath)) {
                    $auditPath129 = [string]$server.Exchange.AuditLogPath
                }
                if ([string]::IsNullOrWhiteSpace($auditPath129) -and
                    ($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'InstallPath') -and
                    -not [string]::IsNullOrWhiteSpace([string]$server.Exchange.InstallPath)) {
                    $auditPath129 = ([string]$server.Exchange.InstallPath).TrimEnd('\') + '\Logging'
                }
                if ($auditAcl.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = if ($null -eq $auditPath129) {
                        'AuditLogPath not available; cannot evaluate audit log directory ACL.'
                    }
                    else {
                        ('AuditLogPathAcl data not available for {0}; cannot evaluate directory ACL.' -f $auditPath129)
                    }
                }
                else {
                    $safePrincipalNames = @('SYSTEM', 'Administrators', 'Exchange Trusted Subsystem', 'TrustedInstaller', 'CREATOR OWNER', 'NETWORK SERVICE', 'Exchange Windows Permissions')
                    $badAces = @($auditAcl | Where-Object {
                            $ace = $_
                            if ([string]$ace.AccessControlType -ne 'Allow') { return $false }
                            if ([bool]$ace.IsInherited) { return $false }
                            $identity = [string]$ace.IdentityReference
                            $isSafe = $false
                            foreach ($safeName in $safePrincipalNames) {
                                if ($identity -like "*\$safeName" -or $identity -ieq $safeName -or
                                    $identity.EndsWith($safeName, [System.StringComparison]::OrdinalIgnoreCase)) {
                                    $isSafe = $true; break
                                }
                            }
                            if ($isSafe) { return $false }
                            $rightsStr = [string]$ace.FileSystemRights
                            return ($rightsStr -match '\bFullControl\b|\bModify\b|\bWrite|\bTakeOwnership\b|\bChangePermissions\b|\bDelete\b')
                        })
                    if ($badAces.Count -gt 0) {
                        $aceList = @($badAces | ForEach-Object { ('{0} ({1})' -f [string]$_.IdentityReference, [string]$_.FileSystemRights) })
                        $pathDesc = if ($null -ne $auditPath129) { ('on {0}' -f $auditPath129) } else { '' }
                        $status = 'Fail'
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} non-inherited Allow ACE(s) {1} grant write-capable permissions to non-standard principals.' -f $badAces.Count, $pathDesc) -Elements $aceList
                    }
                    else {
                        $pathDesc129 = if ($null -ne $auditPath129) { (' ({0})' -f $auditPath129) } else { '' }
                        $status = 'Pass'
                        $evidence = ('Audit log directory{0} ACL contains only standard principals with appropriate permissions.' -f $pathDesc129)
                    }
                }
            }
            'EDCA-MON-011' {
                $auditPath = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'AuditLogPath') -and
                    -not [string]::IsNullOrWhiteSpace([string]$server.Exchange.AuditLogPath)) {
                    $auditPath = [string]$server.Exchange.AuditLogPath
                }
                if ([string]::IsNullOrWhiteSpace($auditPath) -and
                    ($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'InstallPath') -and
                    -not [string]::IsNullOrWhiteSpace([string]$server.Exchange.InstallPath)) {
                    $auditPath = ([string]$server.Exchange.InstallPath).TrimEnd('\') + '\Logging'
                }
                $volumes = @()
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and
                    ($server.OS.PSObject.Properties.Name -contains 'Volumes')) {
                    $volumes = @($server.OS.Volumes | Where-Object {
                            ($_.PSObject.Properties.Name -contains 'DeviceID') -and
                            -not [string]::IsNullOrWhiteSpace([string]$_.DeviceID) -and
                            ($_.PSObject.Properties.Name -contains 'Name') -and
                            -not [string]::IsNullOrWhiteSpace([string]$_.Name)
                        })
                }
                if ([string]::IsNullOrWhiteSpace($auditPath)) {
                    $status = 'Unknown'
                    $evidence = 'AuditLogPath not available; cannot evaluate storage isolation.'
                }
                elseif ($volumes.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Volume inventory not available; cannot evaluate storage isolation.'
                }
                else {
                    $getVolumeForPath = {
                        param([string]$Path, [object[]]$Vols)
                        $normPath = $Path.TrimEnd('\') + '\'
                        $bestMatch = $null
                        $bestLen = -1
                        foreach ($vol in $Vols) {
                            $mountPath = ([string]$vol.Name).TrimEnd('\') + '\'
                            if ($normPath.StartsWith($mountPath, [System.StringComparison]::OrdinalIgnoreCase) -and $mountPath.Length -gt $bestLen) {
                                $bestMatch = $vol
                                $bestLen = $mountPath.Length
                            }
                        }
                        return $bestMatch
                    }
                    $auditVol = & $getVolumeForPath -Path $auditPath -Vols $volumes
                    if ($null -eq $auditVol) {
                        $status = 'Unknown'
                        $evidence = ('AuditLogPath={0}: volume not found in volume inventory.' -f $auditPath)
                    }
                    else {
                        $auditVolDeviceId = [string]$auditVol.DeviceID
                        $auditVolName = [string]$auditVol.Name
                        $osVolDeviceId = $null
                        $osVolLabel = $null
                        if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and
                            ($server.OS.PSObject.Properties.Name -contains 'SystemDrive') -and
                            -not [string]::IsNullOrWhiteSpace([string]$server.OS.SystemDrive)) {
                            $osVol = & $getVolumeForPath -Path ([string]$server.OS.SystemDrive) -Vols $volumes
                            if ($null -ne $osVol) {
                                $osVolDeviceId = [string]$osVol.DeviceID
                                $osVolLabel = [string]$osVol.Name
                            }
                        }
                        $exchVolDeviceId = $null
                        $exchVolLabel = $null
                        $exchInstallPath130 = $null
                        if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                            ($server.Exchange.PSObject.Properties.Name -contains 'InstallPath') -and
                            -not [string]::IsNullOrWhiteSpace([string]$server.Exchange.InstallPath)) {
                            $exchInstallPath130 = [string]$server.Exchange.InstallPath
                            $exchVol = & $getVolumeForPath -Path $exchInstallPath130 -Vols $volumes
                            if ($null -ne $exchVol) {
                                $exchVolDeviceId = [string]$exchVol.DeviceID
                                $exchVolLabel = [string]$exchVol.Name
                            }
                        }
                        $conflicts = @()
                        if (-not [string]::IsNullOrWhiteSpace($osVolDeviceId) -and $auditVolDeviceId -eq $osVolDeviceId) {
                            $conflicts += ('OS system volume ({0})' -f $osVolLabel)
                        }
                        if (-not [string]::IsNullOrWhiteSpace($exchVolDeviceId) -and $auditVolDeviceId -eq $exchVolDeviceId) {
                            $conflicts += ('Exchange binaries volume ({0}, {1})' -f $exchVolLabel, $exchInstallPath130)
                        }
                        if ($conflicts.Count -gt 0) {
                            $status = 'Fail'
                            $evidence = ('AuditLogPath={0} shares volume {1} with: {2}.' -f $auditPath, $auditVolName, ($conflicts -join '; '))
                        }
                        else {
                            $caveats = @()
                            if ([string]::IsNullOrWhiteSpace($osVolDeviceId)) { $caveats += 'OS volume could not be resolved' }
                            if ([string]::IsNullOrWhiteSpace($exchVolDeviceId)) { $caveats += 'Exchange binaries volume could not be resolved' }
                            $note = if ($caveats.Count -gt 0) { (' (caveat: {0})' -f ($caveats -join '; ')) } else { '' }
                            $status = if ($caveats.Count -gt 0) { 'Unknown' } else { 'Pass' }
                            $evidence = ('AuditLogPath={0} is on dedicated volume {1}, separate from OS and Exchange binaries{2}.' -f $auditPath, $auditVolName, $note)
                        }
                    }
                }
            }
            'EDCA-GOV-010' {
                $databases = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'MailboxDatabases')) {
                    $databases = @($server.Exchange.MailboxDatabases)
                }
                if ($databases.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No mailbox database data available for this server.'
                }
                else {
                    $dbServerResults = @($databases | ForEach-Object {
                            $db = $_
                            $psrqUnlimited = $null
                            $psqUnlimited = $null
                            if (($db.PSObject.Properties.Name -contains 'ProhibitSendReceiveQuotaIsUnlimited') -and $null -ne $db.ProhibitSendReceiveQuotaIsUnlimited) {
                                $psrqUnlimited = [bool]$db.ProhibitSendReceiveQuotaIsUnlimited
                            }
                            if (($db.PSObject.Properties.Name -contains 'ProhibitSendQuotaIsUnlimited') -and $null -ne $db.ProhibitSendQuotaIsUnlimited) {
                                $psqUnlimited = [bool]$db.ProhibitSendQuotaIsUnlimited
                            }
                            if ($null -eq $psrqUnlimited -and $null -eq $psqUnlimited) {
                                [pscustomobject]@{ Server = [string]$db.Name; Status = 'Unknown'; Evidence = 'Quota data not available for this database.' }
                            }
                            else {
                                $failReasons = @()
                                if ($psrqUnlimited -eq $true) { $failReasons += 'ProhibitSendReceiveQuota=Unlimited' }
                                if ($psqUnlimited -eq $true) { $failReasons += 'ProhibitSendQuota=Unlimited' }
                                if ($failReasons.Count -gt 0) {
                                    [pscustomobject]@{
                                        Server   = [string]$db.Name
                                        Status   = 'Fail'
                                        Evidence = ('{0} — unrestricted quota allows unlimited mailbox growth and does not protect mail-flow availability.' -f ($failReasons -join ', '))
                                    }
                                }
                                else {
                                    [pscustomobject]@{
                                        Server   = [string]$db.Name
                                        Status   = 'Pass'
                                        Evidence = 'Send and receive quotas are configured (not Unlimited).'
                                    }
                                }
                            }
                        })
                }
            }
            'EDCA-SEC-035' {
                $installAcl = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'InstallPathAcl')) {
                    $installAcl = @($server.Exchange.InstallPathAcl)
                }
                $installPath143 = $null
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'InstallPath') -and
                    -not [string]::IsNullOrWhiteSpace([string]$server.Exchange.InstallPath)) {
                    $installPath143 = [string]$server.Exchange.InstallPath
                }
                if ($installAcl.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'InstallPathAcl data not available; cannot evaluate directory ACL.'
                }
                else {
                    $safePrincipalNames = @('SYSTEM', 'Administrators', 'Exchange Trusted Subsystem', 'TrustedInstaller', 'CREATOR OWNER', 'NETWORK SERVICE')
                    $badAces = @($installAcl | Where-Object {
                            $ace = $_
                            if ([string]$ace.AccessControlType -ne 'Allow') { return $false }
                            if ([bool]$ace.IsInherited) { return $false }
                            $identity = [string]$ace.IdentityReference
                            $isSafe = $false
                            foreach ($safeName in $safePrincipalNames) {
                                if ($identity -like "*\$safeName" -or $identity -ieq $safeName -or
                                    $identity.EndsWith($safeName, [System.StringComparison]::OrdinalIgnoreCase)) {
                                    $isSafe = $true; break
                                }
                            }
                            if ($isSafe) { return $false }
                            $rightsStr = [string]$ace.FileSystemRights
                            return ($rightsStr -match '\bFullControl\b|\bModify\b|\bWrite|\bTakeOwnership\b|\bChangePermissions\b|\bDelete\b')
                        })
                    if ($badAces.Count -gt 0) {
                        $aceList = @($badAces | ForEach-Object { ('{0} ({1})' -f [string]$_.IdentityReference, [string]$_.FileSystemRights) })
                        $pathDesc = if ($null -ne $installPath143) { ('on {0}' -f $installPath143) } else { '' }
                        $status = 'Fail'
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} non-inherited Allow ACE(s) {1} grant write-capable permissions to non-standard principals.' -f $badAces.Count, $pathDesc) -Elements $aceList
                    }
                    else {
                        $pathDesc143 = if ($null -ne $installPath143) { (' ({0})' -f $installPath143) } else { '' }
                        $status = 'Pass'
                        $evidence = ('Exchange install directory{0} ACL contains only standard principals with appropriate permissions.' -f $pathDesc143)
                    }
                }
            }
            'EDCA-GOV-012' {
                $services = @()
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'ExchangeServices')) {
                    $services = @($server.Exchange.ExchangeServices)
                }
                if ($services.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'ExchangeServices data not available; cannot evaluate service state.'
                }
                else {
                    $targetServices = @('MSExchangePOP3', 'MSExchangeIMAP4', 'MSExchangeUM')
                    $failItems = @()
                    $passItems = @()
                    $missingItems = @()
                    foreach ($svcName in $targetServices) {
                        $svc = @($services | Where-Object { [string]$_.Name -ieq $svcName }) | Select-Object -First 1
                        if ($null -eq $svc) {
                            if ($svcName -ne 'MSExchangeUM') {
                                $missingItems += ('{0}: not found in service list' -f $svcName)
                            }
                        }
                        else {
                            $startType = [string]$svc.StartType
                            $svcStatus = [string]$svc.Status
                            $isDisabled = ($startType -ieq 'Disabled')
                            $isRunning = ($svcStatus -ieq 'Running')
                            if (-not $isDisabled -or $isRunning) {
                                $failItems += ('{0}: StartType={1}, Status={2} — must be Disabled and not Running' -f $svcName, $startType, $svcStatus)
                            }
                            else {
                                $passItems += ('{0}: StartType={1}, Status={2}' -f $svcName, $startType, $svcStatus)
                            }
                        }
                    }
                    if ($failItems.Count -gt 0) {
                        $status = 'Fail'
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} unnecessary service(s) are not disabled.' -f $failItems.Count) -Elements $failItems
                    }
                    elseif ($missingItems.Count -gt 0 -and $passItems.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = Format-EDCAEvidenceWithElements -Summary 'Could not verify service state for expected services.' -Elements $missingItems
                    }
                    else {
                        $allItems = @($passItems) + @($missingItems)
                        $status = 'Pass'
                        $evidence = Format-EDCAEvidenceWithElements -Summary 'POP3, IMAP4 and UM services are disabled or not present.' -Elements $allItems
                    }
                }
            }
            'EDCA-SEC-041' {
                $cisPolicy = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and
                    ($server.OS.PSObject.Properties.Name -contains 'CisPolicy')) {
                    $cisPolicy = $server.OS.CisPolicy
                }

                if ($null -eq $cisPolicy) {
                    $status = 'Unknown'
                    $evidence = 'OS security policy data unavailable.'
                }
                else {
                    $legacyEnabled = $null
                    $windowsBackupDir = $null
                    if ($cisPolicy.PSObject.Properties.Name -contains 'LapsLegacyEnabled') {
                        $legacyEnabled = $cisPolicy.LapsLegacyEnabled
                    }
                    if ($cisPolicy.PSObject.Properties.Name -contains 'LapsWindowsBackupDirectory') {
                        $windowsBackupDir = $cisPolicy.LapsWindowsBackupDirectory
                    }

                    if ($null -eq $legacyEnabled -and $null -eq $windowsBackupDir) {
                        $status = 'Unknown'
                        $evidence = 'LAPS registry policy keys not found — re-run collection with the current EDCA build to evaluate this control.'
                    }
                    elseif ($legacyEnabled -eq $true) {
                        $status = 'Pass'
                        $evidence = 'Legacy LAPS (AdmPwd) is enabled via Group Policy (AdmPwdEnabled=1).'
                    }
                    elseif ($null -ne $windowsBackupDir -and [int]$windowsBackupDir -ge 1) {
                        $backupTarget = switch ([int]$windowsBackupDir) {
                            1 { 'Active Directory' }
                            2 { 'Microsoft Entra ID' }
                            default { ('Unknown backup target ({0})' -f $windowsBackupDir) }
                        }
                        $status = 'Pass'
                        $evidence = ('Windows LAPS is configured to back up passwords to {0} (BackupDirectory={1}).' -f $backupTarget, $windowsBackupDir)
                    }
                    else {
                        $status = 'Fail'
                        $evidence = 'Neither Windows LAPS nor legacy LAPS (AdmPwd) is configured via Group Policy on this server. Local administrator accounts have unmanaged passwords — a compromised password on one server can be used for lateral movement to all servers sharing the same credential.'
                    }
                }
            }
            'EDCA-SEC-042' {
                $cisPolicy = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and
                    ($server.OS.PSObject.Properties.Name -contains 'CisPolicy')) {
                    $cisPolicy = $server.OS.CisPolicy
                }

                if ($null -eq $cisPolicy) {
                    $status = 'Unknown'
                    $evidence = 'OS security policy data unavailable.'
                }
                else {
                    $interfaceOptions = $null
                    if ($cisPolicy.PSObject.Properties.Name -contains 'NetBiosInterfaceOptions') {
                        $interfaceOptions = @($cisPolicy.NetBiosInterfaceOptions)
                    }

                    if ($null -eq $interfaceOptions -or $interfaceOptions.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = 'NetBIOS interface options not available — re-run collection with the current EDCA build to evaluate this control.'
                    }
                    else {
                        # NetbiosOptions: 0 = default (DHCP), 1 = Enabled, 2 = Disabled
                        $notDisabled = @($interfaceOptions | Where-Object { [int]$_.NetbiosOptions -ne 2 })
                        if ($notDisabled.Count -eq 0) {
                            $status = 'Pass'
                            $evidence = Format-EDCAEvidenceWithElements -Summary ('NetBIOS over TCP/IP is disabled on all {0} interface(s) (NetbiosOptions=2).' -f $interfaceOptions.Count) -Elements @($interfaceOptions | ForEach-Object { ('{0}: NetbiosOptions={1}' -f $_.Interface, $_.NetbiosOptions) })
                        }
                        else {
                            $issueLines = @($notDisabled | ForEach-Object {
                                    $optLabel = switch ([int]$_.NetbiosOptions) {
                                        0 { 'DHCP-controlled (0)' }
                                        1 { 'Enabled (1)' }
                                        default { ('Value {0}' -f $_.NetbiosOptions) }
                                    }
                                    ('{0}: NetbiosOptions={1}' -f $_.Interface, $optLabel)
                                })
                            $status = 'Fail'
                            $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} interface(s) do not have NetBIOS over TCP/IP disabled.' -f $notDisabled.Count, $interfaceOptions.Count) -Elements $issueLines
                        }
                    }
                }
            }
            'EDCA-SEC-043' {
                $cisPolicy = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and
                    ($server.OS.PSObject.Properties.Name -contains 'CisPolicy')) {
                    $cisPolicy = $server.OS.CisPolicy
                }

                if ($null -eq $cisPolicy) {
                    $status = 'Unknown'
                    $evidence = 'OS security policy data unavailable.'
                }
                else {
                    $serverSig = $null
                    $clientSig = $null
                    if ($cisPolicy.PSObject.Properties.Name -contains 'SmbServerRequireSecuritySignature') {
                        $serverSig = $cisPolicy.SmbServerRequireSecuritySignature
                    }
                    if ($cisPolicy.PSObject.Properties.Name -contains 'SmbClientRequireSecuritySignature') {
                        $clientSig = $cisPolicy.SmbClientRequireSecuritySignature
                    }

                    if ($null -eq $serverSig -and $null -eq $clientSig) {
                        $status = 'Unknown'
                        $evidence = 'SMB signing registry values not available — re-run collection with the current EDCA build to evaluate this control.'
                    }
                    else {
                        $details = @()
                        $issues = @()

                        if ($null -eq $serverSig -or [int]$serverSig -ne 1) {
                            $val = if ($null -eq $serverSig) { 'not set (default 0)' } else { [string]$serverSig }
                            $issues += 'SMB server signing not required'
                            $details += ('SMB server (LanmanServer): RequireSecuritySignature={0}' -f $val)
                        }
                        else {
                            $details += 'SMB server (LanmanServer): RequireSecuritySignature=1 (required)'
                        }

                        if ($null -eq $clientSig -or [int]$clientSig -ne 1) {
                            $val = if ($null -eq $clientSig) { 'not set (default 0)' } else { [string]$clientSig }
                            $issues += 'SMB client signing not required'
                            $details += ('SMB client (LanmanWorkstation): RequireSecuritySignature={0}' -f $val)
                        }
                        else {
                            $details += 'SMB client (LanmanWorkstation): RequireSecuritySignature=1 (required)'
                        }

                        if ($issues.Count -gt 0) {
                            $status = 'Fail'
                            $evidence = Format-EDCAEvidenceWithElements -Summary ('SMB packet signing is not enforced: {0}.' -f ($issues -join '; ')) -Elements $details
                        }
                        else {
                            $status = 'Pass'
                            $evidence = Format-EDCAEvidenceWithElements -Summary 'SMB packet signing is required on both server (LanmanServer) and client (LanmanWorkstation).' -Elements $details
                        }
                    }
                }
            }
            'EDCA-SEC-037' {
                $cisPolicy = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and
                    ($server.OS.PSObject.Properties.Name -contains 'CisPolicy')) {
                    $cisPolicy = $server.OS.CisPolicy
                }

                if ($null -eq $cisPolicy) {
                    $status = 'Unknown'
                    $evidence = 'OS security policy data unavailable.'
                }
                else {
                    $ldapIntegrity = $null
                    if ($cisPolicy.PSObject.Properties.Name -contains 'LdapClientIntegrity') {
                        $ldapIntegrity = $cisPolicy.LdapClientIntegrity
                    }

                    if ($null -eq $ldapIntegrity) {
                        $status = 'Unknown'
                        $evidence = 'LDAP client integrity value not available — re-run collection with the current EDCA build to evaluate this control.'
                    }
                    else {
                        switch ([int]$ldapIntegrity) {
                            0 {
                                $status = 'Fail'
                                $evidence = 'LDAP client signing is disabled (LdapClientIntegrity=0). LDAP traffic is sent without signing, exposing credentials and session data to relay and interception attacks. Set LdapClientIntegrity=2 via Group Policy (Network security: LDAP client signing requirements = Require signing).'
                            }
                            1 {
                                $status = 'Fail'
                                $evidence = 'LDAP client signing is set to negotiate (LdapClientIntegrity=1). Signing is requested but not enforced — servers that do not require signing will receive unsigned LDAP binds. Set LdapClientIntegrity=2 to require signing on all connections.'
                            }
                            2 {
                                $status = 'Pass'
                                $evidence = 'LDAP client signing is required (LdapClientIntegrity=2). All LDAP connections must use signing.'
                            }
                            default {
                                $status = 'Unknown'
                                $evidence = ('Unexpected LdapClientIntegrity value: {0}.' -f $ldapIntegrity)
                            }
                        }
                    }
                }
            }
            'EDCA-TLS-030' {
                $edgeData = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'EdgeData') -and $null -ne $server.Exchange.EdgeData) {
                    $edgeData = $server.Exchange.EdgeData
                }
                if ($null -eq $edgeData) {
                    $status = 'Unknown'
                    $evidence = 'Edge subscription data unavailable; Exchange cmdlet collection may have failed. Ensure the Edge server was collected locally with -Local.'
                }
                else {
                    $subs = @($edgeData.EdgeSubscriptions)
                    if ($subs.Count -eq 0) {
                        $status = 'Fail'
                        $evidence = 'No Edge subscriptions found. The Edge server is not subscribed to an Exchange organisation. Run New-EdgeSubscription and import the subscription file on a Mailbox server.'
                    }
                    else {
                        $invalid = @($subs | Where-Object { ($_.PSObject.Properties.Name -contains 'IsValid') -and [bool]$_.IsValid -eq $false })
                        $sites = @($subs | ForEach-Object { if ($_.PSObject.Properties.Name -contains 'Site') { [string]$_.Site } }) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
                        if ($invalid.Count -gt 0) {
                            $status = 'Fail'
                            $evidence = ('Edge subscription(s) marked invalid: {0}. Re-run the Edge subscription wizard.' -f (($invalid | ForEach-Object { [string]$_.Name } | Where-Object { $_ }) -join ', '))
                        }
                        else {
                            $status = 'Pass'
                            $evidence = ('{0} valid Edge subscription(s) found, synchronising to site(s): {1}.' -f $subs.Count, ($sites -join ', '))
                        }
                    }
                }
            }
            'EDCA-TLS-031' {
                $edgeData = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'EdgeData') -and $null -ne $server.Exchange.EdgeData) {
                    $edgeData = $server.Exchange.EdgeData
                }
                if ($null -eq $edgeData) {
                    $status = 'Unknown'
                    $evidence = 'Anti-spam agent data unavailable; Exchange cmdlet collection may have failed.'
                }
                else {
                    $disabled = @()
                    foreach ($pair in @(
                            @('ContentFilterConfig', 'Content filtering'),
                            @('RecipientFilterConfig', 'Recipient filtering'),
                            @('SenderFilterConfig', 'Sender filtering'),
                            @('ConnectionFilteringAgent', 'Connection filtering')
                        )) {
                        $prop = $pair[0]; $label = $pair[1]
                        $cfg = $edgeData.PSObject.Properties[$prop]
                        if ($null -eq $cfg -or $null -eq $cfg.Value) {
                            $disabled += "$label (data unavailable)"
                        }
                        elseif (($cfg.Value.PSObject.Properties.Name -contains 'Enabled') -and [bool]$cfg.Value.Enabled -eq $false) {
                            $disabled += "$label is disabled"
                        }
                    }
                    if ($disabled.Count -eq 0) {
                        $status = 'Pass'
                        $evidence = 'Content, recipient, sender, and connection filtering agents are all enabled.'
                    }
                    else {
                        $status = 'Fail'
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('Anti-spam agents not enabled:') -Elements $disabled
                    }
                }
            }
            'EDCA-TLS-032' {
                $edgeData = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'EdgeData') -and $null -ne $server.Exchange.EdgeData) {
                    $edgeData = $server.Exchange.EdgeData
                }
                if ($null -eq $edgeData -or $null -eq $edgeData.RecipientFilterConfig) {
                    $status = 'Unknown'
                    $evidence = 'Recipient filter configuration data unavailable.'
                }
                elseif (($edgeData.RecipientFilterConfig.PSObject.Properties.Name -contains 'RecipientValidationEnabled') -and [bool]$edgeData.RecipientFilterConfig.RecipientValidationEnabled) {
                    $status = 'Pass'
                    $evidence = 'Recipient validation is enabled; mail for non-existent recipients is rejected at the Edge.'
                }
                else {
                    $status = 'Fail'
                    $evidence = 'Recipient validation is disabled. The Edge server accepts mail for non-existent recipients, exposing the organisation to directory harvest attacks. Run: Set-RecipientFilterConfig -RecipientValidationEnabled $true'
                }
            }
            'EDCA-TLS-033' {
                $edgeData = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'EdgeData') -and $null -ne $server.Exchange.EdgeData) {
                    $edgeData = $server.Exchange.EdgeData
                }
                if ($null -eq $edgeData -or $null -eq $edgeData.SenderFilterConfig) {
                    $status = 'Unknown'
                    $evidence = 'Sender filter configuration data unavailable.'
                }
                elseif (($edgeData.SenderFilterConfig.PSObject.Properties.Name -contains 'BlankSenderBlockingEnabled') -and [bool]$edgeData.SenderFilterConfig.BlankSenderBlockingEnabled) {
                    $status = 'Pass'
                    $evidence = 'Blank sender blocking is enabled; mail with an empty MAIL FROM address is rejected.'
                }
                else {
                    $status = 'Fail'
                    $evidence = 'Blank sender blocking is disabled. The Edge server accepts mail with an empty MAIL FROM address, facilitating bounce spam and backscatter. Run: Set-SenderFilterConfig -BlankSenderBlockingEnabled $true'
                }
            }
            'EDCA-TLS-034' {
                $edgeData = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'EdgeData') -and $null -ne $server.Exchange.EdgeData) {
                    $edgeData = $server.Exchange.EdgeData
                }
                if ($null -eq $edgeData) {
                    $status = 'Unknown'
                    $evidence = 'Send connector data unavailable.'
                }
                else {
                    $connectors = @($edgeData.SendConnectors)
                    if ($connectors.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = 'No send connectors found on this Edge server.'
                    }
                    else {
                        $noTls = @($connectors | Where-Object {
                                ($_.PSObject.Properties.Name -contains 'RequireTls') -and [bool]$_.RequireTls -eq $false -and
                                ($_.PSObject.Properties.Name -contains 'Enabled') -and [bool]$_.Enabled
                            })
                        if ($noTls.Count -eq 0) {
                            $status = 'Pass'
                            $evidence = ('All {0} send connector(s) have RequireTls enabled.' -f $connectors.Count)
                        }
                        else {
                            $status = 'Fail'
                            $summary = ('{0} of {1} enabled send connector(s) do not require TLS:' -f $noTls.Count, $connectors.Count)
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements @($noTls | ForEach-Object { [string]$_.Identity })
                        }
                    }
                }
            }
            'EDCA-TLS-035' {
                $edgeData = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'EdgeData') -and $null -ne $server.Exchange.EdgeData) {
                    $edgeData = $server.Exchange.EdgeData
                }
                if ($null -eq $edgeData) {
                    $status = 'Unknown'
                    $evidence = 'Send connector data unavailable.'
                }
                else {
                    $connectors = @($edgeData.SendConnectors)
                    if ($connectors.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = 'No send connectors found on this Edge server.'
                    }
                    else {
                        $nonVerbose = @($connectors | Where-Object {
                                ($_.PSObject.Properties.Name -contains 'ProtocolLoggingLevel') -and
                                [string]$_.ProtocolLoggingLevel -ne 'Verbose'
                            })
                        if ($nonVerbose.Count -eq 0) {
                            $status = 'Pass'
                            $evidence = ('All {0} send connector(s) have Verbose protocol logging enabled.' -f $connectors.Count)
                        }
                        else {
                            $status = 'Fail'
                            $summary = ('{0} of {1} send connector(s) do not have Verbose protocol logging:' -f $nonVerbose.Count, $connectors.Count)
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements @($nonVerbose | ForEach-Object { '{0} (ProtocolLoggingLevel: {1})' -f [string]$_.Identity, [string]$_.ProtocolLoggingLevel })
                        }
                    }
                }
            }
            'EDCA-TLS-036' {
                $certs = @()
                if (($server.PSObject.Properties.Name -contains 'Certificates') -and $null -ne $server.Certificates) {
                    $certs = @($server.Certificates)
                }
                if ($certs.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'Certificate data unavailable; cannot verify SMTP service assignment.'
                }
                else {
                    $smtpCerts = @($certs | Where-Object {
                            ($_.PSObject.Properties.Name -contains 'Services') -and [string]$_.Services -match 'SMTP' -and
                            ($_.PSObject.Properties.Name -contains 'IsExpired') -and [bool]$_.IsExpired -eq $false
                        })
                    if ($smtpCerts.Count -gt 0) {
                        $status = 'Pass'
                        $evidence = ('{0} non-expired certificate(s) with the SMTP service assigned: {1}' -f $smtpCerts.Count, (($smtpCerts | ForEach-Object { [string]$_.Subject }) -join ', '))
                    }
                    else {
                        $anySmt = @($certs | Where-Object { ($_.PSObject.Properties.Name -contains 'Services') -and [string]$_.Services -match 'SMTP' })
                        if ($anySmt.Count -gt 0) {
                            $status = 'Fail'
                            $evidence = ('SMTP service is assigned but the certificate is expired. The Edge server cannot negotiate TLS until a valid certificate is assigned. Renew: Enable-ExchangeCertificate -Thumbprint <thumb> -Services SMTP')
                        }
                        else {
                            $status = 'Fail'
                            $evidence = 'No certificate has the SMTP service assigned. The Edge server will not present a certificate for STARTTLS. Assign with: Enable-ExchangeCertificate -Thumbprint <thumb> -Services SMTP'
                        }
                    }
                }
            }
            'EDCA-DATA-019' {
                $val64 = $null
                $val32 = $null
                if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS) {
                    if ($server.OS.PSObject.Properties.Name -contains 'SchUseStrongCrypto64') { $val64 = $server.OS.SchUseStrongCrypto64 }
                    if ($server.OS.PSObject.Properties.Name -contains 'SchUseStrongCrypto32') { $val32 = $server.OS.SchUseStrongCrypto32 }
                }
                $ok64 = ($null -ne $val64) -and ([int]$val64 -eq 1)
                $ok32 = ($null -ne $val32) -and ([int]$val32 -eq 1)
                if ($null -eq $val64 -and $null -eq $val32) {
                    $status = 'Unknown'
                    $evidence = 'SchUseStrongCrypto registry data unavailable.'
                }
                elseif ($ok64 -and $ok32) {
                    $status = 'Pass'
                    $evidence = 'SchUseStrongCrypto is set to 1 in both the 64-bit and 32-bit (WoW6432Node) .NET Framework v4.0.30319 registry paths.'
                }
                else {
                    $missing = @()
                    if (-not $ok64) { $missing += 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319 (64-bit)' }
                    if (-not $ok32) { $missing += 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319 (32-bit)' }
                    $status = 'Fail'
                    $evidence = Format-EDCAEvidenceWithElements -Summary 'SchUseStrongCrypto is not set to 1 in the following paths:' -Elements $missing
                }
            }
            'EDCA-TLS-037' {
                $edgeData = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'EdgeData') -and $null -ne $server.Exchange.EdgeData) {
                    $edgeData = $server.Exchange.EdgeData
                }
                if ($null -eq $edgeData -or $null -eq $edgeData.ReceiveConnectors) {
                    $status = 'Unknown'
                    $evidence = 'Receive connector data unavailable.'
                }
                else {
                    $connectors = @($edgeData.ReceiveConnectors)
                    if ($connectors.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = 'No Receive connectors found on this Edge server.'
                    }
                    else {
                        $notEnabled = @($connectors | Where-Object {
                                ($_.PSObject.Properties.Name -contains 'DomainSecureEnabled') -and
                                [bool]$_.DomainSecureEnabled -eq $false
                            })
                        if ($notEnabled.Count -eq 0) {
                            $status = 'Pass'
                            $evidence = ('All {0} Receive connector(s) have DomainSecureEnabled set to True.' -f $connectors.Count)
                        }
                        else {
                            $status = 'Fail'
                            $summary = ('{0} of {1} Receive connector(s) do not have DomainSecureEnabled:' -f $notEnabled.Count, $connectors.Count)
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements @($notEnabled | ForEach-Object { [string]$_.Identity })
                        }
                    }
                }
            }
            'EDCA-TLS-038' {
                $edgeData = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'EdgeData') -and $null -ne $server.Exchange.EdgeData) {
                    $edgeData = $server.Exchange.EdgeData
                }
                if ($null -eq $edgeData -or $null -eq $edgeData.ReceiveConnectors) {
                    $status = 'Unknown'
                    $evidence = 'Receive connector data unavailable.'
                }
                else {
                    $internetRc = @($edgeData.ReceiveConnectors | Where-Object {
                            ($_.PSObject.Properties.Name -contains 'Bindings') -and
                            ([string]$_.Bindings -match '0\.0\.0\.0:25' -or [string]$_.Bindings -match '\[::\]:25')
                        })
                    if ($internetRc.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = 'No internet-facing Receive connectors (port 25 on all interfaces) found; cannot evaluate TLS auth requirement.'
                    }
                    else {
                        $noTls = @($internetRc | Where-Object {
                                ($_.PSObject.Properties.Name -contains 'AuthMechanism') -and
                                [string]$_.AuthMechanism -notmatch 'Tls'
                            })
                        if ($noTls.Count -eq 0) {
                            $status = 'Pass'
                            $evidence = ('All {0} internet-facing Receive connector(s) include Tls in AuthMechanism.' -f $internetRc.Count)
                        }
                        else {
                            $status = 'Fail'
                            $summary = ('{0} internet-facing Receive connector(s) do not include Tls in AuthMechanism:' -f $noTls.Count)
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements @($noTls | ForEach-Object { '{0} (AuthMechanism: {1})' -f [string]$_.Identity, [string]$_.AuthMechanism })
                        }
                    }
                }
            }
            'EDCA-TLS-039' {
                $edgeData = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'EdgeData') -and $null -ne $server.Exchange.EdgeData) {
                    $edgeData = $server.Exchange.EdgeData
                }
                if ($null -eq $edgeData -or $null -eq $edgeData.ReceiveConnectors) {
                    $status = 'Unknown'
                    $evidence = 'Receive connector data unavailable.'
                }
                else {
                    # Internal connectors created by EdgeSync include ExchangeServer in their AuthMechanism.
                    # Internet-facing connectors do not; use this to distinguish internal from internet-facing.
                    $internalRc = @($edgeData.ReceiveConnectors | Where-Object {
                            ($_.PSObject.Properties.Name -contains 'AuthMechanism') -and
                            [string]$_.AuthMechanism -match '\bExchangeServer\b'
                        })
                    if ($internalRc.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = 'No internal Receive connectors identified (ExchangeServer AuthMechanism); cannot evaluate TLS requirement.'
                    }
                    else {
                        $noTls = @($internalRc | Where-Object {
                                ($_.PSObject.Properties.Name -contains 'RequireTLS') -and
                                [bool]$_.RequireTLS -eq $false
                            })
                        if ($noTls.Count -eq 0) {
                            $status = 'Pass'
                            $evidence = ('All {0} internal Receive connector(s) require TLS.' -f $internalRc.Count)
                        }
                        else {
                            $status = 'Fail'
                            $summary = ('{0} internal Receive connector(s) do not require TLS:' -f $noTls.Count)
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements @($noTls | ForEach-Object { '{0} (RequireTLS: {1})' -f [string]$_.Identity, [string]$_.RequireTLS })
                        }
                    }
                }
            }
            'EDCA-TLS-040' {
                $edgeData = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'EdgeData') -and $null -ne $server.Exchange.EdgeData) {
                    $edgeData = $server.Exchange.EdgeData
                }
                if ($null -eq $edgeData -or $null -eq $edgeData.ReceiveConnectors) {
                    $status = 'Unknown'
                    $evidence = 'Receive connector data unavailable.'
                }
                else {
                    # Internal connectors created by EdgeSync include ExchangeServer in their AuthMechanism.
                    # Internet-facing connectors do not; use this to distinguish internal from internet-facing.
                    $internalRc = @($edgeData.ReceiveConnectors | Where-Object {
                            ($_.PSObject.Properties.Name -contains 'AuthMechanism') -and
                            [string]$_.AuthMechanism -match '\bExchangeServer\b'
                        })
                    if ($internalRc.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = 'No internal Receive connectors identified (ExchangeServer AuthMechanism); cannot evaluate anonymous connection policy.'
                    }
                    else {
                        $allowAnon = @($internalRc | Where-Object {
                                ($_.PSObject.Properties.Name -contains 'PermissionGroups') -and
                                [string]$_.PermissionGroups -match 'AnonymousUsers'
                            })
                        if ($allowAnon.Count -eq 0) {
                            $status = 'Pass'
                            $evidence = ('No internal Receive connector(s) allow anonymous connections.')
                        }
                        else {
                            $status = 'Fail'
                            $summary = ('{0} internal Receive connector(s) allow anonymous connections:' -f $allowAnon.Count)
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements @($allowAnon | ForEach-Object { '{0} (PermissionGroups: {1})' -f [string]$_.Identity, [string]$_.PermissionGroups })
                        }
                    }
                }
            }
            'EDCA-TLS-041' {
                # Collect internet-facing receive connectors from the appropriate data source:
                # - Mailbox role: $server.Exchange.ReceiveConnectors (internet-facing = AnonymousUsers + Tls/None AuthMechanism)
                # - Edge role:    $server.Exchange.EdgeData.ReceiveConnectors (internet-facing = no ExchangeServer in AuthMechanism)
                $internetFacing = @()
                $isEdge = ($server.PSObject.Properties.Name -contains 'Exchange') -and
                $null -ne $server.Exchange -and
                ($server.Exchange.PSObject.Properties.Name -contains 'EdgeData') -and
                $null -ne $server.Exchange.EdgeData

                if ($isEdge) {
                    $allRc = @($server.Exchange.EdgeData.ReceiveConnectors)
                    # Internet-facing connectors do NOT have ExchangeServer in AuthMechanism
                    $internetFacing = @($allRc | Where-Object {
                            ($_.PSObject.Properties.Name -contains 'AuthMechanism') -and
                            [string]$_.AuthMechanism -notmatch '\bExchangeServer\b'
                        })
                }
                elseif (($server.PSObject.Properties.Name -contains 'Exchange') -and
                    $null -ne $server.Exchange -and
                    ($server.Exchange.PSObject.Properties.Name -contains 'ReceiveConnectors')) {
                    $allRc = @($server.Exchange.ReceiveConnectors)
                    # Internet-facing connectors allow anonymous users with Tls or None AuthMechanism
                    $internetFacing = @($allRc | Where-Object {
                            ($_.PSObject.Properties.Name -contains 'PermissionGroups') -and
                            [string]$_.PermissionGroups -match '\bAnonymousUsers\b' -and
                            ($_.PSObject.Properties.Name -contains 'AuthMechanism') -and
                            ([string]$_.AuthMechanism -match '\bTls\b' -or [string]$_.AuthMechanism -eq 'None')
                        })
                }

                if ($internetFacing.Count -eq 0) {
                    $status = 'Pass'
                    $evidence = 'No internet-facing Receive connectors identified on this server; SMTP banner exposure not applicable.'
                }
                else {
                    $revealing = @($internetFacing | Where-Object {
                            $banner = if ($_.PSObject.Properties.Name -contains 'Banner') { [string]$_.Banner } else { $null }
                            (-not [string]::IsNullOrWhiteSpace($banner)) -and ($banner -match '(?i)\bexchange\b|15\.[0-9]+\.[0-9]')
                        })
                    $emptyBanner = @($internetFacing | Where-Object {
                            -not ($_.PSObject.Properties.Name -contains 'Banner') -or [string]::IsNullOrWhiteSpace([string]$_.Banner)
                        })
                    if ($revealing.Count -gt 0) {
                        $status = 'Fail'
                        $details = @($revealing | ForEach-Object { ('{0}: Banner="{1}"' -f [string]$_.Identity, [string]$_.Banner) })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} internet-facing Receive connector(s) have an SMTP banner that reveals server identity.' -f $revealing.Count, $internetFacing.Count) -Elements $details
                    }
                    elseif ($emptyBanner.Count -gt 0) {
                        $status = 'Unknown'
                        $details = @($emptyBanner | ForEach-Object { [string]$_.Identity })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} internet-facing Receive connector(s) have no custom SMTP banner; the default banner may reveal software identity.' -f $emptyBanner.Count, $internetFacing.Count) -Elements $details
                    }
                    else {
                        $status = 'Pass'
                        $evidence = ('All {0} internet-facing Receive connector(s) have a custom SMTP banner that does not reveal server identity.' -f $internetFacing.Count)
                    }
                }
            }
            'EDCA-TLS-042' {
                $edgeData = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'EdgeData') -and $null -ne $server.Exchange.EdgeData) {
                    $edgeData = $server.Exchange.EdgeData
                }
                if ($null -eq $edgeData) {
                    $status = 'Unknown'
                    $evidence = 'Send connector data unavailable.'
                }
                else {
                    $connectors = @($edgeData.SendConnectors)
                    if ($connectors.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = 'No send connectors found on this Edge server.'
                    }
                    else {
                        $noSmartHost = @($connectors | Where-Object {
                                ($_.PSObject.Properties.Name -contains 'DNSRoutingEnabled') -and
                                [bool]$_.DNSRoutingEnabled -eq $true -and
                                ($_.PSObject.Properties.Name -contains 'Enabled') -and
                                [bool]$_.Enabled
                            })
                        if ($noSmartHost.Count -eq 0) {
                            $status = 'Pass'
                            $evidence = ('All {0} enabled send connector(s) route via a Smart Host (DNSRoutingEnabled is False).' -f $connectors.Count)
                        }
                        else {
                            $status = 'Fail'
                            $summary = ('{0} enabled send connector(s) use direct DNS routing instead of a Smart Host:' -f $noSmartHost.Count)
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements @($noSmartHost | ForEach-Object { [string]$_.Identity })
                        }
                    }
                }
            }
            'EDCA-TLS-043' {
                $edgeData = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'EdgeData') -and $null -ne $server.Exchange.EdgeData) {
                    $edgeData = $server.Exchange.EdgeData
                }
                if ($null -eq $edgeData) {
                    $status = 'Unknown'
                    $evidence = 'Send connector data unavailable.'
                }
                else {
                    $connectors = @($edgeData.SendConnectors)
                    if ($connectors.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = 'No send connectors found on this Edge server.'
                    }
                    else {
                        $notMtls = @($connectors | Where-Object {
                                ($_.PSObject.Properties.Name -contains 'Enabled') -and [bool]$_.Enabled -and
                                (
                                    -not ($_.PSObject.Properties.Name -contains 'DomainSecureEnabled') -or
                                    [bool]$_.DomainSecureEnabled -eq $false
                                )
                            })
                        if ($notMtls.Count -eq 0) {
                            $status = 'Pass'
                            $evidence = ('All {0} enabled send connector(s) have domain security (mutual TLS) enabled.' -f $connectors.Count)
                        }
                        else {
                            $status = 'Fail'
                            $summary = ('{0} enabled send connector(s) do not have DomainSecureEnabled:' -f $notMtls.Count)
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements @($notMtls | ForEach-Object { [string]$_.Identity })
                        }
                    }
                }
            }
            'EDCA-TLS-044' {
                $edgeData = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'EdgeData') -and $null -ne $server.Exchange.EdgeData) {
                    $edgeData = $server.Exchange.EdgeData
                }
                if ($null -eq $edgeData -or $null -eq $edgeData.SenderFilterConfig) {
                    $status = 'Unknown'
                    $evidence = 'Sender filter configuration data unavailable.'
                }
                else {
                    $sfc = $edgeData.SenderFilterConfig
                    $enabled = ($sfc.PSObject.Properties.Name -contains 'Enabled') -and [bool]$sfc.Enabled
                    $hasBlocked = ($sfc.PSObject.Properties.Name -contains 'BlockedDomains') -and $null -ne $sfc.BlockedDomains -and @($sfc.BlockedDomains).Count -gt 0
                    if ($enabled -and $hasBlocked) {
                        $status = 'Pass'
                        $evidence = ('Sender filter is enabled with {0} blocked domain(s) configured.' -f @($sfc.BlockedDomains).Count)
                    }
                    elseif (-not $enabled) {
                        $status = 'Fail'
                        $evidence = 'Sender filter is disabled. Enable it with: Set-SenderFilterConfig -Enabled $true'
                    }
                    else {
                        $status = 'Fail'
                        $evidence = 'Sender filter is enabled but no blocked domains are configured. Add unaccepted sending domains to block spoofed internal-domain senders.'
                    }
                }
            }
            'EDCA-TLS-045' {
                $edgeData = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'EdgeData') -and $null -ne $server.Exchange.EdgeData) {
                    $edgeData = $server.Exchange.EdgeData
                }
                if ($null -eq $edgeData -or $null -eq $edgeData.SenderReputationConfig) {
                    $status = 'Unknown'
                    $evidence = 'Sender Reputation configuration data unavailable.'
                }
                elseif (($edgeData.SenderReputationConfig.PSObject.Properties.Name -contains 'Enabled') -and [bool]$edgeData.SenderReputationConfig.Enabled) {
                    $status = 'Pass'
                    $evidence = 'Sender Reputation filter is enabled.'
                }
                else {
                    $status = 'Fail'
                    $evidence = 'Sender Reputation filter is disabled. Enable it with: Set-SenderReputationConfig -Enabled $true'
                }
            }
            'EDCA-TLS-046' {
                $edgeData = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'EdgeData') -and $null -ne $server.Exchange.EdgeData) {
                    $edgeData = $server.Exchange.EdgeData
                }
                if ($null -eq $edgeData -or $null -eq $edgeData.ContentFilterConfig) {
                    $status = 'Unknown'
                    $evidence = 'Content filter configuration data unavailable.'
                }
                elseif (($edgeData.ContentFilterConfig.PSObject.Properties.Name -contains 'Enabled') -and [bool]$edgeData.ContentFilterConfig.Enabled) {
                    $status = 'Pass'
                    $evidence = 'Content filter (spam confidence level evaluation) is enabled.'
                }
                else {
                    $status = 'Fail'
                    $evidence = 'Content filter is disabled. Enable it with: Set-ContentFilterConfig -Enabled $true'
                }
            }
            'EDCA-TLS-047' {
                $edgeData = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'EdgeData') -and $null -ne $server.Exchange.EdgeData) {
                    $edgeData = $server.Exchange.EdgeData
                }
                if ($null -eq $edgeData -or $null -eq $edgeData.SenderIdConfig) {
                    $status = 'Unknown'
                    $evidence = 'Sender ID configuration data unavailable.'
                }
                else {
                    $sidCfg = $edgeData.SenderIdConfig
                    $enabled = ($sidCfg.PSObject.Properties.Name -contains 'Enabled') -and [bool]$sidCfg.Enabled
                    $action = if ($sidCfg.PSObject.Properties.Name -contains 'SpoofedDomainAction') { [string]$sidCfg.SpoofedDomainAction } else { 'Unknown' }
                    if ($enabled) {
                        $status = 'Pass'
                        $evidence = ('Sender ID filter is enabled. SpoofedDomainAction: {0}.' -f $action)
                    }
                    else {
                        $status = 'Fail'
                        $evidence = 'Sender ID filter is disabled. Enable it with: Set-SenderIdConfig -Enabled $true -SpoofedDomainAction Reject'
                    }
                }
            }
            'EDCA-TLS-048' {
                $edgeData = $null
                if (($server.Exchange.PSObject.Properties.Name -contains 'EdgeData') -and $null -ne $server.Exchange.EdgeData) {
                    $edgeData = $server.Exchange.EdgeData
                }
                if ($null -eq $edgeData -or $null -eq $edgeData.ReceiveConnectors) {
                    $status = 'Unknown'
                    $evidence = 'Receive connector data unavailable.'
                }
                else {
                    $connectors = @($edgeData.ReceiveConnectors)
                    if ($connectors.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = 'No Receive connectors found on this Edge server.'
                    }
                    else {
                        $minInterval = [TimeSpan]::FromSeconds(5)
                        $badTarpit = @($connectors | Where-Object {
                                ($_.PSObject.Properties.Name -contains 'TarpitInterval') -and
                                $null -ne $_.TarpitInterval -and
                                $(try { [TimeSpan]::new([long]$_.TarpitInterval.Ticks) -lt $minInterval } catch { $false })
                            })
                        if ($badTarpit.Count -eq 0) {
                            $status = 'Pass'
                            $evidence = ('All {0} Receive connector(s) have a tarpitting interval of at least 5 seconds.' -f $connectors.Count)
                        }
                        else {
                            $status = 'Fail'
                            $summary = ('{0} Receive connector(s) have a tarpitting interval below 5 seconds:' -f $badTarpit.Count)
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements @($badTarpit | ForEach-Object { '{0} (TarpitInterval: {1})' -f [string]$_.Identity, [string]$_.TarpitInterval })
                        }
                    }
                }
            }
            default {
                $status = 'Unknown'
                $evidence = 'Control evaluator not implemented.'
            }
        }

        if ($null -ne $dbServerResults) {
            $serverResults += $dbServerResults
        }
        else {
            $serverResults += [pscustomobject]@{
                Server   = $serverName
                Status   = $status
                Evidence = $evidence
            }
        }
    }

    $nonSkipped = @($serverResults | Where-Object { $_.Status -ne 'Skipped' })
    $hasFail = (@($nonSkipped | Where-Object { $_.Status -eq 'Fail' }).Count -gt 0)
    $hasUnknown = (@($nonSkipped | Where-Object { $_.Status -eq 'Unknown' }).Count -gt 0)

    $overallStatus = if ($nonSkipped.Count -eq 0) {
        'Skipped'
    }
    elseif ($hasFail) {
        'Fail'
    }
    elseif ($hasUnknown) {
        'Unknown'
    }
    else {
        'Pass'
    }

    return [pscustomobject]@{
        ControlId      = $Control.id
        Title          = $Control.title
        Description    = $Control.description
        Category       = $Control.category
        Severity       = $Control.severity
        SeverityWeight = [int]$Control.severityWeight
        Frameworks     = @($Control.frameworks)
        Verify         = [bool]$Control.verify
        OverallStatus  = $overallStatus
        Subject        = [string]$Control.subject
        Roles          = @($Control.roles | ForEach-Object { [string]$_ })
        SubjectLabel   = $subjectLabel
        ServerResults  = $serverResults
        References     = @($Control.references)
        Remediation    = $Control.remediation
        Considerations = [string]$Control.considerations
    }
}

function Get-EDCAScores {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Findings
    )

    $frameworks = @('Best Practice', 'ANSSI', 'BSI', 'CIS', 'CISA', 'NIS2', 'DISA')
    $scores = @()

    # Overall score across all verifiable controls (each counted once); Skipped excluded from denominator
    $allSkipped = @($Findings | Where-Object { $_.Verify -and $_.OverallStatus -eq 'Skipped' })
    $allEligible = @($Findings | Where-Object { $_.Verify -and $_.OverallStatus -ne 'Skipped' })
    $allTotalWeight = 0
    $allPassedWeight = 0
    foreach ($item in $allEligible) {
        $w = 0
        if ($item.PSObject.Properties.Name -contains 'SeverityWeight') { [void][int]::TryParse([string]$item.SeverityWeight, [ref]$w) }
        $allTotalWeight += $w
    }
    foreach ($item in ($allEligible | Where-Object { $_.OverallStatus -eq 'Pass' })) {
        $w = 0
        if ($item.PSObject.Properties.Name -contains 'SeverityWeight') { [void][int]::TryParse([string]$item.SeverityWeight, [ref]$w) }
        $allPassedWeight += $w
    }
    $allScore = if ($allTotalWeight -gt 0) { [math]::Round(100 * $allPassedWeight / $allTotalWeight, 2) } else { 0 }
    $scores += [pscustomobject]@{
        Framework       = 'All'
        Score           = $allScore
        TotalControls   = $allEligible.Count
        FailedControls  = @($allEligible | Where-Object { $_.OverallStatus -eq 'Fail' }).Count
        WarningControls = @($allEligible | Where-Object { $_.OverallStatus -eq 'Warning' }).Count
        UnknownControls = @($allEligible | Where-Object { $_.OverallStatus -eq 'Unknown' }).Count
        SkippedControls = $allSkipped.Count
    }

    foreach ($framework in $frameworks) {
        $allFramework = @($Findings | Where-Object {
                $_.Verify -and ($_.Frameworks -contains $framework)
            })
        $skippedCount = @($allFramework | Where-Object { $_.OverallStatus -eq 'Skipped' }).Count
        $eligible = @($allFramework | Where-Object { $_.OverallStatus -ne 'Skipped' })

        $totalWeight = 0
        foreach ($item in $eligible) {
            $weight = 0
            if ($item.PSObject.Properties.Name -contains 'SeverityWeight') {
                [void][int]::TryParse([string]$item.SeverityWeight, [ref]$weight)
            }
            $totalWeight += $weight
        }

        $passedWeight = 0
        foreach ($item in ($eligible | Where-Object { $_.OverallStatus -eq 'Pass' })) {
            $weight = 0
            if ($item.PSObject.Properties.Name -contains 'SeverityWeight') {
                [void][int]::TryParse([string]$item.SeverityWeight, [ref]$weight)
            }
            $passedWeight += $weight
        }
        $failedCount = @($eligible | Where-Object { $_.OverallStatus -eq 'Fail' }).Count
        $unknownCount = @($eligible | Where-Object { $_.OverallStatus -eq 'Unknown' }).Count

        if ($null -eq $totalWeight -or $totalWeight -eq 0) {
            $score = 0
        }
        else {
            $score = [math]::Round((100 * $passedWeight / $totalWeight), 2)
        }

        $scores += [pscustomobject]@{
            Framework       = $framework
            Score           = $score
            TotalControls   = $eligible.Count
            FailedControls  = $failedCount
            WarningControls = @($eligible | Where-Object { $_.OverallStatus -eq 'Warning' }).Count
            UnknownControls = $unknownCount
            SkippedControls = $skippedCount
        }
    }

    return $scores
}

function Invoke-EDCAAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$CollectionData,
        [Parameter(Mandatory = $true)]
        [object[]]$Controls
    )

    Write-Verbose ('Starting analysis for {0} control definition(s).' -f $Controls.Count)
    $findings = @()
    foreach ($control in $Controls) {
        Write-Verbose ('Evaluating control {0}: {1}' -f [string]$control.id, [string]$control.title)
        $finding = Test-EDCAControl -Control $control -CollectionData $CollectionData
        $findings += $finding

        $serverResultCount = @($finding.ServerResults).Count
        Write-Verbose ('Control {0} evaluated with overall status {1} across {2} server result(s).' -f [string]$finding.ControlId, [string]$finding.OverallStatus, $serverResultCount)
    }

    $scores = Get-EDCAScores -Findings $findings
    foreach ($score in $scores) {
        Write-Verbose ('Score {0}: {1}% (controls: {2}, failed: {3}, unknown: {4})' -f $score.Framework, $score.Score, $score.TotalControls, $score.FailedControls, $score.UnknownControls)
    }

    return [pscustomobject]@{
        Metadata = [pscustomobject]@{
            AnalysisTimestamp   = (Get-Date -Format 'o')
            ControlCount        = $Controls.Count
            EnabledControlCount = (@($Controls | Where-Object { $_.verify }).Count)
        }
        Scores   = $scores
        Findings = $findings
    }
}



