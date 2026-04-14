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

    if ($Control.id -in @('EX-BP-005', 'EX-BP-007', 'EX-BP-036', 'EX-BP-049', 'EX-BP-083', 'EX-BP-084', 'EX-BP-034', 'EX-BP-031', 'EX-BP-033', 'EX-BP-032', 'EX-BP-004', 'EX-BP-003', 'EX-BP-009', 'EX-BP-069', 'EX-BP-087', 'EX-BP-040', 'EX-BP-085', 'EX-BP-095', 'EX-BP-096', 'EX-BP-097', 'EX-BP-098', 'EX-BP-099', 'EX-BP-100', 'EX-BP-102', 'EX-BP-103', 'EX-BP-104', 'EX-BP-111', 'EX-BP-114', 'EX-BP-115', 'EX-BP-116', 'EX-BP-117', 'EX-BP-118', 'EX-BP-119', 'EX-BP-120', 'EX-BP-121', 'EX-BP-122', 'EX-BP-123', 'EX-BP-124', 'EX-BP-109', 'EX-BP-139', 'EX-BP-141', 'EX-BP-153', 'EX-BP-158')) {
        $status = 'Unknown'
        $evidence = ''
        $domainServerResults = $null
        $subjectLabel = 'Server'

        switch ($Control.id) {
            'EX-BP-084' {
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
            'EX-BP-007' {
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
            'EX-BP-049' {
                if (($CollectionData.PSObject.Properties.Name -contains 'Organization') -and $null -ne $CollectionData.Organization -and ($CollectionData.Organization.PSObject.Properties.Name -contains 'OAuth2ClientProfileEnabled') -and $null -ne $CollectionData.Organization.OAuth2ClientProfileEnabled) {
                    $enabled = [bool]$CollectionData.Organization.OAuth2ClientProfileEnabled
                    $status = if ($enabled) { 'Pass' } else { 'Fail' }
                    $evidence = ('OAuth2ClientProfileEnabled is {0}.' -f (Get-EDCAStateDescriptor -Value $enabled -Expectation 'Enabled'))
                }
                else {
                    $status = 'Unknown'
                    $evidence = 'Modern Authentication organization setting unavailable.'
                }
            }
            'EX-BP-083' {
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
            'EX-BP-034' {
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
            'EX-BP-031' {
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
                                [pscustomobject]@{ Server = $_.Domain; Status = $_.Dmarc.Status; Evidence = [string]$_.Dmarc.Evidence }
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
            'EX-BP-033' {
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
                                [pscustomobject]@{ Server = $_.Domain; Status = $_.MtaSts.Status; Evidence = [string]$_.MtaSts.Evidence }
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
            'EX-BP-032' {
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
                                [pscustomobject]@{ Server = $_.Domain; Status = $_.Dane.Status; Evidence = [string]$_.Dane.Evidence }
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
            'EX-BP-004' {
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
            'EX-BP-003' {
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
            'EX-BP-009' {
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
            'EX-BP-069' {
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
                                $dse = if ($_.PSObject.Properties.Name -contains 'DomainSecureEnabled') { $_.DomainSecureEnabled } else { $null }
                                $dseDisplay = if ($dse -eq $true) { 'True' } elseif ($dse -eq $false) { 'False' } else { 'unknown' }
                                $itemStatus = if ($dse -eq $true) { 'Pass' } elseif ($null -eq $dse) { 'Unknown' } else { 'Fail' }
                                [pscustomobject]@{
                                    Server   = [string]$_.Identity
                                    Status   = $itemStatus
                                    Evidence = ('DomainSecureEnabled: {0}.' -f $dseDisplay)
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
            }
            'EX-BP-087' {
                $hybridApplication = $null
                foreach ($srv in $CollectionData.Servers) {
                    if ($srv.PSObject.Properties.Name -contains 'CollectionError') { continue }
                    if (-not (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and ($srv.Exchange.PSObject.Properties.Name -contains 'HybridApplication'))) { continue }
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
            'EX-BP-040' {
                $hybridApplication = $null
                foreach ($srv in $CollectionData.Servers) {
                    if ($srv.PSObject.Properties.Name -contains 'CollectionError') { continue }
                    if (-not (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and ($srv.Exchange.PSObject.Properties.Name -contains 'HybridApplication'))) { continue }
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
            'EX-BP-085' {
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
                    $evidence = 'Default authentication policy Basic Authentication properties unavailable. No authentication policy may be configured, or data collection failed.'
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
            'EX-BP-095' {
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
            'EX-BP-096' {
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
            'EX-BP-097' {
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
            'EX-BP-098' {
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
            'EX-BP-099' {
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
                        $evidence = ('MaxSendSize is {0} ({1} bytes); CIS L1 limit is 25 MB ({2} bytes).' -f $maxSendDisplay, $maxSendBytes, $limit)
                    }
                }
            }
            'EX-BP-100' {
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
                        $evidence = ('MaxReceiveSize is {0} ({1} bytes); CIS L1 limit is 25 MB ({2} bytes).' -f $maxReceiveDisplay, $maxReceiveBytes, $limit)
                    }
                }
            }
            'EX-BP-103' {
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
            'EX-BP-102' {
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
            'EX-BP-104' {
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
            'EX-BP-111' {
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
            'EX-BP-109' {
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
                            $itemStatus = if ($null -eq $bytes) { 'Unknown' } elseif ($bytes -gt $limit) { 'Fail' } else { 'Pass' }
                            $bytesDisplay = if ($null -ne $bytes) { ('{0:N0} bytes ({1} MB)' -f $bytes, [math]::Round($bytes / 1MB, 2)) } else { 'unknown' }
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
            'EX-BP-139' {
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
            'EX-BP-114' {
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
            'EX-BP-115' {
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
            'EX-BP-116' {
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
                        $evidence = ('PasswordHistory is {0} on the default mobile device mailbox policy; CIS L1 minimum is 4.' -f $intVal)
                    }
                }
            }
            'EX-BP-117' {
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
                        $evidence = ('MinPasswordLength is {0} on the default mobile device mailbox policy; CIS L1 minimum is 4.' -f $intVal)
                    }
                }
            }
            'EX-BP-118' {
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
                        $evidence = 'MaxPasswordFailedAttempts is Unlimited on the default mobile device mailbox policy; CIS L1 maximum is 10.'
                    }
                    else {
                        $intVal = [int]$val
                        $status = if ($intVal -le 10) { 'Pass' } else { 'Fail' }
                        $evidence = ('MaxPasswordFailedAttempts is {0} on the default mobile device mailbox policy; CIS L1 maximum is 10.' -f $intVal)
                    }
                }
            }
            'EX-BP-119' {
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
                        $evidence = 'PasswordExpiration is Unlimited on the default mobile device mailbox policy; CIS L1 maximum is 365 days.'
                    }
                    else {
                        try {
                            $ts = [timespan]::Parse([string]$val)
                            $status = if ($ts.TotalDays -le 365) { 'Pass' } else { 'Fail' }
                            $evidence = ('PasswordExpiration is {0} days on the default mobile device mailbox policy; CIS L1 maximum is 365 days.' -f [math]::Round($ts.TotalDays, 1))
                        }
                        catch {
                            $status = 'Unknown'
                            $evidence = ('PasswordExpiration value could not be parsed: {0}' -f [string]$val)
                        }
                    }
                }
            }
            'EX-BP-120' {
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
                        $evidence = 'DevicePolicyRefreshInterval is Unlimited on the default mobile device mailbox policy; CIS L1 maximum is 1 day.'
                    }
                    else {
                        try {
                            $ts = [timespan]::Parse([string]$val)
                            $status = if ($ts.TotalDays -le 1) { 'Pass' } else { 'Fail' }
                            $evidence = ('DevicePolicyRefreshInterval is {0} hours on the default mobile device mailbox policy; CIS L1 maximum is 24 hours (1 day).' -f [math]::Round($ts.TotalHours, 2))
                        }
                        catch {
                            $status = 'Unknown'
                            $evidence = ('DevicePolicyRefreshInterval value could not be parsed: {0}' -f [string]$val)
                        }
                    }
                }
            }
            'EX-BP-121' {
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
            'EX-BP-122' {
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
            'EX-BP-123' {
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
            'EX-BP-153' {
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
                        $status = 'Pass'
                        $evidence = ('IRM is not in use (InternalLicensingEnabled={0}; ExternalLicensingEnabled={1}; AzureRMSLicensingEnabled={2}); AES256-CBC override is not required.' -f $internalEnabled, $externalEnabled, $azureEnabled)
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
            'EX-BP-124' {
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
                        $evidence = 'MaxInactivityTimeLock is Unlimited on the default mobile device mailbox policy; CIS L1 maximum is 15 minutes.'
                    }
                    else {
                        try {
                            $ts = [timespan]::Parse([string]$val)
                            $status = if ($ts.TotalMinutes -le 15) { 'Pass' } else { 'Fail' }
                            $evidence = ('MaxInactivityTimeLock is {0} minutes on the default mobile device mailbox policy; CIS L1 maximum is 15 minutes.' -f [math]::Round($ts.TotalMinutes, 1))
                        }
                        catch {
                            $status = 'Unknown'
                            $evidence = ('MaxInactivityTimeLock value could not be parsed: {0}' -f [string]$val)
                        }
                    }
                }
            }
            'EX-BP-141' {
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
            'EX-BP-158' {
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
            'EX-BP-157' {
                $totalDisabled = 0
                $allDisabled = @()
                $hasData = $false
                foreach ($srv in @($CollectionData.Servers)) {
                    if (($srv.PSObject.Properties.Name -contains 'CollectionError') -and -not [string]::IsNullOrWhiteSpace([string]$srv.CollectionError)) { continue }
                    if (-not (($srv.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $srv.Exchange -and
                            ($srv.Exchange.PSObject.Properties.Name -contains 'IsExchangeServer') -and [bool]$srv.Exchange.IsExchangeServer)) { continue }
                    if ($srv.Exchange.PSObject.Properties.Name -contains 'SingleItemRecoveryDisabledCount' -and $null -ne $srv.Exchange.SingleItemRecoveryDisabledCount) {
                        $hasData = $true
                        $totalDisabled += [int]$srv.Exchange.SingleItemRecoveryDisabledCount
                        if (($srv.Exchange.PSObject.Properties.Name -contains 'SingleItemRecoveryDisabledMailboxes') -and $null -ne $srv.Exchange.SingleItemRecoveryDisabledMailboxes) {
                            $allDisabled += @($srv.Exchange.SingleItemRecoveryDisabledMailboxes)
                        }
                    }
                }
                if (-not $hasData) {
                    $status = 'Unknown'
                    $evidence = 'Single Item Recovery mailbox data unavailable.'
                }
                elseif ($totalDisabled -eq 0) {
                    $status = 'Pass'
                    $evidence = 'Compliant — all user mailboxes have Single Item Recovery enabled.'
                }
                else {
                    $status = 'Fail'
                    $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} user mailbox(es) have Single Item Recovery disabled.' -f $totalDisabled) -Elements $allDisabled
                }
            }
            'EX-BP-036' {
                $exchServers = @($CollectionData.Servers | Where-Object {
                        ($_.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $_.Exchange -and
                        ($_.Exchange.PSObject.Properties.Name -contains 'IsExchangeServer') -and [bool]$_.Exchange.IsExchangeServer
                    })
                if ($exchServers.Count -eq 0) {
                    $status = 'Unknown'
                    $evidence = 'No Exchange server data available; auth certificate baseline cannot be evaluated.'
                }
                else {
                    $authCert = $null
                    foreach ($srv in $exchServers) {
                        if (($srv.Exchange.PSObject.Properties.Name -contains 'AuthCertificate') -and $null -ne $srv.Exchange.AuthCertificate) {
                            $authCert = $srv.Exchange.AuthCertificate
                            break
                        }
                    }
                    if ($null -eq $authCert) {
                        $status = 'Unknown'
                        $evidence = 'Exchange auth certificate telemetry unavailable.'
                    }
                    elseif (-not [bool]$authCert.Found) {
                        $status = 'Fail'
                        $evidence = ('Current auth certificate thumbprint not found in LocalMachine\My: {0}' -f [string]$authCert.Thumbprint)
                    }
                    else {
                        $daysRemaining = if ($authCert.PSObject.Properties.Name -contains 'DaysRemaining' -and $null -ne $authCert.DaysRemaining) { [int]$authCert.DaysRemaining } else { $null }
                        $status = if ([bool]$authCert.IsExpired -or ($null -ne $daysRemaining -and $daysRemaining -lt 30)) { 'Fail' } elseif ($null -ne $daysRemaining -and $daysRemaining -lt 60) { 'Unknown' } else { 'Pass' }
                        $evidence = if ($status -eq 'Pass') { ('Auth certificate valid; expires {0} ({1} days remaining).' -f [string]$authCert.NotAfter, [string]$daysRemaining) } else { ('Auth certificate {0}; expires: {1}; remaining days: {2}.' -f [string]$authCert.Thumbprint, [string]$authCert.NotAfter, [string]$daysRemaining) }
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
        'EX-BP-041',
        'EX-BP-008',
        'EX-BP-029',
        'EX-BP-010',
        'EX-BP-030',
        'EX-BP-052',
        'EX-BP-062',
        'EX-BP-001',
        'EX-BP-006',
        'EX-BP-051',
        'EX-BP-016',
        'EX-BP-015',
        'EX-BP-002',
        'EX-BP-068',
        'EX-BP-070',
        'EX-BP-071',
        'EX-BP-072',
        'EX-BP-073',
        'EX-BP-074',
        'EX-BP-075',
        'EX-BP-076',
        'EX-BP-079',
        'EX-BP-080',
        'EX-BP-081',
        'EX-BP-082',
        'EX-BP-086',
        'EX-BP-088',
        'EX-BP-089',
        'EX-BP-090',
        'EX-BP-091',
        'EX-BP-092',
        'EX-BP-093',
        'EX-BP-094',
        'EX-BP-101',
        'EX-BP-105',
        'EX-BP-106',
        'EX-BP-107',
        'EX-BP-108',
        'EX-BP-110',
        'EX-BP-112',
        'EX-BP-113',
        'EX-BP-125',
        'EX-BP-127',
        'EX-BP-128',
        'EX-BP-129',
        'EX-BP-130',
        'EX-BP-131',
        'EX-BP-133',
        'EX-BP-134',
        'EX-BP-135',
        'EX-BP-136',
        'EX-BP-137',
        'EX-BP-138',
        'EX-BP-140',
        'EX-BP-142',
        'EX-BP-143',
        'EX-BP-144',
        'EX-BP-145',
        'EX-BP-146',
        'EX-BP-147',
        'EX-BP-148',
        'EX-BP-149',
        'EX-BP-150',
        'EX-BP-151',
        'EX-BP-152',
        'EX-BP-154',
        'EX-BP-155',
        'EX-BP-156'
    )

    $exchangeBuilds = $null
    if ($Control.id -in @('EX-BP-008', 'EX-BP-149')) {
        $exchangeBuildsPath = Join-Path -Path $PSScriptRoot -ChildPath '..\Config\exchange.builds.json'
        if (Test-Path -LiteralPath $exchangeBuildsPath) {
            try { $exchangeBuilds = Get-Content -LiteralPath $exchangeBuildsPath -Raw | ConvertFrom-Json } catch {}
        }
    }

    foreach ($server in $CollectionData.Servers) {
        $serverName = ([string]$server.Server -split '\.')[0]
        if ($server.PSObject.Properties.Name -contains 'CollectionError') {
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

        if (($Control.id -in $exchangeOnlyControlIds) -and -not $isExchangeServer) {
            $serverResults += [pscustomobject]@{
                Server   = $serverName
                Status   = 'Skipped'
                Evidence = 'Exchange not detected on this server; control is not applicable.'
            }
            continue
        }

        switch ($Control.id) {
            'EX-BP-041' {
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
            'EX-BP-088' {
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
            'EX-BP-008' {
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
            'EX-BP-149' {
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
            'EX-BP-056' {
                $tls10 = [bool]$server.Tls.Tls10Enabled
                $tls11 = [bool]$server.Tls.Tls11Enabled
                $status = if (-not $tls10 -and -not $tls11) { 'Pass' } else { 'Fail' }
                $evidence = ('TLS 1.0 is {0}; TLS 1.1 is {1}.' -f
                    (Get-EDCAStateDescriptor -Value $tls10 -Expectation 'Disabled'),
                    (Get-EDCAStateDescriptor -Value $tls11 -Expectation 'Disabled'))
            }
            'EX-BP-057' {
                $status = Get-EDCAFindingStatusFromBool -Value $server.Tls.Tls12Enabled
                if ($null -eq $server.Tls.Tls12Enabled) {
                    $evidence = 'TLS 1.2 state unavailable.'
                }
                else {
                    $evidence = ('TLS 1.2 is {0}.' -f (Get-EDCAStateDescriptor -Value ([bool]$server.Tls.Tls12Enabled) -Expectation 'Enabled'))
                }
            }
            'EX-BP-029' {
                $expired = @($server.Certificates | Where-Object { $_.IsExpired })
                $status = if ($expired.Count -eq 0) { 'Pass' } else { 'Fail' }
                $summary = ('Expired certificates: {0}' -f $expired.Count)
                if ($expired.Count -gt 0) {
                    $expiredDetails = @($expired | ForEach-Object {
                            '{0} | Subject={1} | NotAfter={2}' -f [string]$_.Thumbprint, [string]$_.Subject, [string]$_.NotAfter
                        })
                    $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $expiredDetails
                }
                else {
                    $evidence = 'Compliant — no expired certificates found.'
                }
            }
            'EX-BP-010' {
                $problem = @($server.Services | Where-Object { $_.Status -ne 'Running' })
                $status = if ($problem.Count -eq 0) { 'Pass' } else { 'Fail' }
                $summary = ('Non-running required services: {0}' -f $problem.Count)
                if ($problem.Count -gt 0) {
                    $problemDetails = @($problem | ForEach-Object { '{0} status={1}' -f [string]$_.Name, [string]$_.Status })
                    $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $problemDetails
                }
                else {
                    $evidence = 'Compliant — all required Exchange services are running.'
                }
            }
            'EX-BP-030' {
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
            'EX-BP-053' {
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
            'EX-BP-017' {
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
            'EX-BP-025' {
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
            'EX-BP-023' {
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
            'EX-BP-018' {
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
            'EX-BP-028' {
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
                        $status = 'Pass'
                        $evidence = 'No VMXNET3 adapters found; control is not applicable to non-VMware environments.'
                    }
                    else {
                        $problemAdapters = @()
                        foreach ($adapter in $adapters) {
                            $adapterIssues = @()

                            $discardedPackets = 0
                            if ($adapter.PSObject.Properties.Name -contains 'DiscardedPacketsTotal') {
                                $discardedPackets = [int64]$adapter.DiscardedPacketsTotal
                            }
                            if ($discardedPackets -gt 0) {
                                $adapterIssues += ('discarded packets detected ({0})' -f $discardedPackets)
                            }

                            $hasRingProperties = $false
                            if ($adapter.PSObject.Properties.Name -contains 'HasRingProperties') {
                                $hasRingProperties = [bool]$adapter.HasRingProperties
                            }
                            if (-not $hasRingProperties) {
                                $adapterIssues += 'ring size advanced properties not found'
                            }

                            $hasBufferProperties = $false
                            if ($adapter.PSObject.Properties.Name -contains 'HasBufferProperties') {
                                $hasBufferProperties = [bool]$adapter.HasBufferProperties
                            }
                            if (-not $hasBufferProperties) {
                                $adapterIssues += 'buffer advanced properties not found'
                            }

                            if ($adapterIssues.Count -gt 0) {
                                $problemAdapters += ('{0}: {1}' -f [string]$adapter.Name, ($adapterIssues -join '; '))
                            }
                        }

                        if ($problemAdapters.Count -gt 0) {
                            # This is intentionally warning-oriented for BestPractice reporting.
                            $status = 'Unknown'
                            $summary = ('VMXNET3 adapters evaluated: {0}; warning conditions on {1} adapter(s).' -f $adapters.Count, $problemAdapters.Count)
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $problemAdapters
                        }
                        else {
                            $status = 'Pass'
                            $evidence = ('VMXNET3 adapters evaluated: {0}; no discarded packets and ring/buffer properties found.' -f $adapters.Count)
                        }
                    }
                }
            }
            'EX-BP-021' {
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
            'EX-BP-016' {
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
            'EX-BP-015' {
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

                        $nonCompliant = @()
                        $unknownDrives = @()
                        foreach ($dbDrive in $dbDrives) {
                            $matchedVolume = @($volumes | Where-Object { ([string]$_.DriveLetter).Equals($dbDrive, [System.StringComparison]::OrdinalIgnoreCase) } | Select-Object -First 1)
                            if ($matchedVolume.Count -eq 0) {
                                $unknownDrives += $dbDrive
                                continue
                            }

                            $blockSize = $matchedVolume[0].BlockSize
                            if ($null -eq $blockSize) {
                                $unknownDrives += $dbDrive
                                continue
                            }

                            if ([int64]$blockSize -ne 65536) {
                                $nonCompliant += ('{0}:{1}' -f $dbDrive, [int64]$blockSize)
                            }
                        }

                        if ($nonCompliant.Count -gt 0) {
                            $status = 'Fail'
                            $summary = 'Database/log volume block size should be 65536 (64KB).'
                            $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements $nonCompliant
                        }
                        elseif ($unknownDrives.Count -gt 0) {
                            $status = 'Unknown'
                            $evidence = ('Could not determine block size for drive(s): {0}' -f ($unknownDrives -join ', '))
                        }
                        else {
                            $status = 'Pass'
                            $evidence = ('Database/log drive block size validated at 65536 (64KB): {0}' -f ($dbDrives -join ', '))
                        }
                    }
                }
            }
            'EX-BP-049' {
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and ($server.Exchange.PSObject.Properties.Name -contains 'OAuth2ClientProfileEnabled') -and $null -ne $server.Exchange.OAuth2ClientProfileEnabled) {
                    $enabled = [bool]$server.Exchange.OAuth2ClientProfileEnabled
                    $status = if ($enabled) { 'Pass' } else { 'Fail' }
                    $evidence = ('OAuth2ClientProfileEnabled is {0}.' -f (Get-EDCAStateDescriptor -Value $enabled -Expectation 'Enabled'))
                }
                else {
                    $status = 'Unknown'
                    $evidence = 'Modern Authentication data unavailable.'
                }
            }
            'EX-BP-052' {
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
            'EX-BP-062' {
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
                                '{0} | PermissionGroups={1} | AuthMechanism={2}' -f [string]$_.Name, [string]$_.PermissionGroups, [string]$_.AuthMechanism
                            })
                        $evidence = Format-EDCAEvidenceWithElements -Summary $summary -Elements (@($missingPatterns) + @($connectorDetails))
                    }
                    else {
                        $evidence = ('Compliant — external and internal relay connector patterns detected ({0} connectors).' -f $connectors.Count)
                    }
                }
            }
            'EX-BP-001' {
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
            'EX-BP-006' {
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and ($server.Exchange.PSObject.Properties.Name -contains 'SharedMailboxTypeMismatchCount') -and $null -ne $server.Exchange.SharedMailboxTypeMismatchCount) {
                    $count = [int]$server.Exchange.SharedMailboxTypeMismatchCount
                    $status = if ($count -eq 0) { 'Pass' } else { 'Fail' }
                    $evidence = if ($count -eq 0) { 'Compliant — no shared-mailbox typing mismatches detected.' } else { ('Shared-mailbox typing mismatches: {0}' -f $count) }
                }
                else {
                    $status = 'Unknown'
                    $evidence = 'Mailbox type consistency data unavailable.'
                }
            }
            'EX-BP-051' {
                if (($server.PSObject.Properties.Name -contains 'Exchange') -and ($server.Exchange.PSObject.Properties.Name -contains 'OwaDownloadDomainsConfigured') -and $null -ne $server.Exchange.OwaDownloadDomainsConfigured) {
                    $configured = [bool]$server.Exchange.OwaDownloadDomainsConfigured
                    $status = if ($configured) { 'Pass' } else { 'Fail' }
                    $evidence = ('OWA Download Domains are {0}.' -f (Get-EDCAStateDescriptor -Value $configured -Expectation 'Configured'))
                }
                else {
                    $status = 'Unknown'
                    $evidence = 'OWA Download Domains data unavailable.'
                }
            }
            'EX-BP-055' {
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
            'EX-BP-061' {
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
            'EX-BP-046' {
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
            'EX-BP-047' {
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
            'EX-BP-058' {
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
            'EX-BP-065' {
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
                        $status = 'Unknown'
                        $evidence = ('Script block logging policy value unavailable. {0}' -f $osInfo.Evidence)
                    }
                    else {
                        $status = if ([bool]$enabled) { 'Pass' } else { 'Fail' }
                        $evidence = ('PowerShell Script Block Logging is {0}; {1}' -f
                            (Get-EDCAStateDescriptor -Value ([bool]$enabled) -Expectation 'Enabled'),
                            $osInfo.Evidence)
                    }
                }
            }
            'EX-BP-067' {
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
            'EX-BP-066' {
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
            'EX-BP-064' {
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
            'EX-BP-037' {
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
            'EX-BP-034' {
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
            'EX-BP-031' {
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
            'EX-BP-048' {
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
                            "$installPath\FrontEnd",
                            "$installPath\ClientAccess",
                            "$installPath\Logging",
                            "$installPath\TransportRoles",
                            "$installPath\FIP-FS",
                            "$installPath\Working"
                        )
                        if ($productLine -eq 'Exchange2016') {
                            $expectedDirs.Add("$installPath\UnifiedMessaging")
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
            'EX-BP-002' {
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
            'EX-BP-024' {
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
            'EX-BP-027' {
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
            'EX-BP-020' {
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
                    $status = 'Pass'
                    $evidence = 'NUMA group size optimization registry value is not configured; control treated as not applicable.'
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
            'EX-BP-022' {
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
            'EX-BP-045' {
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
            'EX-BP-026' {
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
            'EX-BP-019' {
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
            'EX-BP-013' {
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
            'EX-BP-054' {
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
            'EX-BP-011' {
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
                        $evidence = 'No Exchange setting overrides detected.'
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
            'EX-BP-044' {
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

                    $evidence = if ($status -eq 'Pass') { ('Compliant — internal transport certificate valid; expires {0} ({1} days remaining).' -f [string]$internalTransportCertificate.NotAfter, [string]$daysRemaining) } else { ('Internal transport certificate {0}; expires: {1}; remaining days: {2}' -f [string]$internalTransportCertificate.Thumbprint, [string]$internalTransportCertificate.NotAfter, [string]$daysRemaining) }
                }
            }
            'EX-BP-059' {
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
            'EX-BP-038' {
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
            'EX-BP-035' {
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
            'EX-BP-060' {
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
            'EX-BP-042' {
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
            'EX-BP-043' {
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
            'EX-BP-039' {
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
            'EX-BP-012' {
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
            'EX-BP-063' {
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
            'EX-BP-080' {
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
            'EX-BP-081' {
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
            'EX-BP-082' {
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
                    $evidence = ('MessageTrackingLogSubjectLoggingEnabled is {0}.' -f (Get-EDCAStateDescriptor -Value (-not $messageTrackingLogSubjectLoggingEnabled) -Expectation 'Disabled'))
                }
            }
            'EX-BP-014' {
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
            'EX-BP-068' {
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
            'EX-BP-070' {
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
            'EX-BP-089' {
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
            'EX-BP-090' {
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
            'EX-BP-091' {
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
            'EX-BP-071' {
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
            'EX-BP-072' {
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
            'EX-BP-073' {
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
            'EX-BP-074' {
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
            'EX-BP-075' {
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
            'EX-BP-076' {
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
            'EX-BP-079' {
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
            'EX-BP-092' {
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
            'EX-BP-093' {
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
            'EX-BP-094' {
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
            'EX-BP-101' {
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
            'EX-BP-105' {
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
            'EX-BP-106' {
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
            'EX-BP-107' {
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
            'EX-BP-108' {
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
            'EX-BP-110' {
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
            'EX-BP-112' {
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
            'EX-BP-113' {
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
            'EX-BP-136' {
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
            'EX-BP-137' {
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
            'EX-BP-138' {
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
                    if ($val -ne 20) {
                        $status = 'Fail'
                        $evidence = ('MaxPerDomainOutboundConnections is {0} (expected 20).' -f $val)
                    }
                    else {
                        $status = 'Pass'
                        $evidence = 'Compliant — MaxPerDomainOutboundConnections is 20.'
                    }
                }
            }
            'EX-BP-125' {
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
            'EX-BP-127' {
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
            'EX-BP-134' {
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
            'EX-BP-140' {
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
                    $required = @('Content Filter Agent', 'Sender Id Agent', 'Sender Reputation Filter Agent')
                    $missing = @()
                    $disabled = @()
                    foreach ($agentName in $required) {
                        $found = @($agents | Where-Object { [string]$_.Identity -eq $agentName })
                        if ($found.Count -eq 0) { $missing += $agentName }
                        elseif (-not [bool]$found[0].Enabled) { $disabled += $agentName }
                    }
                    if ($missing.Count -gt 0 -or $disabled.Count -gt 0) {
                        $status = 'Fail'
                        $issues = @()
                        if ($missing.Count -gt 0) { $issues += ('Missing agents: {0}' -f ($missing -join ', ')) }
                        if ($disabled.Count -gt 0) { $issues += ('Disabled agents: {0}' -f ($disabled -join ', ')) }
                        $evidence = Format-EDCAEvidenceWithElements -Summary 'One or more required anti-spam transport agents are missing or disabled.' -Elements $issues
                    }
                    else {
                        $status = 'Pass'
                        $evidence = 'All required anti-spam agents (Content Filter, Sender ID, Sender Reputation) are present and enabled.'
                    }
                }
            }
            'EX-BP-142' {
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
            'EX-BP-147' {
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
                    $revealing = @($connectors | Where-Object {
                            $banner = if ($_.PSObject.Properties.Name -contains 'Banner') { [string]$_.Banner } else { $null }
                            (-not [string]::IsNullOrWhiteSpace($banner)) -and ($banner -match '(?i)\bexchange\b|15\.[0-9]+\.[0-9]')
                        })
                    $emptyBanner = @($connectors | Where-Object {
                            -not ($_.PSObject.Properties.Name -contains 'Banner') -or [string]::IsNullOrWhiteSpace([string]$_.Banner)
                        })
                    if ($revealing.Count -gt 0) {
                        $status = 'Fail'
                        $details = @($revealing | ForEach-Object { ('{0}: Banner="{1}"' -f [string]$_.Identity, [string]$_.Banner) })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} receive connector(s) have an SMTP banner that reveals server identity.' -f $revealing.Count, $connectors.Count) -Elements $details
                    }
                    elseif ($emptyBanner.Count -gt 0) {
                        $status = 'Unknown'
                        $details = @($emptyBanner | ForEach-Object { [string]$_.Identity })
                        $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} receive connector(s) have no custom SMTP banner; the default banner may reveal software identity.' -f $emptyBanner.Count, $connectors.Count) -Elements $details
                    }
                    else {
                        $status = 'Pass'
                        $evidence = ('All {0} receive connector(s) have a custom SMTP banner that does not reveal server identity.' -f $connectors.Count)
                    }
                }
            }
            'EX-BP-148' {
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
            'EX-BP-150' {
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
            'EX-BP-151' {
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
            'EX-BP-152' {
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
            'EX-BP-154' {
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
            'EX-BP-155' {
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
                    $dbDrives = @($databaseStoragePaths | ForEach-Object {
                            if ([string]$_ -match '^([A-Za-z]:)') { $matches[1].ToUpperInvariant() }
                        } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
                    if ($dbDrives.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = 'Could not resolve drive letters from database or log storage paths.'
                    }
                    else {
                        $volumes = @()
                        if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and
                            ($server.OS.PSObject.Properties.Name -contains 'Volumes')) {
                            $volumes = @($server.OS.Volumes)
                        }
                        $notProtected = @()
                        $unmapped = @()
                        foreach ($drive in $dbDrives) {
                            $vol = @($volumes | Where-Object { ([string]$_.DriveLetter).TrimEnd('\').TrimEnd('/').Equals($drive, [System.StringComparison]::OrdinalIgnoreCase) }) | Select-Object -First 1
                            if ($null -eq $vol) { $unmapped += $drive; continue }
                            if (-not [bool]$vol.BitLockerProtected) { $notProtected += $drive }
                        }
                        if ($notProtected.Count -gt 0) {
                            $status = 'Fail'
                            $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} database or log volume(s) are not BitLocker-protected.' -f $notProtected.Count, $dbDrives.Count) -Elements $notProtected
                        }
                        elseif ($unmapped.Count -gt 0) {
                            $status = 'Unknown'
                            $evidence = ('Could not map the following drive(s) to volume metadata: {0}' -f ($unmapped -join ', '))
                        }
                        else {
                            $status = 'Pass'
                            $evidence = ('All database and log volumes are BitLocker-protected: {0}' -f ($dbDrives -join ', '))
                        }
                    }
                }
            }
            'EX-BP-156' {
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
                    $dbDrives = @($databaseStoragePaths | ForEach-Object {
                            if ([string]$_ -match '^([A-Za-z]:)') { $matches[1].ToUpperInvariant() }
                        } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
                    if ($dbDrives.Count -eq 0) {
                        $status = 'Unknown'
                        $evidence = 'Could not resolve drive letters from database or log storage paths.'
                    }
                    else {
                        $volumes = @()
                        if (($server.PSObject.Properties.Name -contains 'OS') -and $null -ne $server.OS -and
                            ($server.OS.PSObject.Properties.Name -contains 'Volumes')) {
                            $volumes = @($server.OS.Volumes)
                        }
                        $notReFS = @()
                        $unmapped = @()
                        foreach ($drive in $dbDrives) {
                            $vol = @($volumes | Where-Object { ([string]$_.DriveLetter).TrimEnd('\').TrimEnd('/').Equals($drive, [System.StringComparison]::OrdinalIgnoreCase) }) | Select-Object -First 1
                            if ($null -eq $vol) { $unmapped += $drive; continue }
                            if ([string]$vol.FileSystem -ne 'ReFS') { $notReFS += ('{0}: {1}' -f $drive, [string]$vol.FileSystem) }
                        }
                        if ($notReFS.Count -gt 0) {
                            $status = 'Fail'
                            $evidence = Format-EDCAEvidenceWithElements -Summary ('{0} of {1} database or log volume(s) are not formatted with ReFS.' -f $notReFS.Count, $dbDrives.Count) -Elements $notReFS
                        }
                        elseif ($unmapped.Count -gt 0) {
                            $status = 'Unknown'
                            $evidence = ('Could not map the following drive(s) to volume metadata: {0}' -f ($unmapped -join ', '))
                        }
                        else {
                            $status = 'Pass'
                            $evidence = ('All database and log volumes are formatted with ReFS: {0}' -f ($dbDrives -join ', '))
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

    $frameworks = @('Best Practice', 'CIS', 'CISA', 'ENISA', 'DISA')
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
            AnalysisTimestamp   = (Get-Date)
            ControlCount        = $Controls.Count
            EnabledControlCount = (@($Controls | Where-Object { $_.verify }).Count)
        }
        Scores   = $scores
        Findings = $findings
    }
}



