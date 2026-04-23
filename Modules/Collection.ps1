# Script:  Collection.ps1
# Synopsis: Part of EDCA (Exchange Deployment & Compliance Assessment)
#           https://github.com/michelderooij/EDCA
# Author:  Michel de Rooij
# Website: https://eightwone.com

Set-StrictMode -Version Latest

function Get-EDCARemoteTlsState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    $scriptBlock = {
        $paths = @{
            Tls10 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
            Tls11 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'
            Tls12 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
            Tls13 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server'
        }

        $result = @{}
        foreach ($key in $paths.Keys) {
            $enabled = $null
            if (Test-Path -Path $paths[$key]) {
                $item = Get-ItemProperty -Path $paths[$key] -ErrorAction SilentlyContinue
                $enabled = $item.Enabled
            }
            $result[$key] = $enabled
        }

        $tls13CipherSuiteAvailable = $null
        if ($null -eq $result.Tls13 -and (Get-Command -Name Get-TlsCipherSuite -ErrorAction SilentlyContinue)) {
            try {
                $tls13Suites = @(Get-TlsCipherSuite -ErrorAction SilentlyContinue | Where-Object { ($_.PSObject.Properties.Name -contains 'Protocol') -and [string]$_.Protocol -eq 'TLS 1.3' })
                $tls13CipherSuiteAvailable = ($tls13Suites.Count -gt 0)
            }
            catch {
            }
        }

        $tls13Enabled = $null
        $tls13EvidenceSource = 'Unknown'
        if ($null -ne $result.Tls13) {
            $tls13Enabled = ($result.Tls13 -eq 1)
            $tls13EvidenceSource = 'Registry'
        }
        elseif ($null -ne $tls13CipherSuiteAvailable) {
            $tls13Enabled = [bool]$tls13CipherSuiteAvailable
            $tls13EvidenceSource = 'CipherSuites'
        }

        return [pscustomobject]@{
            Tls10Enabled        = ($result.Tls10 -eq 1)
            Tls11Enabled        = ($result.Tls11 -eq 1)
            Tls12Enabled        = ($result.Tls12 -eq 1)
            Tls13Enabled        = $tls13Enabled
            Tls13EvidenceSource = $tls13EvidenceSource
            Raw                 = $result
        }
    }

    return Invoke-EDCAServerCommand -Server $Server -ScriptBlock $scriptBlock
}

function Get-EDCARemoteServiceState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $true)]
        [string[]]$ServiceNames
    )

    $scriptBlock = {
        param($ServiceNames)
        $services = @()
        foreach ($serviceName in $ServiceNames) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($null -eq $service) {
                $services += [pscustomobject]@{
                    Name   = $serviceName
                    Status = 'NotFound'
                }
                continue
            }

            $services += [pscustomobject]@{
                Name   = $service.Name
                Status = [string]$service.Status
            }
        }

        return $services
    }

    return Invoke-EDCAServerCommand -Server $Server -ScriptBlock $scriptBlock -ArgumentList (, $ServiceNames)
}

function Get-EDCARemoteCertificates {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    $scriptBlock = {
        $certs = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Select-Object -Property Subject, Thumbprint, NotAfter
        $output = @()
        foreach ($cert in $certs) {
            $output += [pscustomobject]@{
                Subject    = $cert.Subject
                Thumbprint = $cert.Thumbprint
                NotAfter   = $cert.NotAfter
                IsExpired  = ($cert.NotAfter -lt (Get-Date))
            }
        }

        return $output
    }

    return Invoke-EDCAServerCommand -Server $Server -ScriptBlock $scriptBlock
}

function Get-EDCACertificateStatusFromInventory {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Thumbprint,
        [AllowNull()]
        [object[]]$Certificates
    )

    $normalizedThumbprint = ''
    if (-not [string]::IsNullOrWhiteSpace($Thumbprint)) {
        $normalizedThumbprint = $Thumbprint.Trim().ToUpperInvariant()
    }

    if ([string]::IsNullOrWhiteSpace($normalizedThumbprint)) {
        return [pscustomobject]@{
            Thumbprint    = $null
            Found         = $false
            NotAfter      = $null
            IsExpired     = $null
            DaysRemaining = $null
        }
    }

    $matchedCertificate = @($Certificates | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_.Thumbprint) -and
            ([string]$_.Thumbprint).Trim().ToUpperInvariant() -eq $normalizedThumbprint
        } | Select-Object -First 1)

    if ($matchedCertificate.Count -eq 0) {
        return [pscustomobject]@{
            Thumbprint    = $normalizedThumbprint
            Found         = $false
            NotAfter      = $null
            IsExpired     = $null
            DaysRemaining = $null
        }
    }

    $notAfter = $null
    if ($null -ne $matchedCertificate[0].NotAfter) {
        $notAfter = [datetime]$matchedCertificate[0].NotAfter
    }
    $now = Get-Date
    return [pscustomobject]@{
        Thumbprint    = $normalizedThumbprint
        Found         = $true
        NotAfter      = $notAfter
        IsExpired     = ($notAfter -lt $now)
        DaysRemaining = [int][math]::Floor(($notAfter - $now).TotalDays)
    }
}

function Get-EDCAIntervalMinutes {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $null
    }

    if ($Value -is [TimeSpan]) {
        return [double]$Value.TotalMinutes
    }

    if ($Value.PSObject.Properties.Name -contains 'TotalMinutes' -and $null -ne $Value.TotalMinutes) {
        return [double]$Value.TotalMinutes
    }

    if ($Value.PSObject.Properties.Name -contains 'Ticks' -and $null -ne $Value.Ticks) {
        try {
            return [double]([TimeSpan]::FromTicks([int64]$Value.Ticks).TotalMinutes)
        }
        catch {
        }
    }

    if ($Value.PSObject.Properties.Name -contains 'TimeSpan' -and $null -ne $Value.TimeSpan) {
        $inner = Get-EDCAIntervalMinutes -Value $Value.TimeSpan
        if ($null -ne $inner) {
            return $inner
        }
    }

    $asTimeSpan = [TimeSpan]::Zero
    $valueText = [string]$Value
    if ([TimeSpan]::TryParse($valueText, [ref]$asTimeSpan)) {
        return [double]$asTimeSpan.TotalMinutes
    }

    $asDouble = 0.0
    if ([double]::TryParse($valueText, [ref]$asDouble)) {
        return $asDouble
    }

    return $null
}

function Get-EDCAExchangeServerInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    $scriptBlock = {
        $exchangeInfo = [pscustomobject]@{
            ExchangeCmdletsAvailable                 = $false
            Name                                     = $env:COMPUTERNAME
            AdminDisplayVersion                      = $null
            BuildNumber                              = $null
            Edition                                  = $null
            ProductLine                              = 'Unknown'
            IsExchangeServer                         = $false
            IsEdge                                   = $false
            ServerRole                               = 'Unknown'
            EdgeData                                 = $null
            ExtendedProtectionStatus                 = @()
            OutlookAnywhereSSLOffloading             = @()
            AdminAuditLogEnabled                     = $null
            ReplicationHealthPassed                  = $null
            IsDagMember                              = $null
            DagName                                  = $null
            AdSite                                   = $null
            SingleItemRecoveryDisabledCount          = $null
            SingleItemRecoveryDisabledMailboxes      = @()
            Pop3ServiceStatus                        = $null
            Imap4ServiceStatus                       = $null
            MapiHttpEnabled                          = $null
            ReceiveConnectors                        = @()
            UpnPrimarySmtpMismatchCount              = $null
            SharedMailboxTypeMismatchCount           = $null
            SharedMailboxTypeMismatches              = @()
            OwaDownloadDomainsConfigured             = $null
            OAuthHmaDownloadDomainOverrideConfigured = $null
            AlternateServiceAccount                  = $null
            DatabaseStoragePaths                     = @()
            CollectionWarnings                       = @()
        }

        $setupKey = 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup'
        $hasExchangeInstall = Test-Path -Path $setupKey
        if ($hasExchangeInstall) {
            $exchangeInfo.IsExchangeServer = $true
        }
        else {
            $exchangeInfo.CollectionWarnings += 'Exchange installation not detected on target server.'
        }

        $exchangeInstallPath = $null
        $exchangeBinPath = $null
        if ($hasExchangeInstall) {
            try {
                $setupForPath = Get-ItemProperty -Path $setupKey -ErrorAction SilentlyContinue
                $pathCandidates = @()

                if ($null -ne $setupForPath) {
                    if ($setupForPath.PSObject.Properties.Name -contains 'MsiInstallPath') {
                        $pathCandidates += [string]$setupForPath.MsiInstallPath
                    }
                    if ($setupForPath.PSObject.Properties.Name -contains 'InstallPath') {
                        $pathCandidates += [string]$setupForPath.InstallPath
                    }
                    if ($setupForPath.PSObject.Properties.Name -contains 'SetupBinPath') {
                        $pathCandidates += [string]$setupForPath.SetupBinPath
                    }
                }

                if (-not [string]::IsNullOrWhiteSpace([string]$env:ExchangeInstallPath)) {
                    $pathCandidates += [string]$env:ExchangeInstallPath
                }

                foreach ($pathCandidate in $pathCandidates) {
                    if ([string]::IsNullOrWhiteSpace($pathCandidate)) {
                        continue
                    }

                    $normalizedPath = $pathCandidate.Trim().Trim('"')
                    if (-not (Test-Path -Path $normalizedPath)) {
                        continue
                    }

                    $leaf = [string](Split-Path -Path $normalizedPath -Leaf)
                    if ($leaf.Equals('bin', [System.StringComparison]::OrdinalIgnoreCase)) {
                        $exchangeBinPath = $normalizedPath
                        $exchangeInstallPath = Split-Path -Path $normalizedPath -Parent
                    }
                    else {
                        $exchangeInstallPath = $normalizedPath
                        $candidateBinPath = Join-Path -Path $exchangeInstallPath -ChildPath 'bin'
                        if (Test-Path -Path $candidateBinPath) {
                            $exchangeBinPath = $candidateBinPath
                        }
                    }

                    if (-not [string]::IsNullOrWhiteSpace($exchangeInstallPath) -and -not [string]::IsNullOrWhiteSpace($exchangeBinPath)) {
                        break
                    }
                }
            }
            catch {
                $exchangeInfo.CollectionWarnings += ('Exchange install path resolution failed: ' + $_.Exception.Message)
            }

            if ([string]::IsNullOrWhiteSpace($exchangeBinPath)) {
                $exchangeInfo.CollectionWarnings += 'Exchange installation detected but bin path could not be resolved from setup registry.'
            }
        }

        if ($hasExchangeInstall -and -not (Get-Command -Name Get-ExchangeServer -ErrorAction SilentlyContinue)) {
            try {
                if ($exchangeBinPath) {
                    $exShellPsc1 = Join-Path -Path $exchangeBinPath -ChildPath 'exShell.psc1'
                    if (Test-Path -Path $exShellPsc1) {
                        [xml]$psSnapIns = Get-Content -Path $exShellPsc1 -ErrorAction Stop
                        foreach ($psSnapIn in $psSnapIns.PSConsoleFile.PSSnapIns.PSSnapIn) {
                            try {
                                Add-PSSnapin -Name $psSnapIn.Name -ErrorAction Stop
                            }
                            catch {
                                # Ignore already-loaded snap-ins.
                            }
                        }
                    }

                    $exchangePs1 = Join-Path -Path $exchangeBinPath -ChildPath 'Exchange.ps1'
                    if (Test-Path -Path $exchangePs1) {
                        Import-Module $exchangePs1 -ErrorAction SilentlyContinue
                    }
                }
            }
            catch {
                $exchangeInfo.CollectionWarnings += ('Exchange shell bootstrap failed: ' + $_.Exception.Message)
            }
        }

        if ($hasExchangeInstall -and -not (Get-Command -Name Get-ExchangeServer -ErrorAction SilentlyContinue)) {
            try {
                Add-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction Stop
            }
            catch {
            }
        }

        if ($hasExchangeInstall -and -not (Get-Command -Name Get-ExchangeServer -ErrorAction SilentlyContinue)) {
            try {
                $setup = Get-ItemProperty -Path $setupKey -ErrorAction Stop
                $major = $null
                $minor = $null
                $buildMajor = $null
                $buildMinor = $null

                if ($setup.PSObject.Properties.Name -contains 'MsiProductMajor') { $major = $setup.MsiProductMajor }
                if ($setup.PSObject.Properties.Name -contains 'MsiProductMinor') { $minor = $setup.MsiProductMinor }
                if ($setup.PSObject.Properties.Name -contains 'MsiBuildMajor') { $buildMajor = $setup.MsiBuildMajor }
                if ($setup.PSObject.Properties.Name -contains 'MsiBuildMinor') { $buildMinor = $setup.MsiBuildMinor }

                if ($null -ne $major -and $null -ne $minor -and $null -ne $buildMajor -and $null -ne $buildMinor) {
                    $exchangeInfo.AdminDisplayVersion = ('Version {0}.{1} (Build {2}.{3})' -f [int]$major, [int]$minor, [int]$buildMajor, [int]$buildMinor)
                }

                if (($setup.PSObject.Properties.Name -contains 'OwaVersion') -and -not [string]::IsNullOrWhiteSpace([string]$setup.OwaVersion)) {
                    $exchangeInfo.BuildNumber = [string]$setup.OwaVersion
                }

                if ($setup.PSObject.Properties.Name -contains 'Edition') {
                    $exchangeInfo.Edition = [string]$setup.Edition
                }

                if ($null -ne $major -and $null -ne $minor) {
                    if ([int]$major -eq 15 -and [int]$minor -eq 1) {
                        $exchangeInfo.ProductLine = 'Exchange2016'
                    }
                    elseif ([int]$major -eq 15 -and [int]$minor -eq 2) {
                        $isSe = $false
                        if ($setup.PSObject.Properties.Name -contains 'IsExchangeServerSubscriptionEdition') {
                            $isSe = [bool]$setup.IsExchangeServerSubscriptionEdition
                        }
                        if (-not $isSe -and $null -ne $buildMajor -and [int]$buildMajor -ge 2562) {
                            # Exchange SE builds can be identified by 15.2 build train even when explicit SE flags are unavailable.
                            $isSe = $true
                        }
                        $exchangeInfo.ProductLine = if ($isSe) { 'ExchangeSE' } else { 'Exchange2019' }
                    }
                }

                $exchangeInfo.CollectionWarnings += 'Exchange cmdlets unavailable; build metadata collected from setup registry.'
            }
            catch {
                $exchangeInfo.CollectionWarnings += ('Exchange setup registry fallback failed: ' + $_.Exception.Message)
            }
        }

        if (Get-Command -Name Get-ExchangeServer -ErrorAction SilentlyContinue) {
            $exchangeInfo.ExchangeCmdletsAvailable = $true
            try {
                $server = Get-ExchangeServer -Identity $env:COMPUTERNAME -ErrorAction Stop
                $exchangeInfo.IsExchangeServer = $true
                $exchangeInfo.Name = $server.Name
                $exchangeInfo.AdminDisplayVersion = [string]$server.AdminDisplayVersion
                $exchangeInfo.Edition = [string]$server.Edition
                $exchangeInfo.IsDagMember = ($server.PSObject.Properties.Name -contains 'MemberOfDAG') -and -not [string]::IsNullOrWhiteSpace([string]$server.MemberOfDAG)
                $exchangeInfo.DagName = if (($server.PSObject.Properties.Name -contains 'MemberOfDAG') -and -not [string]::IsNullOrWhiteSpace([string]$server.MemberOfDAG)) { [string]$server.MemberOfDAG } else { '' }
                $exchangeInfo.AdSite = if ($server.PSObject.Properties.Name -contains 'Site') { [string]$server.Site } else { '' }

                if ($exchangeInfo.AdminDisplayVersion -match 'Version 15\.1') {
                    $exchangeInfo.ProductLine = 'Exchange2016'
                }
                elseif ($exchangeInfo.AdminDisplayVersion -match 'Version 15\.2') {
                    $isSe = $false
                    if ($server.PSObject.Properties.Name -contains 'IsExchangeServerSubscriptionEdition') {
                        $isSe = [bool]$server.IsExchangeServerSubscriptionEdition
                    }
                    if (-not $isSe -and $exchangeInfo.AdminDisplayVersion -match 'Subscription|SE') {
                        $isSe = $true
                    }
                    if (-not $isSe -and $exchangeInfo.AdminDisplayVersion -match 'Build\s+(\d+)\.') {
                        if ([int]$matches[1] -ge 2562) {
                            $isSe = $true
                        }
                    }
                    $exchangeInfo.ProductLine = if ($isSe) { 'ExchangeSE' } else { 'Exchange2019' }
                }
            }
            catch {
                $exchangeInfo.CollectionWarnings += ('Get-ExchangeServer failed: ' + $_.Exception.Message)
            }

            $virtualDirectoryCommands = @(
                'Get-MapiVirtualDirectory',
                'Get-OwaVirtualDirectory',
                'Get-EcpVirtualDirectory',
                'Get-WebServicesVirtualDirectory',
                'Get-ActiveSyncVirtualDirectory',
                'Get-AutodiscoverVirtualDirectory'
            )

            foreach ($commandName in $virtualDirectoryCommands) {
                if (-not (Get-Command -Name $commandName -ErrorAction SilentlyContinue)) {
                    continue
                }

                try {
                    $items = & $commandName -Server $env:COMPUTERNAME -ErrorAction Stop
                    foreach ($item in $items) {
                        $exchangeInfo.ExtendedProtectionStatus += [pscustomobject]@{
                            VirtualDirectoryType            = $commandName
                            Identity                        = [string]$item.Identity
                            ExtendedProtectionTokenChecking = [string]$item.ExtendedProtectionTokenChecking
                            ExtendedProtectionFlags         = [string]$item.ExtendedProtectionFlags
                            ExtendedProtectionSPNList       = [string]$item.ExtendedProtectionSPNList
                            InternalAuthenticationMethods   = if ($item.PSObject.Properties.Name -contains 'InternalAuthenticationMethods') { [string]$item.InternalAuthenticationMethods } else { '' }
                            ExternalAuthenticationMethods   = if ($item.PSObject.Properties.Name -contains 'ExternalAuthenticationMethods') { [string]$item.ExternalAuthenticationMethods } else { '' }
                            IISAuthenticationMethods        = if ($item.PSObject.Properties.Name -contains 'IISAuthenticationMethods') { [string]$item.IISAuthenticationMethods } else { '' }
                        }
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('{0} failed: {1}' -f $commandName, $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-AdminAuditLogConfig -ErrorAction SilentlyContinue) {
                try {
                    $audit = Get-AdminAuditLogConfig -ErrorAction Stop
                    $exchangeInfo.AdminAuditLogEnabled = [bool]$audit.AdminAuditLogEnabled
                    if ($audit.PSObject.Properties.Name -contains 'AdminAuditLogPath' -and -not [string]::IsNullOrWhiteSpace([string]$audit.AdminAuditLogPath)) {
                        $exchangeInfo.AuditLogPath = [string]$audit.AdminAuditLogPath
                        try {
                            $auditLogAcl = Get-Acl -Path $exchangeInfo.AuditLogPath -ErrorAction Stop
                            $exchangeInfo.AuditLogPathAcl = @($auditLogAcl.Access | ForEach-Object {
                                    [pscustomobject]@{
                                        IdentityReference = [string]$_.IdentityReference
                                        FileSystemRights  = [string]$_.FileSystemRights
                                        AccessControlType = [string]$_.AccessControlType
                                        IsInherited       = [bool]$_.IsInherited
                                    }
                                })
                        }
                        catch {
                            $exchangeInfo.CollectionWarnings += ('Get-Acl for AuditLogPath failed: ' + $_.Exception.Message)
                        }
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-AdminAuditLogConfig failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-OutlookAnywhere -ErrorAction SilentlyContinue) {
                try {
                    $oaItems = @(Get-OutlookAnywhere -Server $env:COMPUTERNAME -ErrorAction Stop)
                    foreach ($oaItem in $oaItems) {
                        $exchangeInfo.OutlookAnywhereSSLOffloading += [pscustomobject]@{
                            Identity      = [string]$oaItem.Identity
                            SSLOffloading = if ($oaItem.PSObject.Properties.Name -contains 'SSLOffloading') { [nullable[bool]]$oaItem.SSLOffloading } else { $null }
                        }
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-OutlookAnywhere failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-MapiVirtualDirectory -ErrorAction SilentlyContinue) {
                try {
                    $mapiVirtualDirectories = @(Get-MapiVirtualDirectory -Server $env:COMPUTERNAME -ErrorAction Stop)
                    if ($mapiVirtualDirectories.Count -gt 0) {
                        $enabledCount = @($mapiVirtualDirectories | Where-Object { $null -ne $_.IISAuthenticationMethods }).Count
                        $exchangeInfo.MapiHttpEnabled = ($enabledCount -gt 0)
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-MapiVirtualDirectory (MAPI/HTTP) failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-ReceiveConnector -ErrorAction SilentlyContinue) {
                try {
                    $connectors = @(Get-ReceiveConnector -Server $env:COMPUTERNAME -ErrorAction Stop)
                    foreach ($connector in $connectors) {
                        $exchangeInfo.ReceiveConnectors += [pscustomobject]@{
                            Identity                 = [string]$connector.Identity
                            PermissionGroups         = [string]$connector.PermissionGroups
                            AuthMechanism            = [string]$connector.AuthMechanism
                            RemoteIPRangesCount      = @($connector.RemoteIPRanges).Count
                            Enabled                  = if ($connector.PSObject.Properties.Name -contains 'Enabled') { [bool]$connector.Enabled } else { $null }
                            TransportRole            = if ($connector.PSObject.Properties.Name -contains 'TransportRole') { [string]$connector.TransportRole } else { $null }
                            TlsDomainCapabilities    = if ($connector.PSObject.Properties.Name -contains 'TlsDomainCapabilities') { [string]$connector.TlsDomainCapabilities } else { $null }
                            CloudServicesMailEnabled = if ($connector.PSObject.Properties.Name -contains 'CloudServicesMailEnabled') { [bool]$connector.CloudServicesMailEnabled } else { $null }
                        }
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-ReceiveConnector failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-SendConnector -ErrorAction SilentlyContinue) {
                try {
                    $sendConnectors = @(Get-SendConnector -ErrorAction Stop)
                    foreach ($connector in $sendConnectors) {
                        $smartHosts = @()
                        if ($connector.PSObject.Properties.Name -contains 'SmartHosts' -and $null -ne $connector.SmartHosts) {
                            $smartHosts = @($connector.SmartHosts | ForEach-Object { [string]$_ })
                        }

                        $addressSpaces = @()
                        if ($connector.PSObject.Properties.Name -contains 'AddressSpaces' -and $null -ne $connector.AddressSpaces) {
                            $addressSpaces = @($connector.AddressSpaces | ForEach-Object {
                                    if ($_.PSObject.Properties.Name -contains 'Address') { [string]$_.Address } else { [string]$_ }
                                })
                        }

                        $tlsCertificateName = $null
                        if ($connector.PSObject.Properties.Name -contains 'TlsCertificateName' -and $null -ne $connector.TlsCertificateName) {
                            $tlsCertificateName = [string]$connector.TlsCertificateName
                        }

                        $tlsCertificateSyntaxValid = $null
                        if (-not [string]::IsNullOrWhiteSpace($tlsCertificateName)) {
                            $tlsCertificateSyntaxValid = ($tlsCertificateName -match '(?i)(<I>).*(<S>).*')
                        }

                        $exchangeInfo.SendConnectors += [pscustomobject]@{
                            Identity                    = [string]$connector.Identity
                            Enabled                     = if ($connector.PSObject.Properties.Name -contains 'Enabled') { [bool]$connector.Enabled } else { $null }
                            CloudServicesMailEnabled    = if ($connector.PSObject.Properties.Name -contains 'CloudServicesMailEnabled') { [bool]$connector.CloudServicesMailEnabled } else { $null }
                            TlsAuthLevel                = if ($connector.PSObject.Properties.Name -contains 'TlsAuthLevel') { [string]$connector.TlsAuthLevel } else { $null }
                            RequireTLS                  = if ($connector.PSObject.Properties.Name -contains 'RequireTLS') { [bool]$connector.RequireTLS } else { $null }
                            TlsCertificateName          = $tlsCertificateName
                            TlsCertificateSyntaxValid   = $tlsCertificateSyntaxValid
                            TlsDomain                   = if ($connector.PSObject.Properties.Name -contains 'TlsDomain') { [string]$connector.TlsDomain } else { $null }
                            Fqdn                        = if ($connector.PSObject.Properties.Name -contains 'Fqdn' -and $null -ne $connector.Fqdn) { [string]$connector.Fqdn } else { $null }
                            SmartHosts                  = $smartHosts
                            AddressSpaces               = $addressSpaces
                            ConnectionInactivityTimeOut = if ($connector.PSObject.Properties.Name -contains 'ConnectionInactivityTimeOut' -and $null -ne $connector.ConnectionInactivityTimeOut) { [string]$connector.ConnectionInactivityTimeOut } else { $null }
                            DNSRoutingEnabled           = if ($connector.PSObject.Properties.Name -contains 'DNSRoutingEnabled') { [bool]$connector.DNSRoutingEnabled } else { $null }
                            IgnoreStartTLS              = if ($connector.PSObject.Properties.Name -contains 'IgnoreStartTLS') { [bool]$connector.IgnoreStartTLS } else { $null }
                        }
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-SendConnector failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-OwaVirtualDirectory -ErrorAction SilentlyContinue) {
                try {
                    $owas = @(Get-OwaVirtualDirectory -Server $env:COMPUTERNAME -ErrorAction Stop)
                    if ($owas.Count -gt 0) {
                        $withDownloadDomains = @($owas | Where-Object {
                                $_.PSObject.Properties.Name -contains 'DownloadDomains' -and
                                -not [string]::IsNullOrWhiteSpace([string]$_.DownloadDomains)
                            }).Count
                        $exchangeInfo.OwaDownloadDomainsConfigured = ($withDownloadDomains -gt 0)
                        $withSmime = @($owas | Where-Object {
                                $_.PSObject.Properties.Name -contains 'SMIMEEnabled' -and [bool]$_.SMIMEEnabled
                            }).Count
                        $exchangeInfo.OwaSmimeEnabled = ($withSmime -gt 0)
                        $exchangeInfo.OwaFormsAuthentication = @($owas | ForEach-Object {
                                [pscustomobject]@{
                                    Identity            = [string]$_.Identity
                                    FormsAuthentication = if ($_.PSObject.Properties.Name -contains 'FormsAuthentication') { [bool]$_.FormsAuthentication } else { $null }
                                }
                            })
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-OwaVirtualDirectory (Download Domains) failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-EventLogLevel -ErrorAction SilentlyContinue) {
                try {
                    $exchangeInfo.EventLogLevels = @(Get-EventLogLevel -ErrorAction Stop | ForEach-Object {
                            [pscustomobject]@{
                                Identity   = [string]$_.Identity
                                EventLevel = [string]$_.EventLevel
                            }
                        })
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-EventLogLevel failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-RpcClientAccess -ErrorAction SilentlyContinue) {
                try {
                    $rpcAccess = Get-RpcClientAccess -Server $env:COMPUTERNAME -ErrorAction Stop
                    if ($null -ne $rpcAccess) {
                        $exchangeInfo.RpcClientAccessConfig = [pscustomobject]@{
                            EncryptionRequired = if ($rpcAccess.PSObject.Properties.Name -contains 'EncryptionRequired') { [bool]$rpcAccess.EncryptionRequired } else { $null }
                        }
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-RpcClientAccess failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-Mailbox -ErrorAction SilentlyContinue) {
                try {
                    $mailboxes = @(Get-Mailbox -ResultSize Unlimited -ErrorAction Stop)
                    $mismatchedUpn = @($mailboxes | Where-Object {
                            $_.RecipientTypeDetails -eq 'UserMailbox' -and
                            -not [string]::IsNullOrWhiteSpace([string]$_.UserPrincipalName) -and
                            -not [string]::IsNullOrWhiteSpace([string]$_.WindowsEmailAddress) -and
                            -not [string]::Equals([string]$_.UserPrincipalName, [string]$_.WindowsEmailAddress, [System.StringComparison]::OrdinalIgnoreCase)
                        })
                    $exchangeInfo.UpnPrimarySmtpMismatchCount = $mismatchedUpn.Count

                    $sharedLikeNames = @($mailboxes | Where-Object {
                            $_.RecipientTypeDetails -ne 'UserMailbox' -and
                            ($_.PSObject.Properties.Name -contains 'AccountDisabled') -and
                            -not [bool]$_.AccountDisabled
                        })
                    $exchangeInfo.SharedMailboxTypeMismatchCount = $sharedLikeNames.Count
                    $exchangeInfo.SharedMailboxTypeMismatches = @($sharedLikeNames | ForEach-Object { [string]$_.DisplayName })

                    $sirDisabled = @($mailboxes | Where-Object {
                            $_.RecipientTypeDetails -eq 'UserMailbox' -and
                            ($_.PSObject.Properties.Name -contains 'SingleItemRecoveryEnabled') -and
                            -not [bool]$_.SingleItemRecoveryEnabled
                        })
                    $exchangeInfo.SingleItemRecoveryDisabledCount = $sirDisabled.Count
                    $exchangeInfo.SingleItemRecoveryDisabledMailboxes = @($sirDisabled | ForEach-Object { [string]$_.DisplayName })
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-Mailbox baseline checks failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-MailboxDatabase -ErrorAction SilentlyContinue) {
                try {
                    $mailboxDatabases = @(Get-MailboxDatabase -Server $env:COMPUTERNAME -ErrorAction Stop)
                    $storagePathSet = @{}
                    foreach ($mailboxDatabase in $mailboxDatabases) {
                        $candidatePaths = @()
                        if ($mailboxDatabase.PSObject.Properties.Name -contains 'EdbFilePath' -and $null -ne $mailboxDatabase.EdbFilePath) {
                            $candidatePaths += [string]$mailboxDatabase.EdbFilePath
                        }
                        if ($mailboxDatabase.PSObject.Properties.Name -contains 'LogFolderPath' -and $null -ne $mailboxDatabase.LogFolderPath) {
                            $candidatePaths += [string]$mailboxDatabase.LogFolderPath
                        }

                        foreach ($candidatePath in $candidatePaths) {
                            if ([string]::IsNullOrWhiteSpace($candidatePath)) {
                                continue
                            }

                            $normalizedPath = $candidatePath.Trim()
                            if (-not $storagePathSet.ContainsKey($normalizedPath)) {
                                $storagePathSet[$normalizedPath] = $true
                                $exchangeInfo.DatabaseStoragePaths += $normalizedPath
                            }
                        }
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-MailboxDatabase storage path checks failed: ' + $_.Exception.Message)
                }
            }

            try {
                $popService = Get-Service -Name MSExchangePOP3 -ErrorAction SilentlyContinue
                if ($null -ne $popService) {
                    $exchangeInfo.Pop3ServiceStatus = [string]$popService.Status
                }
            }
            catch {
            }

            try {
                $imapService = Get-Service -Name MSExchangeIMAP4 -ErrorAction SilentlyContinue
                if ($null -ne $imapService) {
                    $exchangeInfo.Imap4ServiceStatus = [string]$imapService.Status
                }
            }
            catch {
            }

            if ((Get-Command -Name Get-ClientAccessService -ErrorAction SilentlyContinue) -or (Get-Command -Name Get-ClientAccessServer -ErrorAction SilentlyContinue)) {
                try {
                    $clientAccessService = $null
                    $asaSourceCommand = $null

                    if (Get-Command -Name Get-ClientAccessService -ErrorAction SilentlyContinue) {
                        $asaSourceCommand = 'Get-ClientAccessService'
                        $clientAccessService = Get-ClientAccessService -Identity $env:COMPUTERNAME -ErrorAction Stop
                    }
                    else {
                        $asaSourceCommand = 'Get-ClientAccessServer'
                        $clientAccessService = Get-ClientAccessServer -Identity $env:COMPUTERNAME -IncludeAlternateServiceAccountCredentialStatus -ErrorAction Stop
                    }

                    $asaConfiguration = $null
                    if ($null -ne $clientAccessService -and ($clientAccessService.PSObject.Properties.Name -contains 'AlternateServiceAccountConfiguration')) {
                        $asaConfiguration = $clientAccessService.AlternateServiceAccountConfiguration
                    }

                    $effectiveCredentials = @()
                    $latestCredential = $null
                    $previousCredential = $null
                    $asaConfigurationText = if ($null -eq $asaConfiguration) { '' } else { [string]$asaConfiguration }

                    if ($null -ne $asaConfiguration -and ($asaConfiguration.PSObject.Properties.Name -contains 'EffectiveCredentials') -and $null -ne $asaConfiguration.EffectiveCredentials) {
                        $effectiveCredentials = @($asaConfiguration.EffectiveCredentials | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)
                    }

                    if ($null -ne $asaConfiguration -and ($asaConfiguration.PSObject.Properties.Name -contains 'Latest') -and $null -ne $asaConfiguration.Latest) {
                        $latestCredential = [string]$asaConfiguration.Latest
                    }

                    if ($null -ne $asaConfiguration -and ($asaConfiguration.PSObject.Properties.Name -contains 'Previous') -and $null -ne $asaConfiguration.Previous) {
                        $previousCredential = [string]$asaConfiguration.Previous
                    }

                    if ($effectiveCredentials.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($asaConfigurationText)) {
                        $credentialMatches = [regex]::Matches($asaConfigurationText, '(?im)\b[0-9a-zA-Z\.\-_]+\\[0-9a-zA-Z\.\-_\$]+\b')
                        foreach ($credentialMatch in $credentialMatches) {
                            $credentialValue = [string]$credentialMatch.Value
                            if (-not [string]::IsNullOrWhiteSpace($credentialValue) -and ($effectiveCredentials -notcontains $credentialValue)) {
                                $effectiveCredentials += $credentialValue
                            }
                        }
                    }

                    if ([string]::IsNullOrWhiteSpace($latestCredential) -and -not [string]::IsNullOrWhiteSpace($asaConfigurationText)) {
                        $latestMatch = [regex]::Match($asaConfigurationText, '(?im)Latest\s*:\s*[^,]+,\s*([0-9a-zA-Z\.\-_]+\\[0-9a-zA-Z\.\-_\$]+)')
                        if ($latestMatch.Success) {
                            $latestCredential = [string]$latestMatch.Groups[1].Value
                        }
                    }

                    if ([string]::IsNullOrWhiteSpace($previousCredential) -and -not [string]::IsNullOrWhiteSpace($asaConfigurationText)) {
                        $previousMatch = [regex]::Match($asaConfigurationText, '(?im)Previous\s*:\s*[^,]+,\s*([0-9a-zA-Z\.\-_]+\\[0-9a-zA-Z\.\-_\$]+)')
                        if ($previousMatch.Success) {
                            $previousCredential = [string]$previousMatch.Groups[1].Value
                        }
                    }

                    $configured = $false
                    if ($effectiveCredentials.Count -gt 0) {
                        $configured = $true
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($latestCredential) -or -not [string]::IsNullOrWhiteSpace($previousCredential)) {
                        $configured = $true
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($asaConfigurationText) -and $asaConfigurationText -match '(?i)latest\s*:') {
                        $configured = $true
                    }

                    $exchangeInfo.AlternateServiceAccount = [pscustomobject]@{
                        QuerySucceeded     = $true
                        SourceCommand      = $asaSourceCommand
                        Configured         = $configured
                        CredentialCount    = @($effectiveCredentials).Count
                        Credentials        = @($effectiveCredentials | Sort-Object -Unique)
                        LatestCredential   = $latestCredential
                        PreviousCredential = $previousCredential
                        RawConfiguration   = $asaConfigurationText
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-ClientAccessService/Get-ClientAccessServer (ASA) failed: ' + $_.Exception.Message)
                    $exchangeInfo.AlternateServiceAccount = [pscustomobject]@{
                        QuerySucceeded     = $false
                        SourceCommand      = 'Get-ClientAccessService/Get-ClientAccessServer'
                        Configured         = $null
                        CredentialCount    = 0
                        Credentials        = @()
                        LatestCredential   = $null
                        PreviousCredential = $null
                        RawConfiguration   = $null
                    }
                }
            }

            if (Get-Command -Name Test-ReplicationHealth -ErrorAction SilentlyContinue) {
                try {
                    $replication = Test-ReplicationHealth -Identity $env:COMPUTERNAME -ErrorAction Stop
                    $failed = $replication | Where-Object { $_.Result -ne 'Passed' }
                    $exchangeInfo.ReplicationHealthPassed = ($failed.Count -eq 0)
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Test-ReplicationHealth failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-AuthConfig -ErrorAction SilentlyContinue) {
                try {
                    $authConfig = Get-AuthConfig -ErrorAction Stop
                    $authCertificateThumbprint = $null
                    if ($authConfig.PSObject.Properties.Name -contains 'CurrentCertificateThumbprint') {
                        $authCertificateThumbprint = [string]$authConfig.CurrentCertificateThumbprint
                    }
                    $exchangeInfo.AuthCertificate = Get-EDCACertificateStatus -Thumbprint $authCertificateThumbprint -Certificates $certificates
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-AuthConfig failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-TransportService -ErrorAction SilentlyContinue) {
                try {
                    $transportService = Get-TransportService -Identity $env:COMPUTERNAME -ErrorAction Stop

                    $maxOutboundConnections = $null
                    if ($transportService.PSObject.Properties.Name -contains 'MaxOutboundConnections' -and $null -ne $transportService.MaxOutboundConnections) {
                        $mocStr = [string]$transportService.MaxOutboundConnections
                        if ($mocStr -ne 'Unlimited') { try { $maxOutboundConnections = [int]$mocStr } catch {} } else { $maxOutboundConnections = -1 }
                    }

                    $maxPerDomainOutboundConnections = $null
                    if ($transportService.PSObject.Properties.Name -contains 'MaxPerDomainOutboundConnections' -and $null -ne $transportService.MaxPerDomainOutboundConnections) {
                        $mpdocStr = [string]$transportService.MaxPerDomainOutboundConnections
                        if ($mpdocStr -ne 'Unlimited') { try { $maxPerDomainOutboundConnections = [int]$mpdocStr } catch {} } else { $maxPerDomainOutboundConnections = -1 }
                    }

                    $messageRetryIntervalMinutes = $null
                    if ($transportService.PSObject.Properties.Name -contains 'MessageRetryInterval' -and $null -ne $transportService.MessageRetryInterval) {
                        $messageRetryIntervalMinutes = Get-EDCAIntervalMinutes -Value $transportService.MessageRetryInterval
                    }

                    $connectivityLogEnabled = $null
                    if ($transportService.PSObject.Properties.Name -contains 'ConnectivityLogEnabled') {
                        $connectivityLogEnabled = [bool]$transportService.ConnectivityLogEnabled
                    }

                    $messageTrackingLogEnabled = $null
                    if ($transportService.PSObject.Properties.Name -contains 'MessageTrackingLogEnabled') {
                        $messageTrackingLogEnabled = [bool]$transportService.MessageTrackingLogEnabled
                    }

                    $messageTrackingLogSubjectLoggingEnabled = $null
                    if ($transportService.PSObject.Properties.Name -contains 'MessageTrackingLogSubjectLoggingEnabled') {
                        $messageTrackingLogSubjectLoggingEnabled = [bool]$transportService.MessageTrackingLogSubjectLoggingEnabled
                    }

                    $pickupDirectoryPath = $null
                    if ($transportService.PSObject.Properties.Name -contains 'PickupDirectoryPath' -and -not [string]::IsNullOrWhiteSpace([string]$transportService.PickupDirectoryPath)) {
                        $pickupDirectoryPath = [string]$transportService.PickupDirectoryPath
                    }

                    $exchangeInfo.TransportRetryConfig = [pscustomobject]@{
                        MaxOutboundConnections                  = $maxOutboundConnections
                        MaxPerDomainOutboundConnections         = $maxPerDomainOutboundConnections
                        MessageRetryIntervalMinutes             = $messageRetryIntervalMinutes
                        ConnectivityLogEnabled                  = $connectivityLogEnabled
                        MessageTrackingLogEnabled               = $messageTrackingLogEnabled
                        MessageTrackingLogSubjectLoggingEnabled = $messageTrackingLogSubjectLoggingEnabled
                        PickupDirectoryPath                     = $pickupDirectoryPath
                    }

                    $internalTransportCertificateThumbprint = $null
                    if ($transportService.PSObject.Properties.Name -contains 'InternalTransportCertificateThumbprint') {
                        $internalTransportCertificateThumbprint = [string]$transportService.InternalTransportCertificateThumbprint
                    }
                    $exchangeInfo.InternalTransportCertificate = Get-EDCACertificateStatus -Thumbprint $internalTransportCertificateThumbprint -Certificates $certificates
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-TransportService failed: ' + $_.Exception.Message)
                }
            }

            $settingOverrides = @()
            if (Get-Command -Name Get-SettingOverride -ErrorAction SilentlyContinue) {
                try {
                    $settingOverrides = @(Get-SettingOverride -ErrorAction Stop)
                    $settingOverrideNames = @($settingOverrides | ForEach-Object { [string]$_.Name } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)
                    $settingOverrideDetails = @($settingOverrides | ForEach-Object {
                            $n = if ($_.PSObject.Properties.Name -contains 'Name') { [string]$_.Name } else { '' }
                            $s = if (($_.PSObject.Properties.Name -contains 'Server') -and ($null -ne $_.Server)) { [string]$_.Server } else { '' }
                            [pscustomobject]@{ Name = $n; Server = $s }
                        } | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) })
                    $exchangeInfo.SettingOverrides = [pscustomobject]@{
                        Count   = $settingOverrides.Count
                        Names   = $settingOverrideNames
                        Details = $settingOverrideDetails
                    }

                    if ($null -ne $exchangeInfo.Amsi) {
                        $amsiDisabledBySettingOverride = @($settingOverrides | Where-Object {
                                $componentName = if ($_.PSObject.Properties.Name -contains 'ComponentName') { [string]$_.ComponentName } else { '' }
                                $sectionName = if ($_.PSObject.Properties.Name -contains 'SectionName') { [string]$_.SectionName } else { '' }
                                $parametersText = ''
                                if ($_.PSObject.Properties.Name -contains 'Parameters' -and $null -ne $_.Parameters) {
                                    $parametersText = [string]::Join(';', @($_.Parameters | ForEach-Object { [string]$_ }))
                                }

                                $componentName -eq 'Cafe' -and
                                $sectionName -eq 'HttpRequestFiltering' -and
                                $parametersText -match 'Enabled\s*=\s*false'
                            }).Count -gt 0

                        $exchangeInfo.Amsi = [pscustomobject]@{
                            ProviderCount             = $exchangeInfo.Amsi.ProviderCount
                            ProviderIds               = $exchangeInfo.Amsi.ProviderIds
                            DisabledBySettingOverride = $amsiDisabledBySettingOverride
                        }
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-SettingOverride failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-AuthServer -ErrorAction SilentlyContinue) {
                try {
                    $sharedExchangeOnlineAppId = '00000002-0000-0ff1-ce00-000000000000'
                    $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

                    $authServers = @(Get-AuthServer -ErrorAction Stop)
                    $evoStsAuthServers = @($authServers | Where-Object {
                            $_.PSObject.Properties.Name -contains 'Name' -and
                            $_.PSObject.Properties.Name -contains 'Type' -and
                            $_.PSObject.Properties.Name -contains 'Enabled' -and
                            ([string]$_.Name -like 'EvoSTS*') -and
                            ([string]$_.Type -eq 'AzureAD') -and
                            [bool]$_.Enabled
                        })

                    $acsAuthServers = @($authServers | Where-Object {
                            $_.PSObject.Properties.Name -contains 'Type' -and
                            $_.PSObject.Properties.Name -contains 'Enabled' -and
                            ([string]$_.Type -eq 'MicrosoftACS') -and
                            [bool]$_.Enabled
                        })

                    $exchangeOnlinePartnerApplication = @()
                    if (Get-Command -Name Get-PartnerApplication -ErrorAction SilentlyContinue) {
                        $partnerApplications = @(Get-PartnerApplication -ErrorAction SilentlyContinue)
                        $exchangeOnlinePartnerApplication = @($partnerApplications | Where-Object {
                                $applicationIdentifier = if ($_.PSObject.Properties.Name -contains 'ApplicationIdentifier') { [string]$_.ApplicationIdentifier } else { '' }
                                $enabled = if ($_.PSObject.Properties.Name -contains 'Enabled') { [bool]$_.Enabled } else { $true }

                                $enabled -and ($applicationIdentifier -eq $sharedExchangeOnlineAppId)
                            })
                    }

                    $enabledHybridPartnerApplication = ($exchangeOnlinePartnerApplication.Count -gt 0)

                    $oAuthConfigured = ((($evoStsAuthServers.Count -or $acsAuthServers.Count) -gt 0) -and ($exchangeOnlinePartnerApplication.Count -gt 0))

                    $dedicatedHybridAppOverrides = @($settingOverrides | Where-Object {
                            $componentName = if ($_.PSObject.Properties.Name -contains 'ComponentName') { [string]$_.ComponentName } else { '' }
                            $sectionName = if ($_.PSObject.Properties.Name -contains 'SectionName') { [string]$_.SectionName } else { '' }
                            $componentName -eq 'Global' -and $sectionName -eq 'ExchangeOnpremAsThirdPartyAppId'
                        })

                    $sharedAppAuthServers = @($evoStsAuthServers | Where-Object {
                            ([string]$_.ApplicationIdentifier) -eq $sharedExchangeOnlineAppId
                        })

                    $dedicatedAppAuthServers = @($evoStsAuthServers | Where-Object {
                            $applicationIdentifier = [string]$_.ApplicationIdentifier
                            ($applicationIdentifier -match $guidPattern) -and ($applicationIdentifier -ne $sharedExchangeOnlineAppId)
                        })

                    $dedicatedHybridAppConfigured = ($dedicatedHybridAppOverrides.Count -ge 1) -and ($dedicatedAppAuthServers.Count -ge 1) -and ($sharedAppAuthServers.Count -eq 0)

                    $evoStsIsDefaultAuthorizationEndpoint = (@($evoStsAuthServers | Where-Object {
                                $_.PSObject.Properties.Name -contains 'IsDefaultAuthorizationEndpoint' -and
                                [bool]$_.IsDefaultAuthorizationEndpoint
                            }).Count -gt 0)

                    $defaultAuthorizationServer = @($authServers | Where-Object {
                            $_.PSObject.Properties.Name -contains 'IsDefaultAuthorizationEndpoint' -and
                            [bool]$_.IsDefaultAuthorizationEndpoint -eq $true
                        }) | Select-Object -First 1
                    $defaultAuthServerUrl = if ($null -ne $defaultAuthorizationServer -and
                        $defaultAuthorizationServer.PSObject.Properties.Name -contains 'AuthMetadataUrl' -and
                        -not [string]::IsNullOrWhiteSpace([string]$defaultAuthorizationServer.AuthMetadataUrl)) {
                        [string]$defaultAuthorizationServer.AuthMetadataUrl
                    }
                    else { '' }
                    $modernAuthType = if ([string]::IsNullOrWhiteSpace($defaultAuthServerUrl)) { 'None' }
                    elseif ($defaultAuthServerUrl -match 'login\.windows\.net|login\.microsoftonline\.com') { 'HMA' }
                    else { 'ADFS' }

                    $hmaDownloadDomainOverride = @($settingOverrides | Where-Object {
                            $cn = if ($_.PSObject.Properties.Name -contains 'ComponentName') { [string]$_.ComponentName } else { '' }
                            $sn = if ($_.PSObject.Properties.Name -contains 'SectionName') { [string]$_.SectionName } else { '' }
                            $pt = if ($_.PSObject.Properties.Name -contains 'Parameters' -and $null -ne $_.Parameters) { [string]::Join(';', @($_.Parameters | ForEach-Object { [string]$_ })) } else { '' }
                            $cn -eq 'OAuth' -and $sn -eq 'OAuthIdentityCacheFixForDownloadDomains' -and $pt -match 'Enabled\s*=\s*True'
                        })
                    $exchangeInfo.OAuthHmaDownloadDomainOverrideConfigured = ($hmaDownloadDomainOverride.Count -gt 0)

                    $hybridConfigured = $oAuthConfigured
                    $exchangeInfo.HybridApplication = [pscustomobject]@{
                        Configured                             = $hybridConfigured
                        EvoStsIsDefaultAuthorizationEndpoint   = $evoStsIsDefaultAuthorizationEndpoint
                        DedicatedHybridAppConfigured           = $dedicatedHybridAppConfigured
                        DedicatedHybridAppOverrideCount        = $dedicatedHybridAppOverrides.Count
                        DedicatedHybridAppAuthServerCount      = $dedicatedAppAuthServers.Count
                        SharedExchangeOnlineAppAuthServerCount = $sharedAppAuthServers.Count
                        DefaultAuthServerAuthMetadataUrl       = $defaultAuthServerUrl
                        ModernAuthType                         = $modernAuthType
                        Details                                = ('OAuth hybrid detected: {0}; EvoSTS auth servers: {1}; ACS auth servers: {2}; Exchange Online partner app enabled: {3}; dedicated-hybrid-app override count: {4}; dedicated-app auth server count: {5}; shared-app auth server count: {6}; EvoSTS IsDefaultAuthorizationEndpoint: {7}; modern auth type: {8}; default auth server URL: {9}' -f $hybridConfigured, $evoStsAuthServers.Count, $acsAuthServers.Count, $enabledHybridPartnerApplication, $dedicatedHybridAppOverrides.Count, $dedicatedAppAuthServers.Count, $sharedAppAuthServers.Count, $evoStsIsDefaultAuthorizationEndpoint, $modernAuthType, $defaultAuthServerUrl)
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-AuthServer/Get-PartnerApplication hybrid check failed: ' + $_.Exception.Message)
                }
            }
        }

        return $exchangeInfo
    }

    return Invoke-EDCAServerCommand -Server $Server -ScriptBlock $scriptBlock
}

function Resolve-EDCADnsRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [string]$Type
    )

    if (-not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{
            ResolverAvailable = $false
            Success           = $false
            Records           = @()
            Error             = 'Resolve-DnsName is not available on this host.'
        }
    }

    try {
        $records = @(Resolve-DnsName -Name $Name -Type $Type -ErrorAction Stop)
        return [pscustomobject]@{
            ResolverAvailable = $true
            Success           = $true
            Records           = $records
            Error             = ''
        }
    }
    catch {
        return [pscustomobject]@{
            ResolverAvailable = $true
            Success           = $false
            Records           = @()
            Error             = $_.Exception.Message
        }
    }
}

function Get-EDCATxtRecordValues {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Records
    )

    $values = @()
    foreach ($record in $Records) {
        if ($record.PSObject.Properties.Name -contains 'Type' -and [string]$record.Type -ne 'TXT') {
            continue
        }

        if ($record.PSObject.Properties.Name -contains 'Strings' -and $null -ne $record.Strings) {
            $txtValue = ([string[]]$record.Strings) -join ''
            if (-not [string]::IsNullOrWhiteSpace($txtValue)) {
                $values += $txtValue.Trim()
            }
        }
        elseif ($record.PSObject.Properties.Name -contains 'Strings') {
            continue
        }
        else {
            $rawText = [string]$record
            if (-not [string]::IsNullOrWhiteSpace($rawText)) {
                $values += $rawText.Trim()
            }
        }
    }

    return @($values)
}

function Get-EDCASpfDnsLookupCount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain,
        [System.Collections.Generic.HashSet[string]]$Visited = $null
    )

    if ($null -eq $Visited) {
        $Visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }

    if (-not $Visited.Add($Domain)) {
        return 0
    }

    $txtLookup = Resolve-EDCADnsRecord -Name $Domain -Type 'TXT'
    if (-not $txtLookup.Success) {
        return 0
    }

    $txtValues = Get-EDCATxtRecordValues -Records $txtLookup.Records
    $spfRecords = @($txtValues | Where-Object { $_ -match '^v=spf1(\s|$)' })
    if ($spfRecords.Count -ne 1) {
        return 0
    }

    $spf = [string]$spfRecords[0]
    $count = 0
    $count += ([regex]::Matches($spf, '(?:^|\s)(a)(:|\/|\s|$)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
    $count += ([regex]::Matches($spf, '(?:^|\s)(mx)(:|\/|\s|$)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
    $count += ([regex]::Matches($spf, '(?:^|\s)(ptr)(:|\/|\s|$)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count
    $count += ([regex]::Matches($spf, '(?:^|\s)(exists:)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)).Count

    $includeMatches = [regex]::Matches($spf, '(?:^|\s)include:(\S+)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($match in $includeMatches) {
        $count += 1
        $count += Get-EDCASpfDnsLookupCount -Domain $match.Groups[1].Value -Visited $Visited
    }

    if ($spf -match '(?:^|\s)redirect=(\S+)') {
        $count += 1
        $count += Get-EDCASpfDnsLookupCount -Domain $matches[1] -Visited $Visited
    }

    return $count
}

function Test-EDCASpfConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    $txtLookup = Resolve-EDCADnsRecord -Name $Domain -Type 'TXT'
    if (-not $txtLookup.ResolverAvailable) {
        return [pscustomobject]@{
            Status                  = 'Unknown'
            Evidence                = $txtLookup.Error
            Records                 = @()
            PotentialDnsLookupCount = $null
            Issues                  = @($txtLookup.Error)
        }
    }

    if (-not $txtLookup.Success) {
        return [pscustomobject]@{
            Status                  = 'Fail'
            Evidence                = ('No TXT records resolved for SPF check: {0}' -f $txtLookup.Error)
            Records                 = @()
            PotentialDnsLookupCount = $null
            Issues                  = @('No SPF TXT record found.')
        }
    }

    $txtValues = Get-EDCATxtRecordValues -Records $txtLookup.Records
    $spfRecords = @($txtValues | Where-Object { $_ -match '^v=spf1(\s|$)' })
    if ($spfRecords.Count -eq 0) {
        return [pscustomobject]@{
            Status                  = 'Fail'
            Evidence                = 'TXT records exist, but no SPF record starting with v=spf1 was found.'
            Records                 = @()
            PotentialDnsLookupCount = $null
            Issues                  = @('SPF record missing.')
        }
    }

    if ($spfRecords.Count -gt 1) {
        return [pscustomobject]@{
            Status                  = 'Fail'
            Evidence                = ('Multiple SPF records found ({0}). RFC-compliant SPF requires exactly one SPF record.' -f $spfRecords.Count)
            Records                 = $spfRecords
            PotentialDnsLookupCount = $null
            Issues                  = @('Multiple SPF records detected.')
        }
    }

    $spf = [string]$spfRecords[0]
    $issues = @()
    if ($spf -notmatch '\s[\+\-\~\?]?all(\s|$)') {
        $issues += 'SPF record does not contain a terminal all mechanism.'
    }

    if ($spf -match '(^|\s)ptr($|\s|:)') {
        $issues += 'SPF record uses ptr mechanism (not recommended).'
    }

    $lookupCount = Get-EDCASpfDnsLookupCount -Domain $Domain

    if ($lookupCount -gt 10) {
        $issues += ('SPF DNS lookup count ({0}) exceeds RFC 7208 limit of 10; receiving MTAs will likely ignore this SPF record.' -f $lookupCount)
    }

    $status = if ($issues.Count -eq 0) { 'Pass' } else { 'Fail' }
    return [pscustomobject]@{
        Status                  = $status
        Evidence                = $spf
        Records                 = @($spf)
        PotentialDnsLookupCount = $lookupCount
        Issues                  = $issues
    }
}

function Test-EDCADmarcConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    $dmarcDomain = ('_dmarc.{0}' -f $Domain)
    $txtLookup = Resolve-EDCADnsRecord -Name $dmarcDomain -Type 'TXT'
    if (-not $txtLookup.ResolverAvailable) {
        return [pscustomobject]@{
            Status   = 'Unknown'
            Evidence = $txtLookup.Error
            Records  = @()
            Policy   = $null
            Issues   = @($txtLookup.Error)
        }
    }

    if (-not $txtLookup.Success) {
        return [pscustomobject]@{
            Status   = 'Fail'
            Evidence = ('No DMARC TXT records resolved: {0}' -f $txtLookup.Error)
            Records  = @()
            Policy   = $null
            Issues   = @('DMARC record missing.')
        }
    }

    $txtValues = Get-EDCATxtRecordValues -Records $txtLookup.Records
    $dmarcRecords = @($txtValues | Where-Object { $_ -match '^v=DMARC1\s*;?' })
    if ($dmarcRecords.Count -eq 0) {
        return [pscustomobject]@{
            Status   = 'Fail'
            Evidence = 'TXT records exist at _dmarc, but no record starts with v=DMARC1.'
            Records  = @()
            Policy   = $null
            Issues   = @('DMARC syntax/version marker missing.')
        }
    }

    if ($dmarcRecords.Count -gt 1) {
        return [pscustomobject]@{
            Status   = 'Fail'
            Evidence = ('Multiple DMARC records found ({0}); only one DMARC record should exist.' -f $dmarcRecords.Count)
            Records  = $dmarcRecords
            Policy   = $null
            Issues   = @('Multiple DMARC records detected.')
        }
    }

    $record = [string]$dmarcRecords[0]
    $tags = @{}
    foreach ($fragment in ($record -split ';')) {
        $trimmed = $fragment.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            continue
        }

        $pair = $trimmed -split '=', 2
        if ($pair.Count -ne 2) {
            continue
        }

        $key = $pair[0].Trim().ToLowerInvariant()
        $value = $pair[1].Trim()
        if (-not [string]::IsNullOrWhiteSpace($key)) {
            $tags[$key] = $value
        }
    }

    $issues = @()
    if (-not $tags.ContainsKey('p')) {
        $issues += 'DMARC policy tag p= is missing.'
    }

    $policy = ''
    if ($tags.ContainsKey('p')) {
        $policy = [string]$tags['p']
        if ($policy -notin @('none', 'quarantine', 'reject')) {
            $issues += ('DMARC p= value is invalid: {0}' -f $policy)
        }
        elseif ($policy -eq 'none') {
            $issues += 'DMARC p=none is monitoring-only and does not enforce protection.'
        }
    }

    if ($tags.ContainsKey('pct')) {
        $pctValue = 0
        if (-not [int]::TryParse([string]$tags['pct'], [ref]$pctValue) -or $pctValue -lt 1 -or $pctValue -gt 100) {
            $issues += ('DMARC pct value is invalid: {0}' -f [string]$tags['pct'])
        }
    }

    foreach ($alignmentTag in @('adkim', 'aspf')) {
        if ($tags.ContainsKey($alignmentTag)) {
            $value = [string]$tags[$alignmentTag]
            if ($value -notin @('r', 's')) {
                $issues += ('DMARC {0} value is invalid: {1}' -f $alignmentTag, $value)
            }
        }
    }

    $status = if ($issues.Count -eq 0) { 'Pass' } else { 'Fail' }
    return [pscustomobject]@{
        Status   = $status
        Evidence = ('DMARC record: {0}; policy: {1}; issues: {2}' -f $record, $policy, $issues.Count)
        Records  = @($record)
        Policy   = $policy
        Issues   = $issues
    }
}

function Test-EDCAMtaStsConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    $dnsName = ('_mta-sts.{0}' -f $Domain)
    $txtLookup = Resolve-EDCADnsRecord -Name $dnsName -Type 'TXT'
    if (-not $txtLookup.ResolverAvailable) {
        return [pscustomobject]@{
            Status          = 'Unknown'
            Evidence        = $txtLookup.Error
            DnsRecord       = $null
            PolicyUrl       = ('https://mta-sts.{0}/.well-known/mta-sts.txt' -f $Domain)
            PolicyStatus    = 'Unknown'
            PolicyMode      = $null
            PolicyMaxAge    = $null
            PolicyMxEntries = @()
            Issues          = @($txtLookup.Error)
        }
    }

    if (-not $txtLookup.Success) {
        return [pscustomobject]@{
            Status          = 'Fail'
            Evidence        = ('No MTA-STS DNS TXT record resolved: {0}' -f $txtLookup.Error)
            DnsRecord       = $null
            PolicyUrl       = ('https://mta-sts.{0}/.well-known/mta-sts.txt' -f $Domain)
            PolicyStatus    = 'NotChecked'
            PolicyMode      = $null
            PolicyMaxAge    = $null
            PolicyMxEntries = @()
            Issues          = @('MTA-STS DNS TXT record missing.')
        }
    }

    $txtValues = Get-EDCATxtRecordValues -Records $txtLookup.Records
    $stsRecords = @($txtValues | Where-Object { $_ -match '^v=STSv1\s*;?' })
    if ($stsRecords.Count -eq 0) {
        return [pscustomobject]@{
            Status          = 'Fail'
            Evidence        = 'TXT records exist at _mta-sts, but no record starts with v=STSv1.'
            DnsRecord       = $null
            PolicyUrl       = ('https://mta-sts.{0}/.well-known/mta-sts.txt' -f $Domain)
            PolicyStatus    = 'NotChecked'
            PolicyMode      = $null
            PolicyMaxAge    = $null
            PolicyMxEntries = @()
            Issues          = @('MTA-STS DNS version marker missing.')
        }
    }

    if ($stsRecords.Count -gt 1) {
        return [pscustomobject]@{
            Status          = 'Fail'
            Evidence        = ('Multiple MTA-STS TXT records found ({0}); only one should exist.' -f $stsRecords.Count)
            DnsRecord       = $stsRecords[0]
            PolicyUrl       = ('https://mta-sts.{0}/.well-known/mta-sts.txt' -f $Domain)
            PolicyStatus    = 'NotChecked'
            PolicyMode      = $null
            PolicyMaxAge    = $null
            PolicyMxEntries = @()
            Issues          = @('Multiple MTA-STS DNS TXT records detected.')
        }
    }

    $dnsRecord = [string]$stsRecords[0]
    $dnsParts = @{}
    foreach ($fragment in ($dnsRecord -split ';')) {
        $trimmed = $fragment.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            continue
        }

        $pair = $trimmed -split '=', 2
        if ($pair.Count -ne 2) {
            continue
        }

        $dnsParts[$pair[0].Trim().ToLowerInvariant()] = $pair[1].Trim()
    }

    $issues = @()
    if (-not $dnsParts.ContainsKey('id') -or [string]::IsNullOrWhiteSpace([string]$dnsParts['id'])) {
        $issues += 'MTA-STS DNS TXT record is missing id= value.'
    }

    $policyUrl = ('https://mta-sts.{0}/.well-known/mta-sts.txt' -f $Domain)
    $policyStatus = 'Unknown'
    $policyMode = ''
    $policyMaxAge = $null
    $policyMxEntries = @()
    try {
        $response = Invoke-WebRequest -Uri $policyUrl -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
        $policyLines = @([string]$response.Content -split "`r?`n") | ForEach-Object { $_.Trim() } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        $policyMap = @{}
        $mxEntries = @()
        foreach ($line in $policyLines) {
            if ($line -match '^[Mm][Xx]\s*:\s*(.+)$') {
                $mxEntries += $matches[1].Trim()
                continue
            }

            $pair = $line -split ':', 2
            if ($pair.Count -eq 2) {
                $key = $pair[0].Trim().ToLowerInvariant()
                $value = $pair[1].Trim()
                if (-not [string]::IsNullOrWhiteSpace($key)) {
                    $policyMap[$key] = $value
                }
            }
        }

        if (-not $policyMap.ContainsKey('version') -or [string]$policyMap['version'] -ne 'STSv1') {
            $issues += 'MTA-STS policy file version is missing or not STSv1.'
        }

        if (-not $policyMap.ContainsKey('mode')) {
            $issues += 'MTA-STS policy file mode is missing.'
        }
        else {
            $policyMode = [string]$policyMap['mode']
            if ($policyMode -notin @('enforce', 'testing', 'none')) {
                $issues += ('MTA-STS policy mode is invalid: {0}' -f $policyMode)
            }
        }

        if (-not $policyMap.ContainsKey('max_age')) {
            $issues += 'MTA-STS policy file max_age is missing.'
        }
        else {
            $maxAge = 0
            if (-not [int]::TryParse([string]$policyMap['max_age'], [ref]$maxAge) -or $maxAge -le 0) {
                $issues += ('MTA-STS max_age is invalid: {0}' -f [string]$policyMap['max_age'])
            }
        }

        if ($policyMode -in @('enforce', 'testing') -and $mxEntries.Count -eq 0) {
            $issues += 'MTA-STS policy mode requires at least one mx: entry.'
        }

        $policyMaxAge = if ($policyMap.ContainsKey('max_age')) { [string]$policyMap['max_age'] } else { $null }
        $policyMxEntries = $mxEntries
        $policyStatus = 'Fetched'
    }
    catch {
        $policyStatus = 'FetchFailed'
        $issues += ('MTA-STS policy fetch failed: {0}' -f $_.Exception.Message)
    }

    $status = if ($issues.Count -eq 0) { 'Pass' } else { 'Fail' }
    return [pscustomobject]@{
        Status          = $status
        Evidence        = ('MTA-STS DNS record: "{0}"; policy status: {1}; issues: {2}' -f $dnsRecord, $policyStatus, $issues.Count)
        DnsRecord       = $dnsRecord
        PolicyUrl       = $policyUrl
        PolicyStatus    = $policyStatus
        PolicyMode      = if ([string]::IsNullOrWhiteSpace($policyMode)) { $null } else { $policyMode }
        PolicyMaxAge    = $policyMaxAge
        PolicyMxEntries = $policyMxEntries
        Issues          = $issues
    }
}

function Test-EDCADaneConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    $mxLookup = Resolve-EDCADnsRecord -Name $Domain -Type 'MX'
    if (-not $mxLookup.ResolverAvailable) {
        return [pscustomobject]@{
            Status     = 'Unknown'
            Evidence   = $mxLookup.Error
            MxHosts    = @()
            TlsaByHost = @()
            Issues     = @($mxLookup.Error)
        }
    }

    if (-not $mxLookup.Success) {
        return [pscustomobject]@{
            Status     = 'Fail'
            Evidence   = ('No MX records resolved for domain: {0}' -f $mxLookup.Error)
            MxHosts    = @()
            TlsaByHost = @()
            Issues     = @('MX records missing; SMTP DANE cannot be evaluated.')
        }
    }

    $mxHosts = @()
    foreach ($record in $mxLookup.Records) {
        if ($record.PSObject.Properties.Name -contains 'NameExchange') {
            $mxHost = ([string]$record.NameExchange).Trim().TrimEnd('.').ToLowerInvariant()
            if (-not [string]::IsNullOrWhiteSpace($mxHost)) {
                $mxHosts += $mxHost
            }
        }
    }

    $mxHosts = @($mxHosts | Sort-Object -Unique)
    if ($mxHosts.Count -eq 0) {
        return [pscustomobject]@{
            Status     = 'Fail'
            Evidence   = 'MX lookup returned no usable MX host entries.'
            MxHosts    = @()
            TlsaByHost = @()
            Issues     = @('MX records did not contain NameExchange values.')
        }
    }

    $issues = @()
    $tlsaByHost = @()
    foreach ($mxHost in $mxHosts) {
        $tlsaName = ('_25._tcp.{0}' -f $mxHost)

        # Try TLSA type; Windows DNS may not support it on older OS versions
        $tlsaLookup = Resolve-EDCADnsRecord -Name $tlsaName -Type 'TLSA'

        $directTlsaRecords = @()
        $cnameTarget = $null

        if ($tlsaLookup.Success) {
            $directTlsaRecords = @($tlsaLookup.Records | Where-Object { $_.PSObject.Properties.Name -contains 'Type' -and [string]$_.Type -eq 'TLSA' })
            # A CNAME at the TLSA name is also valid (e.g. Exchange Online / M365 DANE delegation)
            $cnameHit = @($tlsaLookup.Records | Where-Object { $_.PSObject.Properties.Name -contains 'Type' -and [string]$_.Type -eq 'CNAME' })
            if ($cnameHit.Count -gt 0 -and ($cnameHit[0].PSObject.Properties.Name -contains 'NameHost')) {
                $cnameTarget = ([string]$cnameHit[0].NameHost).TrimEnd('.')
            }
        }

        # If TLSA type query failed (not supported on this Windows version), try explicit CNAME lookup
        if (-not $tlsaLookup.Success -and $directTlsaRecords.Count -eq 0 -and $null -eq $cnameTarget) {
            $cnameLookup = Resolve-EDCADnsRecord -Name $tlsaName -Type 'CNAME'
            if ($cnameLookup.Success) {
                $cnameHit = @($cnameLookup.Records | Where-Object { $_.PSObject.Properties.Name -contains 'Type' -and [string]$_.Type -eq 'CNAME' })
                if ($cnameHit.Count -gt 0 -and ($cnameHit[0].PSObject.Properties.Name -contains 'NameHost')) {
                    $cnameTarget = ([string]$cnameHit[0].NameHost).TrimEnd('.')
                }
            }
        }

        $hasTlsa = $directTlsaRecords.Count -gt 0
        $hasCname = -not [string]::IsNullOrWhiteSpace($cnameTarget)

        if (-not $hasTlsa -and -not $hasCname) {
            $errorDetail = if (-not $tlsaLookup.Success) { $tlsaLookup.Error } else { 'No TLSA record or CNAME delegation found.' }
            $issues += ('{0}: no TLSA record or CNAME delegation found.' -f $tlsaName)
            $tlsaByHost += [pscustomobject]@{
                MxHost      = $mxHost
                TlsaName    = $tlsaName
                TlsaCount   = 0
                CnameTarget = $null
                Status      = 'Fail'
                Error       = $errorDetail
            }
            continue
        }

        # CNAME delegation only (no direct TLSA records) - valid Exchange Online / M365 DANE pattern
        if ($hasCname -and -not $hasTlsa) {
            $tlsaByHost += [pscustomobject]@{
                MxHost      = $mxHost
                TlsaName    = $tlsaName
                TlsaCount   = 0
                CnameTarget = $cnameTarget
                Status      = 'Pass'
                Error       = ''
            }
            continue
        }

        # Direct TLSA records - validate parameter values
        $invalidTlsaCount = 0
        foreach ($tlsaRecord in $directTlsaRecords) {
            if (($tlsaRecord.PSObject.Properties.Name -contains 'CertificateUsage') -and ($tlsaRecord.CertificateUsage -notin 0, 1, 2, 3)) {
                $invalidTlsaCount++
            }
            if (($tlsaRecord.PSObject.Properties.Name -contains 'Selector') -and ($tlsaRecord.Selector -notin 0, 1)) {
                $invalidTlsaCount++
            }
            if (($tlsaRecord.PSObject.Properties.Name -contains 'MatchingType') -and ($tlsaRecord.MatchingType -notin 0, 1, 2)) {
                $invalidTlsaCount++
            }
        }

        if ($invalidTlsaCount -gt 0) {
            $issues += ('{0}: TLSA records contain invalid parameter values.' -f $tlsaName)
        }

        $tlsaByHost += [pscustomobject]@{
            MxHost      = $mxHost
            TlsaName    = $tlsaName
            TlsaCount   = $directTlsaRecords.Count
            CnameTarget = $cnameTarget
            Status      = if ($invalidTlsaCount -gt 0) { 'Fail' } else { 'Pass' }
            Error       = ''
        }
    }

    $status = if ($issues.Count -eq 0) { 'Pass' } else { 'Fail' }
    $evidenceParts = @($tlsaByHost | ForEach-Object {
            if (-not [string]::IsNullOrWhiteSpace($_.CnameTarget) -and $_.TlsaCount -eq 0) {
                ('{0} -> CNAME: {1}' -f $_.TlsaName, $_.CnameTarget)
            }
            elseif ($_.TlsaCount -gt 0 -and -not [string]::IsNullOrWhiteSpace($_.CnameTarget)) {
                ('{0}: {1} TLSA record(s) via CNAME: {2}' -f $_.TlsaName, $_.TlsaCount, $_.CnameTarget)
            }
            elseif ($_.TlsaCount -gt 0) {
                ('{0}: {1} TLSA record(s)' -f $_.TlsaName, $_.TlsaCount)
            }
            else {
                ('{0}: not found - {1}' -f $_.TlsaName, $_.Error)
            }
        })
    return [pscustomobject]@{
        Status     = $status
        Evidence   = $evidenceParts -join "; "
        MxHosts    = $mxHosts
        TlsaByHost = $tlsaByHost
        Issues     = $issues
    }
}

function Test-EDCADkimConfiguration {
    # Note: Get-DkimSigningConfig and Enable-DkimSigningConfig are Exchange Online PowerShell cmdlets.
    # They do not exist in the Exchange Management Shell on Exchange Server on-premises.
    # DKIM signing for on-premises Exchange always requires a third-party agent, gateway, or SaaS service.
    # This function detects DKIM by probing well-known selectors across popular mail platforms.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    # Selectors used by common mail platforms:
    #   selector1/selector2  Exchange Online (Microsoft 365)
    #   google               Google Workspace
    #   k1/k2                Mailchimp / Mandrill / Klaviyo
    #   s1/s2                SendGrid / generic
    #   pm                   Postmark
    #   proofpoint           Proofpoint
    #   default/mail/dkim    generic / self-hosted
    $knownSelectors = @('selector1', 'selector2', 'google', 'k1', 'k2', 's1', 's2', 'pm', 'proofpoint', 'default', 'mail', 'dkim')

    # Map CNAME target suffixes to signing service names.
    $cnameServiceMap = [ordered]@{
        '.onmicrosoft.com'   = 'Exchange Online (Microsoft 365)'
        '.mimecast.com'      = 'Mimecast'
        '.pphosted.com'      = 'Proofpoint'
        '.amazonses.com'     = 'Amazon SES'
        '.sendgrid.net'      = 'SendGrid'
        '.mtasv.net'         = 'Postmark'
        '.mandrillapp.com'   = 'Mailchimp / Mandrill'
        '.klaviyo.com'       = 'Klaviyo'
        '.mailgun.org'       = 'Mailgun'
        '.sparkpostmail.com' = 'SparkPost'
        '.mailjet.com'       = 'Mailjet'
        '.socketlabs.com'    = 'SocketLabs'
        '.exacttarget.com'   = 'Salesforce Marketing Cloud'
        '.salesforce.com'    = 'Salesforce Marketing Cloud'
        '.messagelabs.com'   = 'Symantec Email Security.cloud'
    }

    # Fallback service hints based on selector name when no CNAME suffix matches.
    $selectorServiceHint = @{
        'google'     = 'Google Workspace'
        'proofpoint' = 'Proofpoint'
        'pm'         = 'Postmark'
    }

    $issues = @()
    $detectedSelectors = [ordered]@{}

    foreach ($selector in $knownSelectors) {
        $dnsName = ('{0}._domainkey.{1}' -f $selector, $Domain)
        $txtLookup = Resolve-EDCADnsRecord -Name $dnsName -Type 'TXT'

        if (-not $txtLookup.ResolverAvailable) {
            return [pscustomobject]@{
                Status            = 'Unknown'
                Evidence          = $txtLookup.Error
                Selector1         = $null
                Selector2         = $null
                DetectedSelectors = $null
                SigningService    = $null
                Issues            = @($txtLookup.Error)
            }
        }

        if (-not $txtLookup.Success) { continue }

        # Extract CNAME records (Resolve-DnsName may return the full chain).
        $cnameTarget = @($txtLookup.Records |
            Where-Object { $_.PSObject.Properties.Name -contains 'Type' -and [string]$_.Type -eq 'CNAME' } |
            ForEach-Object { [string]$_.NameHost }) | Select-Object -Last 1

        # Extract TXT values containing a DKIM public key (p= tag).
        $txtValues = Get-EDCATxtRecordValues -Records $txtLookup.Records
        $dkimTxt = @($txtValues | Where-Object { $_ -match 'p=' }) | Select-Object -First 1

        if ([string]::IsNullOrWhiteSpace($cnameTarget) -and [string]::IsNullOrWhiteSpace($dkimTxt)) { continue }

        # Determine service name from CNAME target suffix.
        $service = $null
        if (-not [string]::IsNullOrWhiteSpace($cnameTarget)) {
            $lcTarget = $cnameTarget.ToLowerInvariant()
            foreach ($suffix in $cnameServiceMap.Keys) {
                if ($lcTarget.EndsWith($suffix)) {
                    $service = $cnameServiceMap[$suffix]
                    break
                }
            }
        }
        if ($null -eq $service -and $selectorServiceHint.ContainsKey($selector)) {
            $service = $selectorServiceHint[$selector]
        }

        $detectedSelectors[$selector] = [pscustomobject]@{
            Type    = if (-not [string]::IsNullOrWhiteSpace($cnameTarget)) { 'CNAME' } else { 'TXT' }
            Cname   = $cnameTarget
            Value   = $dkimTxt
            Service = $service
        }
    }

    if ($detectedSelectors.Count -eq 0) {
        $probed = ($knownSelectors | ForEach-Object { '{0}._domainkey' -f $_ }) -join ', '
        $issues += ('No DKIM selector records found. Probed: {0}.' -f $probed)
    }

    $status = if ($issues.Count -eq 0) { 'Pass' } else { 'Fail' }

    $evidenceParts = @(
        foreach ($sel in $detectedSelectors.Keys) {
            $entry = $detectedSelectors[$sel]
            $serviceTag = if ($null -ne $entry.Service) { ' [{0}]' -f $entry.Service } else { '' }
            if ($entry.Type -eq 'CNAME') {
                ('{0}._domainkey: CNAME -> {1}{2}' -f $sel, $entry.Cname, $serviceTag)
            }
            else {
                ('{0}._domainkey: TXT found{1}' -f $sel, $serviceTag)
            }
        }
    )
    if ($evidenceParts.Count -eq 0) { $evidenceParts = @($issues) }

    $signingService = @($detectedSelectors.Values | ForEach-Object { $_.Service } | Where-Object { $null -ne $_ } | Select-Object -Unique) -join ', '

    return [pscustomobject]@{
        Status            = $status
        Evidence          = $evidenceParts -join '; '
        Selector1         = if ($detectedSelectors.Contains('selector1')) { $detectedSelectors['selector1'].Value } else { $null }
        Selector2         = if ($detectedSelectors.Contains('selector2')) { $detectedSelectors['selector2'].Value } else { $null }
        DetectedSelectors = $detectedSelectors
        SigningService    = if ([string]::IsNullOrWhiteSpace($signingService)) { $null } else { $signingService }
        Issues            = $issues
    }
}

function Test-EDCATlsRptConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Domain
    )

    $dnsName = ('_smtp._tls.{0}' -f $Domain)
    $txtLookup = Resolve-EDCADnsRecord -Name $dnsName -Type 'TXT'

    if (-not $txtLookup.ResolverAvailable) {
        return [pscustomobject]@{
            Status   = 'Unknown'
            Evidence = $txtLookup.Error
            Record   = $null
            Issues   = @($txtLookup.Error)
        }
    }

    if (-not $txtLookup.Success) {
        return [pscustomobject]@{
            Status   = 'Fail'
            Evidence = ('No TLS-RPT TXT record resolved at {0}: {1}' -f $dnsName, $txtLookup.Error)
            Record   = $null
            Issues   = @('TLS-RPT record missing.')
        }
    }

    $txtValues = Get-EDCATxtRecordValues -Records $txtLookup.Records
    $tlsrptRecords = @($txtValues | Where-Object { $_ -match '^v=TLSRPTv1\s*;?' })
    if ($tlsrptRecords.Count -eq 0) {
        return [pscustomobject]@{
            Status   = 'Fail'
            Evidence = ('TXT records found at {0} but none starts with v=TLSRPTv1.' -f $dnsName)
            Record   = $null
            Issues   = @('TLS-RPT record version marker missing or invalid.')
        }
    }

    $record = [string]$tlsrptRecords[0]
    $issues = @()
    $tags = @{}
    foreach ($fragment in ($record -split ';')) {
        $trimmed = $fragment.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed)) { continue }
        $pair = $trimmed -split '=', 2
        if ($pair.Count -ne 2) { continue }
        $key = $pair[0].Trim().ToLowerInvariant()
        $value = $pair[1].Trim()
        if (-not [string]::IsNullOrWhiteSpace($key)) { $tags[$key] = $value }
    }

    if (-not $tags.ContainsKey('rua') -or [string]::IsNullOrWhiteSpace([string]$tags['rua'])) {
        $issues += 'TLS-RPT record is missing rua= reporting endpoint.'
    }

    $status = if ($issues.Count -eq 0) { 'Pass' } else { 'Fail' }
    return [pscustomobject]@{
        Status   = $status
        Evidence = ('TLS-RPT record: {0}; issues: {1}' -f $record, $issues.Count)
        Record   = $record
        Issues   = $issues
    }
}

function Invoke-EDCAEmailAuthenticationChecks {
    [CmdletBinding()]
    param(
        [string[]]$AcceptedDomains
    )

    $normalizedDomains = @($AcceptedDomains | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).Trim().TrimEnd('.').ToLowerInvariant() } | Sort-Object -Unique)
    $domains = @($normalizedDomains | Where-Object { $_ -ne 'onmicrosoft.com' -and -not $_.EndsWith('.onmicrosoft.com') })

    $skippedOnMicrosoftDomains = @($normalizedDomains | Where-Object { $_ -eq 'onmicrosoft.com' -or $_.EndsWith('.onmicrosoft.com') })
    if ($skippedOnMicrosoftDomains.Count -gt 0) {
        Write-Verbose ('Skipping {0} onmicrosoft.com domain(s) for email authentication checks: {1}' -f $skippedOnMicrosoftDomains.Count, ($skippedOnMicrosoftDomains -join ', '))
    }

    if ($domains.Count -eq 0) {
        return [pscustomobject]@{
            Available     = $false
            Reason        = 'No eligible accepted domains were discovered from Exchange after excluding onmicrosoft.com domains.'
            DomainResults = @()
        }
    }

    if (-not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{
            Available     = $false
            Reason        = 'Resolve-DnsName is not available on this host; DNS-based email authentication checks cannot run.'
            DomainResults = @()
        }
    }

    $domainResults = @()
    foreach ($domain in $domains) {
        Write-Verbose -Message ('Validating email authentication DNS records for domain: {0}' -f $domain)
        $domainResults += [pscustomobject]@{
            Domain = $domain
            Spf    = Test-EDCASpfConfiguration -Domain $domain
            Dmarc  = Test-EDCADmarcConfiguration -Domain $domain
            MtaSts = Test-EDCAMtaStsConfiguration -Domain $domain
            Dane   = Test-EDCADaneConfiguration -Domain $domain
            Dkim   = Test-EDCADkimConfiguration -Domain $domain
            TlsRpt = Test-EDCATlsRptConfiguration -Domain $domain
        }
    }

    return [pscustomobject]@{
        Available     = $true
        Reason        = ''
        DomainResults = $domainResults
    }
}

function Get-EDCAServerInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    $collectionScriptBlock = {
        param([bool]$collectExchangeCmdlets = $true)
        Set-StrictMode -Version Latest
        $ErrorActionPreference = 'Stop'

        function Get-EDCACertificateStatus {
            [CmdletBinding()]
            param(
                [AllowNull()]
                [string]$Thumbprint,
                [AllowNull()]
                [object[]]$Certificates
            )

            $normalizedThumbprint = ''
            if (-not [string]::IsNullOrWhiteSpace($Thumbprint)) {
                $normalizedThumbprint = $Thumbprint.Trim().ToUpperInvariant()
            }

            if ([string]::IsNullOrWhiteSpace($normalizedThumbprint)) {
                return [pscustomobject]@{
                    Thumbprint    = $null
                    Found         = $false
                    NotAfter      = $null
                    IsExpired     = $null
                    DaysRemaining = $null
                }
            }

            $matchedCertificate = @($Certificates | Where-Object {
                    -not [string]::IsNullOrWhiteSpace([string]$_.Thumbprint) -and
                    ([string]$_.Thumbprint).Trim().ToUpperInvariant() -eq $normalizedThumbprint
                } | Select-Object -First 1)

            if ($matchedCertificate.Count -eq 0) {
                return [pscustomobject]@{
                    Thumbprint    = $normalizedThumbprint
                    Found         = $false
                    NotAfter      = $null
                    IsExpired     = $null
                    DaysRemaining = $null
                }
            }

            $notAfter = $matchedCertificate[0].NotAfter
            $now = Get-Date
            return [pscustomobject]@{
                Thumbprint    = $normalizedThumbprint
                Found         = $true
                NotAfter      = $notAfter
                IsExpired     = ($notAfter -lt $now)
                DaysRemaining = [int][math]::Floor(($notAfter - $now).TotalDays)
            }
        }

        function Get-EDCACimInstance {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [string]$ClassName,
                [AllowNull()]
                [string]$Namespace,
                [AllowNull()]
                [string]$Filter
            )

            $cimParams = @{
                ClassName   = $ClassName
                ErrorAction = 'SilentlyContinue'
            }
            if (-not [string]::IsNullOrWhiteSpace($Namespace)) {
                $cimParams.Namespace = $Namespace
            }
            if (-not [string]::IsNullOrWhiteSpace($Filter)) {
                $cimParams.Filter = $Filter
            }

            # Keep CIM chatter out of verbose output and surface it under debug instead.
            $records = @(& { Get-CimInstance @cimParams -Verbose } 4>&1)
            foreach ($record in $records) {
                if ($record -is [System.Management.Automation.VerboseRecord]) {
                    Write-Debug ('CIM {0}: {1}' -f $ClassName, $record.Message)
                    continue
                }

                $record
            }
        }

        $exchangeInfo = [pscustomobject]@{
            ExchangeCmdletsAvailable                 = $false
            Name                                     = $env:COMPUTERNAME
            AdminDisplayVersion                      = $null
            BuildNumber                              = $null
            Edition                                  = $null
            ProductLine                              = 'Unknown'
            IsExchangeServer                         = $false
            IsEdge                                   = $false
            ServerRole                               = 'Unknown'
            EdgeData                                 = $null
            ExtendedProtectionStatus                 = @()
            AdminAuditLogEnabled                     = $null
            ReplicationHealthPassed                  = $null
            IsDagMember                              = $null
            DagName                                  = $null
            AdSite                                   = $null
            SingleItemRecoveryDisabledCount          = $null
            SingleItemRecoveryDisabledMailboxes      = @()
            OAuth2ClientProfileEnabled               = $null
            Pop3ServiceStatus                        = $null
            Imap4ServiceStatus                       = $null
            MapiHttpEnabled                          = $null
            ReceiveConnectors                        = @()
            SendConnectors                           = @()
            UpnPrimarySmtpMismatchCount              = $null
            SharedMailboxTypeMismatchCount           = $null
            SharedMailboxTypeMismatches              = @()
            OwaDownloadDomainsConfigured             = $null
            OAuthHmaDownloadDomainOverrideConfigured = $null
            AlternateServiceAccount                  = $null
            AcceptedDomains                          = @()
            DatabaseStoragePaths                     = @()
            InstallPath                              = $null
            RpcMinConnectionTimeout                  = $null
            TcpKeepAliveTime                         = $null
            TcpAckFrequencyAdapters                  = @()
            NumaGroupSizeOptimization                = $null
            IPv6DisabledComponents                   = $null
            CtsProcessorAffinityPercentage           = $null
            DisableAsyncNotification                 = $null
            DisableRootAutoUpdate                    = $null
            SleepyNic                                = $null
            NodeRunner                               = $null
            MapiFrontEndAppPoolGcMode                = $null
            VisualCRedistributable                   = $null
            AuthCertificate                          = $null
            SerializedDataSigningEnabled             = $null
            SettingOverrides                         = $null
            InternalTransportCertificate             = $null
            Eems                                     = $null
            Amsi                                     = $null
            Hsts                                     = $null
            IisModules                               = $null
            TokenCacheModuleLoaded                   = $null
            FipFs                                    = $null
            IisWebConfig                             = $null
            ExchangeComputerMembership               = $null
            UnifiedContentCleanup                    = $null
            TransportBackPressure                    = $null
            TransportRetryConfig                     = $null
            HybridApplication                        = $null
            ErrorReportingEnabled                    = $null
            MailboxDatabases                         = @()
            OwaSmimeEnabled                          = $null
            OwaFormsAuthentication                   = @()
            OutlookAnywhereSSLOffloading             = @()
            EventLogLevels                           = @()
            RpcClientAccessConfig                    = $null
            TransportService                         = $null
            TransportAgents                          = @()
            AntiSpamConfigs                          = $null
            ExchangeServices                         = @()
            ServiceHealth                            = $null
            InstallPathAcl                           = @()
            AuditLogPath                             = $null
            AuditLogPathAcl                          = @()
            CollectionWarnings                       = @()
        }

        $os = Get-EDCACimInstance -ClassName Win32_OperatingSystem
        $cs = Get-EDCACimInstance -ClassName Win32_ComputerSystem
        $cpu = Get-EDCACimInstance -ClassName Win32_Processor

        $activePowerPlanGuid = $null
        $activePowerPlanName = $null
        $highPerformanceSet = $false
        try {
            $powerPlanOutput = (powercfg /GETACTIVESCHEME 2>$null | Out-String)
            $powerMatch = [regex]::Match($powerPlanOutput, 'Power Scheme GUID:\s*([a-fA-F0-9\-]+)\s*\(([^\)]+)\)')
            if ($powerMatch.Success) {
                $activePowerPlanGuid = $powerMatch.Groups[1].Value
                $activePowerPlanName = $powerMatch.Groups[2].Value
                $knownHighPerformanceGuids = @(
                    '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c',
                    'db310065-829b-4671-9647-2261c00e86ef'
                )
                $highPerformanceSet = ($knownHighPerformanceGuids -contains $activePowerPlanGuid.ToLowerInvariant()) -or ($activePowerPlanName -like '*High performance*')
            }
        }
        catch {
        }

        $pageFiles = @(Get-EDCACimInstance -ClassName Win32_PageFileSetting)
        $pageFileItems = @()
        foreach ($pageFile in $pageFiles) {
            $pageFileItems += [pscustomobject]@{
                Name        = $pageFile.Name
                InitialSize = $pageFile.InitialSize
                MaximumSize = $pageFile.MaximumSize
            }
        }

        $volumeItems = @()
        $systemDrive = [string]$os.SystemDrive
        $systemVolume = $null
        try {
            $bitlockerStatus = @{}
            try {
                $blVolumes = @(Get-EDCACimInstance -ClassName Win32_EncryptableVolume -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption')
                foreach ($blVol in $blVolumes) {
                    $blLetter = ([string]$blVol.DriveLetter).TrimEnd('\').TrimEnd('/')
                    if (-not [string]::IsNullOrWhiteSpace($blLetter)) {
                        $bitlockerStatus[$blLetter.ToUpperInvariant()] = ([int]$blVol.ProtectionStatus -eq 1)
                    }
                }
            }
            catch {
            }
            $volumes = @(Get-EDCACimInstance -ClassName Win32_Volume -Filter 'DriveType = 3')
            foreach ($volume in $volumes) {
                $driveLetter = [string]$volume.DriveLetter
                # Name is the mount path: 'D:\' for drive-letter volumes or 'C:\MountedVolumes\DB1\' for directory-mounted volumes
                $mountName = ([string]$volume.Name).TrimEnd('\') + '\'
                if ([string]::IsNullOrWhiteSpace($mountName) -or $mountName -eq '\') {
                    continue
                }

                $blKey = if (-not [string]::IsNullOrWhiteSpace($driveLetter)) { $driveLetter.TrimEnd('\').ToUpperInvariant() } else { $null }
                $volumeItem = [pscustomobject]@{
                    DeviceID           = [string]$volume.DeviceID
                    Name               = $mountName
                    DriveLetter        = if ([string]::IsNullOrWhiteSpace($driveLetter)) { $null } else { $driveLetter.TrimEnd('\') }
                    Label              = [string]$volume.Label
                    FileSystem         = [string]$volume.FileSystem
                    BlockSize          = if ($null -ne $volume.BlockSize) { [int64]$volume.BlockSize } else { $null }
                    CapacityGB         = if ($null -ne $volume.Capacity) { [math]::Round(([double]$volume.Capacity / 1GB), 2) } else { $null }
                    FreeSpaceGB        = if ($null -ne $volume.FreeSpace) { [math]::Round(([double]$volume.FreeSpace / 1GB), 2) } else { $null }
                    BitLockerProtected = if ($null -ne $blKey -and $bitlockerStatus.ContainsKey($blKey)) { $bitlockerStatus[$blKey] } else { $false }
                }

                $volumeItems += $volumeItem
                if (-not [string]::IsNullOrWhiteSpace($systemDrive) -and -not [string]::IsNullOrWhiteSpace($driveLetter) -and
                    $driveLetter.TrimEnd('\').Equals($systemDrive.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) {
                    $systemVolume = $volumeItem
                }
            }
        }
        catch {
        }

        $rssEnabledCount = $null
        $rssAdapterCount = $null
        $rssDetails = @()
        if (Get-Command -Name Get-NetAdapterRss -ErrorAction SilentlyContinue) {
            try {
                $rssAdapters = @(Get-NetAdapterRss -ErrorAction SilentlyContinue)
                $rssAdapterCount = $rssAdapters.Count
                $rssEnabledCount = @($rssAdapters | Where-Object { $_.Enabled -eq $true }).Count
                foreach ($adapter in $rssAdapters) {
                    $rssDetails += [pscustomobject]@{
                        Name    = $adapter.Name
                        Enabled = [bool]$adapter.Enabled
                    }
                }
            }
            catch {
            }
        }

        $vmxnet3Adapters = @()
        $vmxnet3CommandAvailable = (Get-Command -Name Get-NetAdapter -ErrorAction SilentlyContinue) -and (Get-Command -Name Get-NetAdapterAdvancedProperty -ErrorAction SilentlyContinue)
        if ($vmxnet3CommandAvailable) {
            try {
                $allAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
                $candidateAdapters = @($allAdapters | Where-Object {
                        ([string]$_.InterfaceDescription -match 'vmxnet3') -or
                        ([string]$_.DriverDescription -match 'vmxnet3') -or
                        ([string]$_.Name -match 'vmxnet3')
                    })

                foreach ($adapter in $candidateAdapters) {
                    $adapterName = [string]$adapter.Name

                    $discardTotal = 0
                    $discardDetails = @()
                    if (Get-Command -Name Get-NetAdapterStatistics -ErrorAction SilentlyContinue) {
                        try {
                            $stats = Get-NetAdapterStatistics -Name $adapterName -ErrorAction SilentlyContinue
                            if ($null -ne $stats) {
                                foreach ($property in $stats.PSObject.Properties) {
                                    if ($property.Name -match 'Discard' -and ($property.Value -is [ValueType])) {
                                        $value = [int64]$property.Value
                                        $discardTotal += $value
                                        $discardDetails += [pscustomobject]@{
                                            Counter = [string]$property.Name
                                            Value   = $value
                                        }
                                    }
                                }
                            }
                        }
                        catch {
                        }
                    }

                    $advancedProperties = @()
                    try {
                        $advancedProperties = @(Get-NetAdapterAdvancedProperty -Name $adapterName -ErrorAction SilentlyContinue)
                    }
                    catch {
                    }

                    $ringProperties = @($advancedProperties | Where-Object { [string]$_.DisplayName -match 'ring' })
                    $bufferProperties = @($advancedProperties | Where-Object { [string]$_.DisplayName -match 'buffer' })

                    $vmxnet3Adapters += [pscustomobject]@{
                        Name                  = $adapterName
                        InterfaceDescription  = [string]$adapter.InterfaceDescription
                        DriverDescription     = [string]$adapter.DriverDescription
                        Status                = [string]$adapter.Status
                        LinkSpeed             = [string]$adapter.LinkSpeed
                        DiscardedPacketsTotal = $discardTotal
                        DiscardCounters       = $discardDetails
                        RingProperties        = @($ringProperties | ForEach-Object {
                                [pscustomobject]@{
                                    DisplayName  = [string]$_.DisplayName
                                    DisplayValue = [string]$_.DisplayValue
                                    RegistryKey  = [string]$_.RegistryKeyword
                                }
                            })
                        BufferProperties      = @($bufferProperties | ForEach-Object {
                                [pscustomobject]@{
                                    DisplayName  = [string]$_.DisplayName
                                    DisplayValue = [string]$_.DisplayValue
                                    RegistryKey  = [string]$_.RegistryKeyword
                                }
                            })
                        HasRingProperties     = (@($ringProperties).Count -gt 0)
                        HasBufferProperties   = (@($bufferProperties).Count -gt 0)
                    }
                }
            }
            catch {
            }
        }

        $smb1Value = $null
        $smbServerRequireSecuritySignature = $null
        try {
            $smbServerParams = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ErrorAction SilentlyContinue
            if ($null -ne $smbServerParams) {
                if ($smbServerParams.PSObject.Properties.Name -contains 'SMB1') {
                    $smb1Value = [int]$smbServerParams.SMB1
                }
                if ($smbServerParams.PSObject.Properties.Name -contains 'RequireSecuritySignature') {
                    $smbServerRequireSecuritySignature = [int]$smbServerParams.RequireSecuritySignature
                }
            }
        }
        catch {
        }

        $smbClientRequireSecuritySignature = $null
        try {
            $smbClientParams = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -ErrorAction SilentlyContinue
            if ($null -ne $smbClientParams -and $smbClientParams.PSObject.Properties.Name -contains 'RequireSecuritySignature') {
                $smbClientRequireSecuritySignature = [int]$smbClientParams.RequireSecuritySignature
            }
        }
        catch {
        }

        $ldapClientIntegrity = $null
        try {
            $ldapParams = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP' -ErrorAction SilentlyContinue
            if ($null -ne $ldapParams -and $ldapParams.PSObject.Properties.Name -contains 'LdapClientIntegrity') {
                $ldapClientIntegrity = [int]$ldapParams.LdapClientIntegrity
            }
        }
        catch {
        }

        $netBiosInterfaceOptions = @()
        try {
            $netBtInterfacesPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
            if (Test-Path -Path $netBtInterfacesPath) {
                foreach ($netBtInterface in @(Get-ChildItem -Path $netBtInterfacesPath -ErrorAction SilentlyContinue)) {
                    $netBtProps = Get-ItemProperty -Path $netBtInterface.PSPath -ErrorAction SilentlyContinue
                    if ($null -ne $netBtProps -and $netBtProps.PSObject.Properties.Name -contains 'NetbiosOptions') {
                        $netBiosInterfaceOptions += [pscustomobject]@{
                            Interface      = [string]$netBtInterface.PSChildName
                            NetbiosOptions = [int]$netBtProps.NetbiosOptions
                        }
                    }
                }
            }
        }
        catch {
        }

        $lapsLegacyEnabled = $null
        $lapsWindowsBackupDirectory = $null
        try {
            $lapsLegacyPolicy = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' -ErrorAction SilentlyContinue
            if ($null -ne $lapsLegacyPolicy -and $lapsLegacyPolicy.PSObject.Properties.Name -contains 'AdmPwdEnabled') {
                $lapsLegacyEnabled = ([int]$lapsLegacyPolicy.AdmPwdEnabled -eq 1)
            }
        }
        catch {
        }
        try {
            $lapsWindowsPolicy = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Policies\LAPS' -ErrorAction SilentlyContinue
            if ($null -ne $lapsWindowsPolicy -and $lapsWindowsPolicy.PSObject.Properties.Name -contains 'BackupDirectory') {
                $lapsWindowsBackupDirectory = [int]$lapsWindowsPolicy.BackupDirectory
            }
        }
        catch {
        }

        $firewallProfiles = @()
        $firewallAllProfilesEnabled = $null
        if (Get-Command -Name Get-NetFirewallProfile -ErrorAction SilentlyContinue) {
            try {
                $EAprofiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue)
                foreach ($EAprofile in $EAprofiles) {
                    $firewallProfiles += [pscustomobject]@{
                        Name    = [string]$EAprofile.Name
                        Enabled = [bool]$EAprofile.Enabled
                    }
                }

                if ($EAprofiles.Count -gt 0) {
                    $enabledCount = @($EAprofiles | Where-Object { $_.Enabled -eq $true }).Count
                    $firewallAllProfilesEnabled = ($enabledCount -eq $EAprofiles.Count)
                }
            }
            catch {
            }
        }

        $llmnrValue = $null
        try {
            $dnsPolicy = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction SilentlyContinue
            if ($null -ne $dnsPolicy -and $dnsPolicy.PSObject.Properties.Name -contains 'EnableMulticast') {
                $llmnrValue = [int]$dnsPolicy.EnableMulticast
            }
        }
        catch {
        }

        $lmCompatibilityLevel = $null
        try {
            $lsaPolicy = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
            if ($null -ne $lsaPolicy -and $lsaPolicy.PSObject.Properties.Name -contains 'LmCompatibilityLevel') {
                $lmCompatibilityLevel = [int]$lsaPolicy.LmCompatibilityLevel
            }
        }
        catch {
        }

        $ntlmMinClientSec = $null
        $ntlmMinServerSec = $null
        try {
            $msvPolicy = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue
            if ($null -ne $msvPolicy) {
                if ($msvPolicy.PSObject.Properties.Name -contains 'NtlmMinClientSec') {
                    $ntlmMinClientSec = [int]$msvPolicy.NtlmMinClientSec
                }
                if ($msvPolicy.PSObject.Properties.Name -contains 'NtlmMinServerSec') {
                    $ntlmMinServerSec = [int]$msvPolicy.NtlmMinServerSec
                }
            }
        }
        catch {
        }

        $wdigestUseLogonCredential = $null
        try {
            $wdigestPolicy = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -ErrorAction SilentlyContinue
            if ($null -ne $wdigestPolicy -and $wdigestPolicy.PSObject.Properties.Name -contains 'UseLogonCredential') {
                $wdigestUseLogonCredential = [int]$wdigestPolicy.UseLogonCredential
            }
        }
        catch {
        }

        $rdpNlaRequired = $null
        try {
            $rdpTcp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue
            if ($null -ne $rdpTcp -and $rdpTcp.PSObject.Properties.Name -contains 'UserAuthentication') {
                $rdpNlaRequired = ([int]$rdpTcp.UserAuthentication -eq 1)
            }
        }
        catch {
        }

        $defenderRealtimeProtectionEnabled = $null
        $defenderAvailable = $false
        if (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue) {
            try {
                $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
                if ($null -ne $mpStatus) {
                    $defenderAvailable = $true
                    if ($mpStatus.PSObject.Properties.Name -contains 'RealTimeProtectionEnabled') {
                        $defenderRealtimeProtectionEnabled = [bool]$mpStatus.RealTimeProtectionEnabled
                    }
                }
            }
            catch {
            }
        }

        $defenderExclusionPaths = @()
        $defenderExclusionProcesses = @()
        if ($defenderAvailable -and (Get-Command -Name Get-MpPreference -ErrorAction SilentlyContinue)) {
            try {
                $mpPref = Get-MpPreference -ErrorAction SilentlyContinue
                if ($null -ne $mpPref) {
                    if ($mpPref.PSObject.Properties.Name -contains 'ExclusionPath' -and $null -ne $mpPref.ExclusionPath) {
                        $defenderExclusionPaths = @($mpPref.ExclusionPath | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
                    }
                    if ($mpPref.PSObject.Properties.Name -contains 'ExclusionProcess' -and $null -ne $mpPref.ExclusionProcess) {
                        $defenderExclusionProcesses = @($mpPref.ExclusionProcess | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { [string]$_ })
                    }
                }
            }
            catch {
            }
        }

        $credentialGuardEnabled = $null
        $credentialGuardSignals = @()
        try {
            $cgPolicy = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard' -ErrorAction SilentlyContinue
            if ($null -ne $cgPolicy -and $cgPolicy.PSObject.Properties.Name -contains 'Enabled') {
                $credentialGuardSignals += ([int]$cgPolicy.Enabled -eq 1)
            }
        }
        catch {
        }

        try {
            $lsaPolicy = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
            if ($null -ne $lsaPolicy -and $lsaPolicy.PSObject.Properties.Name -contains 'LsaCfgFlags') {
                $lsaCfgFlags = [int]$lsaPolicy.LsaCfgFlags
                if ($lsaCfgFlags -in @(1, 2)) {
                    $credentialGuardSignals += $true
                }
                elseif ($lsaCfgFlags -eq 0) {
                    $credentialGuardSignals += $false
                }
            }
        }
        catch {
        }

        try {
            if (Get-Command -Name Get-CimInstance -ErrorAction SilentlyContinue) {
                $deviceGuard = Get-EDCACimInstance -ClassName 'Win32_DeviceGuard' -Namespace 'root\Microsoft\Windows\DeviceGuard'
                if ($null -ne $deviceGuard -and $deviceGuard.PSObject.Properties.Name -contains 'SecurityServicesRunning' -and $null -ne $deviceGuard.SecurityServicesRunning) {
                    $runningSecurityServices = @($deviceGuard.SecurityServicesRunning | ForEach-Object { [int]$_ })
                    if ($runningSecurityServices.Count -gt 0) {
                        # Value 1 indicates that Credential Guard is running.
                        $credentialGuardSignals += ($runningSecurityServices -contains 1)
                    }
                }
            }
        }
        catch {
        }

        if ($credentialGuardSignals.Count -gt 0) {
            $credentialGuardEnabled = ($credentialGuardSignals -contains $true)
        }

        $scriptBlockLoggingEnabled = $null
        try {
            $psLogging = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue
            if ($null -ne $psLogging -and $psLogging.PSObject.Properties.Name -contains 'EnableScriptBlockLogging') {
                $scriptBlockLoggingEnabled = ([int]$psLogging.EnableScriptBlockLogging -eq 1)
            }
        }
        catch {
        }

        $moduleLoggingEnabled = $null
        $moduleLoggingAllModules = $null
        try {
            $modLogging = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -ErrorAction SilentlyContinue
            if ($null -ne $modLogging -and $modLogging.PSObject.Properties.Name -contains 'EnableModuleLogging') {
                $moduleLoggingEnabled = ([int]$modLogging.EnableModuleLogging -eq 1)
            }
            if ($moduleLoggingEnabled -eq $true) {
                $modNames = Get-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' -ErrorAction SilentlyContinue
                if ($null -ne $modNames) {
                    $moduleLoggingAllModules = ($modNames.GetValueNames() -contains '*')
                }
                else {
                    $moduleLoggingAllModules = $false
                }
            }
        }
        catch {
        }

        $netFrameworkRelease = $null
        try {
            $netReg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release -ErrorAction SilentlyContinue
            if ($null -ne $netReg -and $netReg.PSObject.Properties.Name -contains 'Release') {
                $netFrameworkRelease = [int]$netReg.Release
            }
        }
        catch {
        }

        $schUseStrongCrypto64 = $null
        $schUseStrongCrypto32 = $null
        try {
            $reg64 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name SchUseStrongCrypto -ErrorAction SilentlyContinue
            if ($null -ne $reg64 -and $reg64.PSObject.Properties.Name -contains 'SchUseStrongCrypto') {
                $schUseStrongCrypto64 = [int]$reg64.SchUseStrongCrypto
            }
        }
        catch {
        }
        try {
            $reg32 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name SchUseStrongCrypto -ErrorAction SilentlyContinue
            if ($null -ne $reg32 -and $reg32.PSObject.Properties.Name -contains 'SchUseStrongCrypto') {
                $schUseStrongCrypto32 = [int]$reg32.SchUseStrongCrypto
            }
        }
        catch {
        }

        $schUseStrongCrypto64 = $null
        $schUseStrongCrypto32 = $null
        try {
            $reg64 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name SchUseStrongCrypto -ErrorAction SilentlyContinue
            if ($null -ne $reg64 -and $reg64.PSObject.Properties.Name -contains 'SchUseStrongCrypto') {
                $schUseStrongCrypto64 = [int]$reg64.SchUseStrongCrypto
            }
        }
        catch {
        }
        try {
            $reg32 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name SchUseStrongCrypto -ErrorAction SilentlyContinue
            if ($null -ne $reg32 -and $reg32.PSObject.Properties.Name -contains 'SchUseStrongCrypto') {
                $schUseStrongCrypto32 = [int]$reg32.SchUseStrongCrypto
            }
        }
        catch {
        }

        $tcpKeepAliveTime = $null
        try {
            $tcpParameters = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -ErrorAction SilentlyContinue
            if ($null -ne $tcpParameters -and $tcpParameters.PSObject.Properties.Name -contains 'KeepAliveTime') {
                $tcpKeepAliveTime = [int]$tcpParameters.KeepAliveTime
            }
        }
        catch {
        }

        $tcpAckFrequencyAdapters = @()
        try {
            $nicConfigs = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPEnabled })
            foreach ($nic in $nicConfigs) {
                $guid = [string]$nic.SettingID
                $regPath = ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{0}' -f $guid)
                $value = $null
                if (Test-Path -Path $regPath) {
                    $regItem = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                    if ($null -ne $regItem -and $regItem.PSObject.Properties.Name -contains 'TcpAckFrequency') {
                        $value = [int]$regItem.TcpAckFrequency
                    }
                }
                $tcpAckFrequencyAdapters += [pscustomobject]@{
                    AdapterDescription = [string]$nic.Description
                    Guid               = $guid
                    TcpAckFrequency    = $value
                }
            }
        }
        catch {
        }

        $rpcMinConnectionTimeout = $null
        try {
            $rpcPolicy = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\RPC' -ErrorAction SilentlyContinue
            if ($null -ne $rpcPolicy -and $rpcPolicy.PSObject.Properties.Name -contains 'MinimumConnectionTimeout') {
                $rpcMinConnectionTimeout = [int]$rpcPolicy.MinimumConnectionTimeout
            }
        }
        catch {
        }

        $ipv6DisabledComponents = $null
        try {
            $ipv6Parameters = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -ErrorAction SilentlyContinue
            if ($null -ne $ipv6Parameters -and $ipv6Parameters.PSObject.Properties.Name -contains 'DisabledComponents') {
                $ipv6DisabledComponents = [int]$ipv6Parameters.DisabledComponents
            }
        }
        catch {
        }

        $disableRootAutoUpdate = $null
        try {
            $authRootPolicy = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot' -ErrorAction SilentlyContinue
            if ($null -ne $authRootPolicy -and $authRootPolicy.PSObject.Properties.Name -contains 'DisableRootAutoUpdate') {
                $disableRootAutoUpdate = [int]$authRootPolicy.DisableRootAutoUpdate
            }
        }
        catch {
        }

        $numaGroupSizeOptimization = $null
        try {
            $kernelSettings = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel' -ErrorAction SilentlyContinue
            if ($null -ne $kernelSettings -and $kernelSettings.PSObject.Properties.Name -contains 'NumaGroupSizeOptimization') {
                $numaGroupSizeOptimization = [int]$kernelSettings.NumaGroupSizeOptimization
            }
        }
        catch {
        }

        $ctsProcessorAffinityPercentage = $null
        try {
            $ctsSettings = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Search\SystemParameters' -ErrorAction SilentlyContinue
            if ($null -ne $ctsSettings -and $ctsSettings.PSObject.Properties.Name -contains 'CtsProcessorAffinityPercentage') {
                $ctsProcessorAffinityPercentage = [int]$ctsSettings.CtsProcessorAffinityPercentage
            }
        }
        catch {
        }

        $disableAsyncNotification = $null
        try {
            $exchangeRootSettings = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15' -ErrorAction SilentlyContinue
            if ($null -ne $exchangeRootSettings -and $exchangeRootSettings.PSObject.Properties.Name -contains 'DisableAsyncNotification') {
                $disableAsyncNotification = [int]$exchangeRootSettings.DisableAsyncNotification
            }
        }
        catch {
        }

        $allowInsecureRenegoClients = $null
        $allowInsecureRenegoServers = $null
        try {
            $schannelPolicy = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' -ErrorAction SilentlyContinue
            if ($null -ne $schannelPolicy) {
                if ($schannelPolicy.PSObject.Properties.Name -contains 'AllowInsecureRenegoClients') {
                    $allowInsecureRenegoClients = [int]$schannelPolicy.AllowInsecureRenegoClients
                }
                if ($schannelPolicy.PSObject.Properties.Name -contains 'AllowInsecureRenegoServers') {
                    $allowInsecureRenegoServers = [int]$schannelPolicy.AllowInsecureRenegoServers
                }
            }
        }
        catch {
        }

        $weakCipherStates = @()
        foreach ($cipherName in @('NULL', 'DES 56/56', 'RC4 40/128', 'RC4 56/128', 'RC4 64/128', 'RC4 128/128', 'Triple DES 168')) {
            $cipherEnabled = $null
            try {
                $cipherKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipherName"
                if (Test-Path -Path $cipherKey) {
                    $cipherItem = Get-ItemProperty -Path $cipherKey -ErrorAction SilentlyContinue
                    if ($null -ne $cipherItem -and $cipherItem.PSObject.Properties.Name -contains 'Enabled') {
                        $cipherEnabled = if ([long]$cipherItem.Enabled -eq 0) { 0 } else { 1 }
                    }
                }
            }
            catch {
            }
            $weakCipherStates += [pscustomobject]@{ Name = $cipherName; Enabled = $cipherEnabled }
        }

        $weakHashStates = @()
        foreach ($hashName in @('MD5', 'SHA')) {
            $hashEnabled = $null
            try {
                $hashKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\$hashName"
                if (Test-Path -Path $hashKey) {
                    $hashItem = Get-ItemProperty -Path $hashKey -ErrorAction SilentlyContinue
                    if ($null -ne $hashItem -and $hashItem.PSObject.Properties.Name -contains 'Enabled') {
                        $hashEnabled = if ([long]$hashItem.Enabled -eq 0) { 0 } else { 1 }
                    }
                }
            }
            catch {
            }
            $weakHashStates += [pscustomobject]@{ Name = $hashName; Enabled = $hashEnabled }
        }

        $weakKeyExchangeStates = @()
        foreach ($keaName in @('PKCS')) {
            $keaEnabled = $null
            try {
                $keaKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\$keaName"
                if (Test-Path -Path $keaKey) {
                    $keaItem = Get-ItemProperty -Path $keaKey -ErrorAction SilentlyContinue
                    if ($null -ne $keaItem -and $keaItem.PSObject.Properties.Name -contains 'Enabled') {
                        $keaEnabled = if ([long]$keaItem.Enabled -eq 0) { 0 } else { 1 }
                    }
                }
            }
            catch {
            }
            $weakKeyExchangeStates += [pscustomobject]@{ Name = $keaName; Enabled = $keaEnabled }
        }

        $kerberosEncryptionTypes = $null
        try {
            $kerbPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            if (Test-Path -Path $kerbPath) {
                $kerbItem = Get-ItemProperty -Path $kerbPath -Name SupportedEncryptionTypes -ErrorAction SilentlyContinue
                if ($null -ne $kerbItem -and $kerbItem.PSObject.Properties.Name -contains 'SupportedEncryptionTypes') {
                    $kerberosEncryptionTypes = [int]$kerbItem.SupportedEncryptionTypes
                }
            }
        }
        catch {
        }

        $cipherSuiteOrder = $null
        if (Get-Command -Name Get-TlsCipherSuite -ErrorAction SilentlyContinue) {
            try {
                $allSuites = @(Get-TlsCipherSuite -ErrorAction SilentlyContinue)
                # Treat suites without a Protocol property, or those not labelled TLS 1.3, as TLS 1.2.
                $tls12Suites = @($allSuites | Where-Object { -not ($_.PSObject.Properties.Name -contains 'Protocol') -or [string]$_.Protocol -ne 'TLS 1.3' })
                # Keep only suites that expose a non-empty Name property (some CimInstances may lack it).
                $tls12Suites = @($tls12Suites | Where-Object { ($_.PSObject.Properties.Name -contains 'Name') -and -not [string]::IsNullOrWhiteSpace([string]$_.Name) })
                $nonPfsSuites = @($tls12Suites | Where-Object { $_.Name -notmatch 'ECDHE|DHE' } | Select-Object -ExpandProperty Name)
                # Find DHE (non-ECDHE) suites that appear before the first ECDHE suite.
                $firstEcdheIndex = -1
                for ($i = 0; $i -lt $tls12Suites.Count; $i++) {
                    if ($tls12Suites[$i].Name -match 'ECDHE') { $firstEcdheIndex = $i; break }
                }
                $dheBeforeEcdhe = @()
                if ($firstEcdheIndex -gt 0) {
                    $dheBeforeEcdhe = @($tls12Suites[0..($firstEcdheIndex - 1)] | Where-Object { $_.Name -match '\bDHE\b' -and $_.Name -notmatch 'ECDHE' } | Select-Object -ExpandProperty Name)
                }
                $cipherSuiteOrder = [pscustomobject]@{
                    QuerySucceeded = $true
                    Tls12Suites    = @($tls12Suites | Select-Object -ExpandProperty Name)
                    NonPfsSuites   = $nonPfsSuites
                    DheBeforeEcdhe = $dheBeforeEcdhe
                }
            }
            catch {
                $cipherSuiteOrder = [pscustomobject]@{
                    QuerySucceeded = $false
                    Error          = $_.Exception.Message
                }
            }
        }

        $serializedDataSigningEnabled = $null
        try {
            $diagnosticSettings = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Diagnostics' -ErrorAction SilentlyContinue
            if ($null -ne $diagnosticSettings -and $diagnosticSettings.PSObject.Properties.Name -contains 'EnableSerializationDataSigning') {
                $serializedDataSigningEnabled = ([int]$diagnosticSettings.EnableSerializationDataSigning -eq 1)
            }
        }
        catch {
        }

        $sleepyNicNonCompliantAdapters = @()
        $sleepyNicAdapterCount = 0
        $sleepyNicCommandAvailable = $false
        if (Get-Command -Name Get-NetAdapter -ErrorAction SilentlyContinue) {
            $sleepyNicCommandAvailable = $true
            try {
                $pnpByInterfaceDescription = @{}
                $nicClassKeyPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002bE10318}'
                $nicClassKeys = @(Get-ChildItem -Path $nicClassKeyPath -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^\d{4}$' })
                foreach ($nicClassKey in $nicClassKeys) {
                    $nicClassProperties = Get-ItemProperty -Path $nicClassKey.PSPath -ErrorAction SilentlyContinue
                    if ($null -eq $nicClassProperties) {
                        continue
                    }

                    $driverDescription = ''
                    if ($nicClassProperties.PSObject.Properties.Name -contains 'DriverDesc') {
                        $driverDescription = [string]$nicClassProperties.DriverDesc
                    }

                    if ([string]::IsNullOrWhiteSpace($driverDescription)) {
                        continue
                    }

                    $pnpCapabilities = $null
                    if ($nicClassProperties.PSObject.Properties.Name -contains 'PnPCapabilities') {
                        $pnpCapabilities = [int]$nicClassProperties.PnPCapabilities
                    }
                    $pnpByInterfaceDescription[$driverDescription.Trim().ToLowerInvariant()] = $pnpCapabilities
                }

                $netAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
                foreach ($netAdapter in $netAdapters) {
                    if ([string]$netAdapter.InterfaceDescription -eq 'Remote NDIS Compatible Device') {
                        continue
                    }

                    $sleepyNicAdapterCount++
                    $adapterDescriptionKey = ([string]$netAdapter.InterfaceDescription).Trim().ToLowerInvariant()
                    $adapterPnpCapabilities = $null
                    if ($pnpByInterfaceDescription.ContainsKey($adapterDescriptionKey)) {
                        $adapterPnpCapabilities = $pnpByInterfaceDescription[$adapterDescriptionKey]
                    }

                    $sleepyNicDisabled = ($adapterPnpCapabilities -in @(24, 280))
                    if (-not $sleepyNicDisabled) {
                        $sleepyNicNonCompliantAdapters += [pscustomobject]@{
                            Name            = [string]$netAdapter.Name
                            PnPCapabilities = $adapterPnpCapabilities
                        }
                    }
                }
            }
            catch {
            }
        }

        $sleepyNic = [pscustomobject]@{
            CommandAvailable     = $sleepyNicCommandAvailable
            AdapterCount         = $sleepyNicAdapterCount
            NonCompliantCount    = @($sleepyNicNonCompliantAdapters).Count
            NonCompliantAdapters = $sleepyNicNonCompliantAdapters
        }

        $visualCRedistributableEntries = @()
        try {
            $uninstallRegistryPaths = @(
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
            )
            foreach ($uninstallRegistryPath in $uninstallRegistryPaths) {
                foreach ($package in @(Get-ItemProperty -Path $uninstallRegistryPath -ErrorAction SilentlyContinue)) {
                    if (-not ($package.PSObject.Properties.Name -contains 'DisplayName')) {
                        continue
                    }

                    $displayName = [string]$package.DisplayName
                    if ([string]::IsNullOrWhiteSpace($displayName)) {
                        continue
                    }

                    if ($displayName -notmatch 'Visual C\+\+') {
                        continue
                    }

                    $year = $null
                    if ($displayName -match '2012') {
                        $year = 2012
                    }
                    elseif ($displayName -match '2013') {
                        $year = 2013
                    }

                    if ($null -eq $year) {
                        continue
                    }

                    $architecture = if ($displayName -match 'x64') { 'x64' } elseif ($displayName -match 'x86') { 'x86' } else { 'Unknown' }
                    $displayVersion = if ($package.PSObject.Properties.Name -contains 'DisplayVersion') { [string]$package.DisplayVersion } else { '' }
                    $entryKey = ('{0}|{1}|{2}' -f $displayName, $displayVersion, $architecture)
                    if (@($visualCRedistributableEntries | Where-Object { $_.EntryKey -eq $entryKey }).Count -eq 0) {
                        $visualCRedistributableEntries += [pscustomobject]@{
                            EntryKey       = $entryKey
                            DisplayName    = $displayName
                            DisplayVersion = $displayVersion
                            Year           = $year
                            Architecture   = $architecture
                        }
                    }
                }
            }
        }
        catch {
        }

        $visualCRedistributable = [pscustomobject]@{
            Entries    = @($visualCRedistributableEntries)
            Has2012x64 = (@($visualCRedistributableEntries | Where-Object { $_.Year -eq 2012 -and $_.Architecture -eq 'x64' }).Count -gt 0)
            Has2013x64 = (@($visualCRedistributableEntries | Where-Object { $_.Year -eq 2013 -and $_.Architecture -eq 'x64' }).Count -gt 0)
        }

        $exchangeComputerMembership = [pscustomobject]@{
            QuerySucceeded       = $false
            MissingGroups        = @()
            PresentGroups        = @()
            TrustedForDelegation = $null
        }

        $amsiProviderIds = @()
        $amsiProviderCount = $null
        try {
            $amsiProvidersPath = 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
            if (Test-Path -Path $amsiProvidersPath) {
                $amsiProviderIds = @(Get-ChildItem -Path $amsiProvidersPath -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.PSChildName })
                $amsiProviderCount = $amsiProviderIds.Count
            }
        }
        catch {
        }

        $eemsServicePresent = $false
        $eemsServiceStatus = $null
        $eemsServiceStartMode = $null
        try {
            $eemsService = Get-Service -Name 'MSExchangeMitigation' -ErrorAction SilentlyContinue
            if ($null -ne $eemsService) {
                $eemsServicePresent = $true
                $eemsServiceStatus = [string]$eemsService.Status
                $eemsServiceCim = Get-EDCACimInstance -ClassName Win32_Service -Filter "Name='MSExchangeMitigation'"
                if ($null -ne $eemsServiceCim -and $eemsServiceCim.PSObject.Properties.Name -contains 'StartMode') {
                    $eemsServiceStartMode = [string]$eemsServiceCim.StartMode
                }
            }
        }
        catch {
        }

        $pendingRebootLocations = @()
        try {
            if (Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
                $pendingRebootLocations += 'Component Based Servicing: RebootPending'
            }
        }
        catch {
        }
        try {
            if (Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
                $pendingRebootLocations += 'Windows Update: RebootRequired'
            }
        }
        catch {
        }
        try {
            $sessionManager = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction SilentlyContinue
            if ($null -ne $sessionManager -and $sessionManager.PSObject.Properties.Name -contains 'PendingFileRenameOperations' -and $null -ne $sessionManager.PendingFileRenameOperations) {
                $pendingRebootLocations += 'Session Manager: PendingFileRenameOperations'
            }
        }
        catch {
        }
        $pendingReboot = ($pendingRebootLocations.Count -gt 0)

        $msmqInstalledFeatures = @()
        $msmqQuerySucceeded = $false
        if (Get-Command -Name Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $msmqQuerySucceeded = $true
            try {
                foreach ($feature in @(Get-WindowsFeature -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @('NET-WCF-MSMQ-Activation45', 'MSMQ') -and $_.Installed })) {
                    $msmqInstalledFeatures += [string]$feature.Name
                }
            }
            catch {
            }
        }

        $serverType = 'Physical'
        $manufacturerText = [string]$cs.Manufacturer
        $modelText = [string]$cs.Model
        if ($manufacturerText -match 'VMware' -or $modelText -match 'VMware') {
            $serverType = 'VMware'
        }
        elseif ($manufacturerText -match 'Microsoft Corporation' -and $modelText -match 'Virtual') {
            $serverType = 'HyperV'
        }
        elseif ($modelText -match 'Virtual') {
            $serverType = 'Virtual'
        }

        $vmwareIntrospection = $null
        if ($serverType -eq 'VMware') {
            $vsepfltRunning = $false
            $vnetfltRunning = $false
            try {
                $vsepfltSvc = Get-Service -Name 'vsepflt' -ErrorAction SilentlyContinue
                if ($null -ne $vsepfltSvc) {
                    $vsepfltRunning = ($vsepfltSvc.Status -eq 'Running')
                }
                $vnetfltSvc = Get-Service -Name 'vnetflt' -ErrorAction SilentlyContinue
                if ($null -ne $vnetfltSvc) {
                    $vnetfltRunning = ($vnetfltSvc.Status -eq 'Running')
                }
            }
            catch {
            }
            $vmwareIntrospection = [pscustomobject]@{
                VsepfltRunning = $vsepfltRunning
                VnetfltRunning = $vnetfltRunning
            }
        }

        $dynamicMemoryDetected = $null
        $dynamicMemoryCounterName = $null
        $dynamicMemoryCounterValueMB = $null
        $dynamicMemoryDetails = 'Not applicable for detected server type.'
        if ($serverType -in @('HyperV', 'VMware')) {
            $dynamicMemoryCounterName = if ($serverType -eq 'HyperV') { '\Hyper-V Dynamic Memory Integration Service\Maximum Memory, MBytes' } else { '\VM Memory\Memory Reservation in MB' }
            if (Get-Command -Name Get-Counter -ErrorAction SilentlyContinue) {
                try {
                    $counterData = Get-Counter -Counter $dynamicMemoryCounterName -ErrorAction Stop
                    $counterSample = @($counterData.CounterSamples | Select-Object -First 1)
                    if ($counterSample.Count -gt 0) {
                        $dynamicMemoryCounterValueMB = [double]$counterSample[0].CookedValue
                        $counterValueGB = ($dynamicMemoryCounterValueMB / 1024)
                        $physicalMemoryGB = [double]($cs.TotalPhysicalMemory / 1GB)
                        $dynamicMemoryDetected = ([math]::Abs($counterValueGB - $physicalMemoryGB) -gt 0.25)
                        if ($dynamicMemoryDetected) {
                            $dynamicMemoryDetails = ('Dynamic memory appears enabled. Counter reports {0} GB while physical memory is {1} GB.' -f [math]::Round($counterValueGB, 2), [math]::Round($physicalMemoryGB, 2))
                        }
                        else {
                            $dynamicMemoryDetails = ('Dynamic memory not detected. Counter reports {0} GB and physical memory is {1} GB.' -f [math]::Round($counterValueGB, 2), [math]::Round($physicalMemoryGB, 2))
                        }
                    }
                    else {
                        $dynamicMemoryDetails = 'Dynamic memory counter did not return any samples.'
                    }
                }
                catch {
                    $dynamicMemoryDetails = ('Dynamic memory counter query failed: {0}' -f $_.Exception.Message)
                }
            }
            else {
                $dynamicMemoryDetails = 'Get-Counter cmdlet is unavailable.'
            }
        }

        $exchangeInfo.RpcMinConnectionTimeout = $rpcMinConnectionTimeout
        $exchangeInfo.TcpKeepAliveTime = $tcpKeepAliveTime
        $exchangeInfo.TcpAckFrequencyAdapters = $tcpAckFrequencyAdapters
        $exchangeInfo.NumaGroupSizeOptimization = $numaGroupSizeOptimization
        $exchangeInfo.IPv6DisabledComponents = $ipv6DisabledComponents
        $exchangeInfo.CtsProcessorAffinityPercentage = $ctsProcessorAffinityPercentage
        $exchangeInfo.DisableAsyncNotification = $disableAsyncNotification
        $exchangeInfo.DisableRootAutoUpdate = $disableRootAutoUpdate
        $exchangeInfo.SleepyNic = $sleepyNic
        $exchangeInfo.VisualCRedistributable = $visualCRedistributable
        $exchangeInfo.ExchangeComputerMembership = $exchangeComputerMembership
        $exchangeInfo.SerializedDataSigningEnabled = $serializedDataSigningEnabled
        $exchangeInfo.Amsi = [pscustomobject]@{
            ProviderCount             = $amsiProviderCount
            ProviderIds               = $amsiProviderIds
            DisabledBySettingOverride = $null
        }
        $exchangeInfo.Eems = [pscustomobject]@{
            Present            = $eemsServicePresent
            Status             = $eemsServiceStatus
            StartMode          = $eemsServiceStartMode
            MitigationsEnabled = $null
        }

        $coreCount = 0
        $socketCount = 0
        foreach ($processor in @($cpu)) {
            $coreCount += [int]$processor.NumberOfCores
            $socketCount++
        }

        $osInfo = [pscustomobject]@{
            ComputerName              = $env:COMPUTERNAME
            Domain                    = $env:USERDOMAIN
            OSVersion                 = $os.Version
            OSCaption                 = $os.Caption
            LastBootUpTime            = $os.LastBootUpTime
            SystemDrive               = $systemDrive
            SystemVolume              = $systemVolume
            Volumes                   = $volumeItems
            Manufacturer              = $cs.Manufacturer
            Model                     = $cs.Model
            TotalPhysicalMemoryGB     = [math]::Round(($cs.TotalPhysicalMemory / 1GB), 2)
            NumberOfProcessorSockets  = $socketCount
            NumberOfCores             = $coreCount
            NumberOfLogicalProcessors = [int]$cs.NumberOfLogicalProcessors
            ExecutionPolicy           = [string](Get-ExecutionPolicy -Scope LocalMachine)
            PowerPlan                 = [pscustomobject]@{
                ActiveSchemeGuid   = $activePowerPlanGuid
                ActiveSchemeName   = $activePowerPlanName
                HighPerformanceSet = $highPerformanceSet
            }
            PageFile                  = [pscustomobject]@{
                Count = $pageFileItems.Count
                Items = $pageFileItems
            }
            NicRss                    = [pscustomobject]@{
                AdapterCount = $rssAdapterCount
                EnabledCount = $rssEnabledCount
                Adapters     = $rssDetails
            }
            VmxNet3                   = [pscustomobject]@{
                CommandAvailable = [bool]$vmxnet3CommandAvailable
                AdapterCount     = @($vmxnet3Adapters).Count
                Adapters         = $vmxnet3Adapters
            }
            CisPolicy                 = [pscustomobject]@{
                Smb1Value                         = $smb1Value
                FirewallProfiles                  = $firewallProfiles
                FirewallAllProfilesEnabled        = $firewallAllProfilesEnabled
                LlmnrEnableMulticast              = $llmnrValue
                LmCompatibilityLevel              = $lmCompatibilityLevel
                NtlmMinClientSec                  = $ntlmMinClientSec
                NtlmMinServerSec                  = $ntlmMinServerSec
                WdigestUseLogonCredential         = $wdigestUseLogonCredential
                RdpNlaRequired                    = $rdpNlaRequired
                DefenderAvailable                 = $defenderAvailable
                DefenderRtpEnabled                = $defenderRealtimeProtectionEnabled
                DefenderExclusionPaths            = $defenderExclusionPaths
                DefenderExclusionProcesses        = $defenderExclusionProcesses
                CredentialGuardEnabled            = $credentialGuardEnabled
                ScriptBlockLoggingEnabled         = $scriptBlockLoggingEnabled
                ModuleLoggingEnabled              = $moduleLoggingEnabled
                ModuleLoggingAllModules           = $moduleLoggingAllModules
                TcpKeepAlive                      = $tcpKeepAliveTime
                RpcMinConnectionTimeout           = $rpcMinConnectionTimeout
                IPv6DisabledComponents            = $ipv6DisabledComponents
                DisableRootAutoUpdate             = $disableRootAutoUpdate
                SmbServerRequireSecuritySignature = $smbServerRequireSecuritySignature
                SmbClientRequireSecuritySignature = $smbClientRequireSecuritySignature
                LdapClientIntegrity               = $ldapClientIntegrity
                NetBiosInterfaceOptions           = $netBiosInterfaceOptions
                LapsLegacyEnabled                 = $lapsLegacyEnabled
                LapsWindowsBackupDirectory        = $lapsWindowsBackupDirectory
            }
            PendingReboot             = [pscustomobject]@{
                Pending   = $pendingReboot
                Locations = $pendingRebootLocations
            }
            MsmqFeature               = [pscustomobject]@{
                QuerySucceeded    = $msmqQuerySucceeded
                InstalledFeatures = $msmqInstalledFeatures
                Installed         = ($msmqInstalledFeatures.Count -gt 0)
            }
            DynamicMemory             = [pscustomobject]@{
                ServerType     = $serverType
                IsVirtual      = ($serverType -ne 'Physical')
                Detected       = $dynamicMemoryDetected
                CounterName    = $dynamicMemoryCounterName
                CounterValueMB = $dynamicMemoryCounterValueMB
                Details        = $dynamicMemoryDetails
            }
            TlsHardening              = [pscustomobject]@{
                AllowInsecureRenegoClients = $allowInsecureRenegoClients
                AllowInsecureRenegoServers = $allowInsecureRenegoServers
                WeakCiphers                = $weakCipherStates
                WeakHashes                 = $weakHashStates
                WeakKeyExchange            = $weakKeyExchangeStates
                CipherSuiteOrder           = $cipherSuiteOrder
            }
            KerberosEncryptionTypes   = $kerberosEncryptionTypes
            NetFrameworkRelease       = $netFrameworkRelease
            SchUseStrongCrypto64      = $schUseStrongCrypto64
            SchUseStrongCrypto32      = $schUseStrongCrypto32
            VmwareIntrospection       = $vmwareIntrospection
        }

        $tlsPaths = @{
            Tls10 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server'
            Tls11 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server'
            Tls12 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server'
            Tls13 = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server'
        }
        $tlsRaw = @{}
        foreach ($key in $tlsPaths.Keys) {
            $enabled = $null
            if (Test-Path -Path $tlsPaths[$key]) {
                $item = Get-ItemProperty -Path $tlsPaths[$key] -ErrorAction SilentlyContinue
                $enabled = $item.Enabled
            }
            $tlsRaw[$key] = $enabled
        }

        $tls13CipherSuiteAvailable = $null
        if ($null -eq $tlsRaw.Tls13 -and (Get-Command -Name Get-TlsCipherSuite -ErrorAction SilentlyContinue)) {
            try {
                $tls13Suites = @(Get-TlsCipherSuite -ErrorAction SilentlyContinue | Where-Object { ($_.PSObject.Properties.Name -contains 'Protocol') -and [string]$_.Protocol -eq 'TLS 1.3' })
                $tls13CipherSuiteAvailable = ($tls13Suites.Count -gt 0)
            }
            catch {
            }
        }

        $tls13Enabled = $null
        $tls13EvidenceSource = 'Unknown'
        if ($null -ne $tlsRaw.Tls13) {
            $tls13Enabled = ($tlsRaw.Tls13 -eq 1)
            $tls13EvidenceSource = 'Registry'
        }
        elseif ($null -ne $tls13CipherSuiteAvailable) {
            $tls13Enabled = [bool]$tls13CipherSuiteAvailable
            $tls13EvidenceSource = 'CipherSuites'
        }

        $tlsInfo = [pscustomobject]@{
            Tls10Enabled        = ($tlsRaw.Tls10 -eq 1)
            Tls11Enabled        = ($tlsRaw.Tls11 -eq 1)
            Tls12Enabled        = ($tlsRaw.Tls12 -eq 1)
            Tls13Enabled        = $tls13Enabled
            Tls13EvidenceSource = $tls13EvidenceSource
            Raw                 = $tlsRaw
        }

        $services = @()
        foreach ($serviceName in @('MSExchangeIS', 'MSExchangeTransport')) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($null -eq $service) {
                $services += [pscustomobject]@{
                    Name   = $serviceName
                    Status = 'NotFound'
                }
            }
            else {
                $services += [pscustomobject]@{
                    Name   = $service.Name
                    Status = [string]$service.Status
                }
            }
        }

        $certificates = @()
        foreach ($cert in @(Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Select-Object -Property Subject, Thumbprint, NotAfter)) {
            $certificates += [pscustomobject]@{
                Subject    = $cert.Subject
                Thumbprint = $cert.Thumbprint
                NotAfter   = $cert.NotAfter
                IsExpired  = ($cert.NotAfter -lt (Get-Date))
            }
        }

        $setupKey = 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup'
        $hasExchangeInstall = Test-Path -Path $setupKey
        if ($hasExchangeInstall) {
            $exchangeInfo.IsExchangeServer = $true
        }
        else {
            $exchangeInfo.CollectionWarnings += 'Exchange installation not detected on target server.'
        }

        $exchangeInstallPath = $null
        $exchangeBinPath = $null
        if ($hasExchangeInstall) {
            try {
                $setupForPath = Get-ItemProperty -Path $setupKey -ErrorAction SilentlyContinue
                $pathCandidates = @()

                if ($null -ne $setupForPath) {
                    if ($setupForPath.PSObject.Properties.Name -contains 'MsiInstallPath') {
                        $pathCandidates += [string]$setupForPath.MsiInstallPath
                    }
                    if ($setupForPath.PSObject.Properties.Name -contains 'InstallPath') {
                        $pathCandidates += [string]$setupForPath.InstallPath
                    }
                    if ($setupForPath.PSObject.Properties.Name -contains 'SetupBinPath') {
                        $pathCandidates += [string]$setupForPath.SetupBinPath
                    }
                }

                if (-not [string]::IsNullOrWhiteSpace([string]$env:ExchangeInstallPath)) {
                    $pathCandidates += [string]$env:ExchangeInstallPath
                }

                foreach ($pathCandidate in $pathCandidates) {
                    if ([string]::IsNullOrWhiteSpace($pathCandidate)) {
                        continue
                    }

                    $normalizedPath = $pathCandidate.Trim().Trim('"')
                    if (-not (Test-Path -Path $normalizedPath)) {
                        continue
                    }

                    $leaf = [string](Split-Path -Path $normalizedPath -Leaf)
                    if ($leaf.Equals('bin', [System.StringComparison]::OrdinalIgnoreCase)) {
                        $exchangeBinPath = $normalizedPath
                        $exchangeInstallPath = Split-Path -Path $normalizedPath -Parent
                    }
                    else {
                        $exchangeInstallPath = $normalizedPath
                        $candidateBinPath = Join-Path -Path $exchangeInstallPath -ChildPath 'bin'
                        if (Test-Path -Path $candidateBinPath) {
                            $exchangeBinPath = $candidateBinPath
                        }
                    }

                    if (-not [string]::IsNullOrWhiteSpace($exchangeInstallPath) -and -not [string]::IsNullOrWhiteSpace($exchangeBinPath)) {
                        break
                    }
                }
            }
            catch {
                $exchangeInfo.CollectionWarnings += ('Exchange install path resolution failed: ' + $_.Exception.Message)
            }

            if ([string]::IsNullOrWhiteSpace($exchangeBinPath)) {
                $exchangeInfo.CollectionWarnings += 'Exchange installation detected but bin path could not be resolved from setup registry.'
            }
        }

        if ($hasExchangeInstall -and -not (Get-Command -Name Get-ExchangeServer -ErrorAction SilentlyContinue)) {
            try {
                if ($exchangeBinPath) {
                    $exShellPsc1 = Join-Path -Path $exchangeBinPath -ChildPath 'exShell.psc1'
                    if (Test-Path -Path $exShellPsc1) {
                        [xml]$psSnapIns = Get-Content -Path $exShellPsc1 -ErrorAction Stop
                        foreach ($psSnapIn in $psSnapIns.PSConsoleFile.PSSnapIns.PSSnapIn) {
                            try {
                                Add-PSSnapin -Name $psSnapIn.Name -ErrorAction Stop
                            }
                            catch {
                                # Ignore already-loaded snap-ins.
                            }
                        }
                    }

                    $exchangePs1 = Join-Path -Path $exchangeBinPath -ChildPath 'Exchange.ps1'
                    if (Test-Path -Path $exchangePs1) {
                        Import-Module $exchangePs1 -ErrorAction SilentlyContinue
                    }
                }
            }
            catch {
                $exchangeInfo.CollectionWarnings += ('Exchange shell bootstrap failed: ' + $_.Exception.Message)
            }
        }

        if ($hasExchangeInstall -and -not (Get-Command -Name Get-ExchangeServer -ErrorAction SilentlyContinue)) {
            try {
                Add-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction Stop
            }
            catch {
            }
        }

        if ($hasExchangeInstall -and -not (Get-Command -Name Get-ExchangeServer -ErrorAction SilentlyContinue)) {
            try {
                $setup = Get-ItemProperty -Path $setupKey -ErrorAction Stop
                $major = $null
                $minor = $null
                $buildMajor = $null
                $buildMinor = $null

                if ($setup.PSObject.Properties.Name -contains 'MsiProductMajor') { $major = $setup.MsiProductMajor }
                if ($setup.PSObject.Properties.Name -contains 'MsiProductMinor') { $minor = $setup.MsiProductMinor }
                if ($setup.PSObject.Properties.Name -contains 'MsiBuildMajor') { $buildMajor = $setup.MsiBuildMajor }
                if ($setup.PSObject.Properties.Name -contains 'MsiBuildMinor') { $buildMinor = $setup.MsiBuildMinor }

                if ($null -ne $major -and $null -ne $minor -and $null -ne $buildMajor -and $null -ne $buildMinor) {
                    $exchangeInfo.AdminDisplayVersion = ('Version {0}.{1} (Build {2}.{3})' -f [int]$major, [int]$minor, [int]$buildMajor, [int]$buildMinor)
                }

                if (($setup.PSObject.Properties.Name -contains 'OwaVersion') -and -not [string]::IsNullOrWhiteSpace([string]$setup.OwaVersion)) {
                    $exchangeInfo.BuildNumber = [string]$setup.OwaVersion
                }

                if ($setup.PSObject.Properties.Name -contains 'Edition') {
                    $exchangeInfo.Edition = [string]$setup.Edition
                }

                if ($null -ne $major -and $null -ne $minor) {
                    if ([int]$major -eq 15 -and [int]$minor -eq 1) {
                        $exchangeInfo.ProductLine = 'Exchange2016'
                    }
                    elseif ([int]$major -eq 15 -and [int]$minor -eq 2) {
                        $isSe = $false
                        if ($setup.PSObject.Properties.Name -contains 'IsExchangeServerSubscriptionEdition') {
                            $isSe = [bool]$setup.IsExchangeServerSubscriptionEdition
                        }
                        if (-not $isSe -and $null -ne $buildMajor -and [int]$buildMajor -ge 2562) {
                            # Exchange SE builds can be identified by 15.2 build train even when explicit SE flags are unavailable.
                            $isSe = $true
                        }
                        $exchangeInfo.ProductLine = if ($isSe) { 'ExchangeSE' } else { 'Exchange2019' }
                    }
                }

                $exchangeInfo.CollectionWarnings += 'Exchange cmdlets unavailable; build metadata collected from setup registry.'
            }
            catch {
                $exchangeInfo.CollectionWarnings += ('Exchange setup registry fallback failed: ' + $_.Exception.Message)
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($exchangeInstallPath)) {
            $exchangeInfo.InstallPath = $exchangeInstallPath
            if ([string]::IsNullOrWhiteSpace($exchangeInfo.AuditLogPath)) {
                $defaultAuditLogPath = $exchangeInstallPath.TrimEnd('\') + '\Logging'
                $exchangeInfo.AuditLogPath = $defaultAuditLogPath
                if (Test-Path -LiteralPath $defaultAuditLogPath) {
                    try {
                        $defaultAuditAcl = Get-Acl -Path $defaultAuditLogPath -ErrorAction Stop
                        $exchangeInfo.AuditLogPathAcl = @($defaultAuditAcl.Access | ForEach-Object {
                                [pscustomobject]@{
                                    IdentityReference = [string]$_.IdentityReference
                                    FileSystemRights  = [string]$_.FileSystemRights
                                    AccessControlType = [string]$_.AccessControlType
                                    IsInherited       = [bool]$_.IsInherited
                                }
                            })
                    }
                    catch {
                        $exchangeInfo.CollectionWarnings += ('Get-Acl for default AuditLogPath failed: ' + $_.Exception.Message)
                    }
                }
            }
            try {
                $installPathAcl = Get-Acl -Path $exchangeInstallPath -ErrorAction Stop
                $exchangeInfo.InstallPathAcl = @($installPathAcl.Access | ForEach-Object {
                        [pscustomobject]@{
                            IdentityReference = [string]$_.IdentityReference
                            FileSystemRights  = [string]$_.FileSystemRights
                            AccessControlType = [string]$_.AccessControlType
                            IsInherited       = [bool]$_.IsInherited
                        }
                    })
            }
            catch {
                $exchangeInfo.CollectionWarnings += ('Get-Acl for InstallPath failed: ' + $_.Exception.Message)
            }

            $hstsSites = @()
            try {
                $appHostConfigPath = Join-Path -Path $env:WINDIR -ChildPath 'System32\inetsrv\config\applicationHost.config'
                if (Test-Path -Path $appHostConfigPath) {
                    [xml]$appHostXml = Get-Content -Path $appHostConfigPath -Raw -Encoding UTF8 -ErrorAction Stop
                    $siteNodes = @($appHostXml.configuration.'system.applicationHost'.sites.site)
                    $locationNodes = @($appHostXml.configuration.location)

                    foreach ($siteNode in $siteNodes) {
                        $siteName = [string]$siteNode.name
                        if ([string]::IsNullOrWhiteSpace($siteName)) {
                            continue
                        }

                        $nativeEnabled = $false
                        $nativeMaxAge = $null
                        $nativeIncludeSubDomains = $null
                        $nativePreload = $null
                        $nativeRedirectHttpToHttps = $null

                        $nativeHstsNode = $siteNode.SelectSingleNode('hsts')
                        if ($null -ne $nativeHstsNode -and $null -ne $nativeHstsNode.Attributes) {
                            $enabledAttr = $nativeHstsNode.Attributes['enabled']
                            if ($null -ne $enabledAttr) {
                                $tmpBool = $false
                                if ([bool]::TryParse([string]$enabledAttr.Value, [ref]$tmpBool)) {
                                    $nativeEnabled = $tmpBool
                                }
                            }

                            $maxAgeAttr = $nativeHstsNode.Attributes['max-age']
                            if ($null -ne $maxAgeAttr) {
                                $tmpInt = 0
                                if ([int]::TryParse([string]$maxAgeAttr.Value, [ref]$tmpInt)) {
                                    $nativeMaxAge = $tmpInt
                                }
                            }

                            foreach ($boolAttr in @('includeSubDomains', 'preload', 'redirectHttpToHttps')) {
                                $attrValue = $nativeHstsNode.Attributes[$boolAttr]
                                if ($null -ne $attrValue) {
                                    $tmpBool = $false
                                    if ([bool]::TryParse([string]$attrValue.Value, [ref]$tmpBool)) {
                                        switch ($boolAttr) {
                                            'includeSubDomains' { $nativeIncludeSubDomains = $tmpBool }
                                            'preload' { $nativePreload = $tmpBool }
                                            'redirectHttpToHttps' { $nativeRedirectHttpToHttps = $tmpBool }
                                        }
                                    }
                                }
                            }
                        }

                        $customHeaderValue = $null
                        foreach ($locationNode in @($locationNodes | Where-Object { [string]$_.path -eq $siteName })) {
                            foreach ($headerNode in @($locationNode.SelectNodes('system.webServer/httpProtocol/customHeaders/add'))) {
                                $headerName = [string]$headerNode.GetAttribute('name')
                                if ([string]::Equals($headerName, 'Strict-Transport-Security', [System.StringComparison]::OrdinalIgnoreCase)) {
                                    $customHeaderValue = [string]$headerNode.GetAttribute('value')
                                    break
                                }
                            }

                            if (-not [string]::IsNullOrWhiteSpace($customHeaderValue)) {
                                break
                            }
                        }

                        $customHeaderEnabled = -not [string]::IsNullOrWhiteSpace($customHeaderValue)
                        $customMaxAge = $null
                        $customIncludeSubDomains = $null
                        $customPreload = $null
                        $customRedirectHttpToHttps = $null
                        if ($customHeaderEnabled) {
                            $maxAgeMatch = [regex]::Match($customHeaderValue, 'max-age\s*=\s*(\d+)', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                            if ($maxAgeMatch.Success) {
                                $customMaxAge = [int]$maxAgeMatch.Groups[1].Value
                            }

                            $customIncludeSubDomains = ($customHeaderValue -match '(?i)(^|;)\s*includeSubDomains(\s*;|$)')
                            $customPreload = ($customHeaderValue -match '(?i)(^|;)\s*preload(\s*;|$)')
                            $customRedirectHttpToHttps = ($customHeaderValue -match '(?i)redirectHttpToHttps\s*=\s*true')
                        }

                        $effectiveEnabled = ($nativeEnabled -or $customHeaderEnabled)
                        $effectiveMaxAge = if ($null -ne $nativeMaxAge) { $nativeMaxAge } else { $customMaxAge }
                        $effectiveIncludeSubDomains = if ($null -ne $nativeIncludeSubDomains) { $nativeIncludeSubDomains } else { $customIncludeSubDomains }
                        $effectivePreload = if ($null -ne $nativePreload) { $nativePreload } else { $customPreload }
                        $effectiveRedirectHttpToHttps = if ($null -ne $nativeRedirectHttpToHttps) { $nativeRedirectHttpToHttps } else { $customRedirectHttpToHttps }

                        $hstsSites += [pscustomobject]@{
                            SiteName            = $siteName
                            NativeEnabled       = $nativeEnabled
                            CustomHeaderEnabled = $customHeaderEnabled
                            CustomHeaderValue   = $customHeaderValue
                            Enabled             = $effectiveEnabled
                            MaxAge              = $effectiveMaxAge
                            IncludeSubDomains   = $effectiveIncludeSubDomains
                            Preload             = $effectivePreload
                            RedirectHttpToHttps = $effectiveRedirectHttpToHttps
                        }
                    }
                }
            }
            catch {
                $exchangeInfo.CollectionWarnings += ('HSTS collection failed: ' + $_.Exception.Message)
            }

            $exchangeInfo.Hsts = [pscustomobject]@{
                SiteCount = @($hstsSites).Count
                Sites     = $hstsSites
            }

            $iisModuleRows = @()
            $iisModulesQuerySucceeded = $false
            $tokenCacheModuleLoaded = $null
            if (Get-Command -Name Get-WebGlobalModule -ErrorAction SilentlyContinue) {
                $iisModulesQuerySucceeded = $true
                try {
                    $globalModules = @(Get-WebGlobalModule)
                    $tokenCacheModuleLoaded = (@($globalModules | Where-Object {
                                [string]::Equals([string]$_.Name, 'TokenCacheModule', [System.StringComparison]::OrdinalIgnoreCase)
                            }).Count -gt 0)

                    foreach ($globalModule in $globalModules) {
                        $moduleName = [string]$globalModule.Name
                        $modulePath = [System.Environment]::ExpandEnvironmentVariables([string]$globalModule.Image)
                        $modulePathExists = (-not [string]::IsNullOrWhiteSpace($modulePath)) -and (Test-Path -Path $modulePath)
                        $signatureStatus = $null
                        $signatureSigner = $null
                        $isSigned = $null
                        $isMicrosoftSigned = $null

                        if ($modulePathExists) {
                            try {
                                $signature = Get-AuthenticodeSignature -FilePath $modulePath -ErrorAction SilentlyContinue
                                if ($null -ne $signature) {
                                    $signatureStatus = [string]$signature.Status
                                    $isSigned = ($signature.Status -ne [System.Management.Automation.SignatureStatus]::NotSigned)
                                    $subject = $null
                                    if ($null -ne $signature.SignerCertificate) {
                                        $subject = [string]$signature.SignerCertificate.Subject
                                    }
                                    if (-not [string]::IsNullOrWhiteSpace($subject)) {
                                        $signatureSigner = $subject
                                    }
                                    $isMicrosoftSigned = (-not [string]::IsNullOrWhiteSpace($subject)) -and ($subject -match 'Microsoft')
                                }
                            }
                            catch {
                            }
                        }

                        $iisModuleRows += [pscustomobject]@{
                            Name              = $moduleName
                            Path              = $modulePath
                            PathExists        = $modulePathExists
                            Signed            = $isSigned
                            SignatureStatus   = $signatureStatus
                            Signer            = $signatureSigner
                            IsMicrosoftSigned = $isMicrosoftSigned
                        }
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('IIS module collection failed: ' + $_.Exception.Message)
                }
            }

            $unsignedModuleCount = @($iisModuleRows | Where-Object { $_.Signed -eq $false }).Count
            $nonMicrosoftModuleCount = @($iisModuleRows | Where-Object { $_.Signed -eq $true -and $_.IsMicrosoftSigned -eq $false }).Count
            $invalidSignatureCount = @($iisModuleRows | Where-Object { $_.Signed -eq $true -and $null -ne $_.SignatureStatus -and $_.SignatureStatus -ne 'Valid' }).Count

            $exchangeInfo.IisModules = [pscustomobject]@{
                QuerySucceeded          = $iisModulesQuerySucceeded
                UnsignedCount           = $unsignedModuleCount
                NonMicrosoftSignedCount = $nonMicrosoftModuleCount
                InvalidSignatureCount   = $invalidSignatureCount
                Modules                 = $iisModuleRows
            }
            $exchangeInfo.TokenCacheModuleLoaded = $tokenCacheModuleLoaded

            $nodeRunnerConfigPath = Join-Path -Path $exchangeInstallPath -ChildPath 'Bin\Search\Ceres\Runtime\1.0\noderunner.exe.config'
            $nodeRunnerPresent = Test-Path -Path $nodeRunnerConfigPath
            $nodeRunnerConfigValid = $null
            $nodeRunnerMemoryLimitMB = $null
            if ($nodeRunnerPresent) {
                try {
                    [xml]$nodeRunnerConfigXml = Get-Content -Path $nodeRunnerConfigPath -Raw -Encoding UTF8 -ErrorAction Stop
                    $memoryLimitRaw = $nodeRunnerConfigXml.configuration.nodeRunnerSettings.memoryLimitMegabytes
                    if (-not [string]::IsNullOrWhiteSpace([string]$memoryLimitRaw)) {
                        $nodeRunnerMemoryLimitMB = [int]$memoryLimitRaw
                    }
                    $nodeRunnerConfigValid = $true
                }
                catch {
                    $nodeRunnerConfigValid = $false
                    $exchangeInfo.CollectionWarnings += ('noderunner.exe.config parse failed: ' + $_.Exception.Message)
                }
            }
            $exchangeInfo.NodeRunner = [pscustomobject]@{
                Present       = $nodeRunnerPresent
                ConfigValid   = $nodeRunnerConfigValid
                MemoryLimitMB = $nodeRunnerMemoryLimitMB
            }

            $mapiFeGcConfigPath = Join-Path -Path $exchangeInstallPath -ChildPath 'Bin\MSExchangeMapiFrontEndAppPool_CLRConfig.config'
            $mapiFeGcPresent = Test-Path -Path $mapiFeGcConfigPath
            $mapiFeGcServerEnabled = $null
            $mapiFeGcParseSucceeded = $null
            $mapiFeGcDetails = 'MAPI Front End GC mode configuration file not found.'
            if ($mapiFeGcPresent) {
                try {
                    $mapiFeGcRaw = Get-Content -Path $mapiFeGcConfigPath -Raw -Encoding UTF8 -ErrorAction Stop
                    $mapiFeGcMatch = [regex]::Match($mapiFeGcRaw, '<\s*gcServer\s+enabled\s*=\s*"(true|false)"', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
                    if ($mapiFeGcMatch.Success) {
                        $mapiFeGcServerEnabled = [bool]::Parse($mapiFeGcMatch.Groups[1].Value)
                        $mapiFeGcParseSucceeded = $true
                        $mapiFeGcDetails = ('GCServer enabled={0}' -f $mapiFeGcServerEnabled)
                    }
                    else {
                        $mapiFeGcParseSucceeded = $false
                        $mapiFeGcDetails = 'gcServer enabled setting not found in MAPI Front End GC mode configuration file.'
                    }
                }
                catch {
                    $mapiFeGcParseSucceeded = $false
                    $mapiFeGcDetails = ('Failed to parse MAPI Front End GC mode configuration: {0}' -f $_.Exception.Message)
                }
            }

            $exchangeInfo.MapiFrontEndAppPoolGcMode = [pscustomobject]@{
                ConfigPath      = $mapiFeGcConfigPath
                Present         = $mapiFeGcPresent
                ParseSucceeded  = $mapiFeGcParseSucceeded
                GcServerEnabled = $mapiFeGcServerEnabled
                Details         = $mapiFeGcDetails
            }

            $fipFsEngineFolderPath = Join-Path -Path $exchangeInstallPath -ChildPath 'FIP-FS\Data\Engines\amd64\Microsoft\Bin'
            $fipFsEnginePathPresent = Test-Path -Path $fipFsEngineFolderPath
            $fipFsProblematicFolders = @()
            if ($fipFsEnginePathPresent) {
                try {
                    foreach ($engineFolder in @(Get-ChildItem -Path $fipFsEngineFolderPath -Directory -ErrorAction SilentlyContinue)) {
                        $engineVersion = 0
                        if ([int]::TryParse([string]$engineFolder.Name, [ref]$engineVersion) -and $engineVersion -ge 2201010000) {
                            $fipFsProblematicFolders += [string]$engineFolder.Name
                        }
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('FIP-FS engine inspection failed: ' + $_.Exception.Message)
                }
            }
            $exchangeInfo.FipFs = [pscustomobject]@{
                EngineFolderPath       = $fipFsEngineFolderPath
                EnginePathPresent      = $fipFsEnginePathPresent
                ProblematicEngineCount = $fipFsProblematicFolders.Count
                ProblematicEngineNames = $fipFsProblematicFolders
            }

            $iisConfigRelativePaths = @(
                'FrontEnd\HttpProxy\owa\web.config',
                'FrontEnd\HttpProxy\ecp\web.config',
                'FrontEnd\HttpProxy\EWS\web.config',
                'FrontEnd\HttpProxy\Autodiscover\web.config',
                'ClientAccess\owa\web.config',
                'ClientAccess\ecp\web.config',
                'ClientAccess\exchWeb\EWS\web.config',
                'ClientAccess\Autodiscover\web.config'
            )
            $iisMissingFiles = @()
            $iisInvalidFiles = @()
            foreach ($iisConfigRelativePath in $iisConfigRelativePaths) {
                $iisConfigPath = Join-Path -Path $exchangeInstallPath -ChildPath $iisConfigRelativePath
                if (-not (Test-Path -Path $iisConfigPath)) {
                    $iisMissingFiles += $iisConfigPath
                    continue
                }

                try {
                    [xml]$null = Get-Content -Path $iisConfigPath -Raw -Encoding UTF8 -ErrorAction Stop
                }
                catch {
                    $iisInvalidFiles += $iisConfigPath
                }
            }
            $exchangeInfo.IisWebConfig = [pscustomobject]@{
                CheckedCount = $iisConfigRelativePaths.Count
                MissingCount = $iisMissingFiles.Count
                InvalidCount = $iisInvalidFiles.Count
                MissingFiles = $iisMissingFiles
                InvalidFiles = $iisInvalidFiles
            }

            $unifiedContentConfigured = $null
            $unifiedContentDetails = 'UnifiedContent cleanup validation not performed.'
            $edgeTransportConfigPath = Join-Path -Path $exchangeInstallPath -ChildPath 'Bin\EdgeTransport.exe.config'
            $antiMalwareConfigPath = Join-Path -Path $exchangeInstallPath -ChildPath 'Bin\Monitoring\Config\AntiMalware.xml'
            if (-not (Test-Path -Path $edgeTransportConfigPath)) {
                $unifiedContentConfigured = $false
                $unifiedContentDetails = 'EdgeTransport.exe.config is missing.'
            }
            elseif (-not (Test-Path -Path $antiMalwareConfigPath)) {
                $unifiedContentConfigured = $false
                $unifiedContentDetails = 'AntiMalware.xml is missing.'
            }
            else {
                try {
                    [xml]$edgeTransportConfigXml = Get-Content -Path $edgeTransportConfigPath -Raw -Encoding UTF8 -ErrorAction Stop
                    [xml]$antiMalwareConfigXml = Get-Content -Path $antiMalwareConfigPath -Raw -Encoding UTF8 -ErrorAction Stop

                    $temporaryStoragePathSetting = ($edgeTransportConfigXml.configuration.appSettings.add | Where-Object { [string]$_.key -eq 'TemporaryStoragePath' } | Select-Object -First 1)
                    $temporaryStoragePath = if ($null -ne $temporaryStoragePathSetting) { [string]$temporaryStoragePathSetting.value } else { '' }
                    $cleanupFolderResponderPath = [string]$antiMalwareConfigXml.Definition.MaintenanceDefinition.ExtensionAttributes.CleanupFolderResponderFolderPaths

                    if ([string]::IsNullOrWhiteSpace($temporaryStoragePath) -or [string]::IsNullOrWhiteSpace($cleanupFolderResponderPath)) {
                        $unifiedContentConfigured = $false
                        $unifiedContentDetails = 'TemporaryStoragePath or CleanupFolderResponderFolderPaths is empty.'
                    }
                    else {
                        $expectedCleanupPath = (Join-Path -Path $temporaryStoragePath -ChildPath 'UnifiedContent')
                        $unifiedContentConfigured = ($cleanupFolderResponderPath -like ('*{0}*' -f $expectedCleanupPath))
                        $unifiedContentDetails = ('Expected cleanup path: {0}' -f $expectedCleanupPath)
                    }
                }
                catch {
                    $unifiedContentConfigured = $null
                    $unifiedContentDetails = 'UnifiedContent config parsing failed.'
                    $exchangeInfo.CollectionWarnings += ('UnifiedContent cleanup inspection failed: ' + $_.Exception.Message)
                }
            }
            $exchangeInfo.UnifiedContentCleanup = [pscustomobject]@{
                Configured = $unifiedContentConfigured
                Details    = $unifiedContentDetails
            }

            if (-not [string]::IsNullOrWhiteSpace($exchangeInstallPath)) {
                $bpConfigPath = Join-Path -Path $exchangeInstallPath -ChildPath 'Bin\EdgeTransport.exe.config'
                if (-not (Test-Path -Path $bpConfigPath)) {
                    $exchangeInfo.TransportBackPressure = [pscustomobject]@{
                        ConfigPresent                            = $false
                        NormalPriorityMessageExpirationTimeout   = $null
                        CriticalPriorityMessageExpirationTimeout = $null
                    }
                }
                else {
                    try {
                        [xml]$bpXml = Get-Content -Path $bpConfigPath -Raw -Encoding UTF8 -ErrorAction Stop
                        $bpNormal = ($bpXml.configuration.appSettings.add | Where-Object { [string]$_.key -eq 'NormalPriorityMessageExpirationTimeout' } | Select-Object -First 1)
                        $bpCritical = ($bpXml.configuration.appSettings.add | Where-Object { [string]$_.key -eq 'CriticalPriorityMessageExpirationTimeout' } | Select-Object -First 1)
                        $exchangeInfo.TransportBackPressure = [pscustomobject]@{
                            ConfigPresent                            = $true
                            NormalPriorityMessageExpirationTimeout   = if ($null -ne $bpNormal) { [string]$bpNormal.value }   else { $null }
                            CriticalPriorityMessageExpirationTimeout = if ($null -ne $bpCritical) { [string]$bpCritical.value } else { $null }
                        }
                    }
                    catch {
                        $exchangeInfo.TransportBackPressure = [pscustomobject]@{
                            ConfigPresent                            = $null
                            NormalPriorityMessageExpirationTimeout   = $null
                            CriticalPriorityMessageExpirationTimeout = $null
                        }
                        $exchangeInfo.CollectionWarnings += ('EdgeTransport.exe.config back pressure parse failed: ' + $_.Exception.Message)
                    }
                }
            }
        }

        if ($hasExchangeInstall) {
            try {
                $popService = Get-Service -Name MSExchangePOP3 -ErrorAction SilentlyContinue
                if ($null -ne $popService) {
                    $exchangeInfo.Pop3ServiceStatus = [string]$popService.Status
                }
            }
            catch {
            }

            try {
                $imapService = Get-Service -Name MSExchangeIMAP4 -ErrorAction SilentlyContinue
                if ($null -ne $imapService) {
                    $exchangeInfo.Imap4ServiceStatus = [string]$imapService.Status
                }
            }
            catch {
            }

            try {
                $msExchangeServices = @(Get-Service -Name 'MSExchange*' -ErrorAction SilentlyContinue)
                foreach ($svc in $msExchangeServices) {
                    $exchangeInfo.ExchangeServices += [pscustomobject]@{
                        Name      = [string]$svc.Name
                        Status    = [string]$svc.Status
                        StartType = [string]$svc.StartType
                    }
                }
            }
            catch {}
        }

        if ($collectExchangeCmdlets -and $hasExchangeInstall -and -not (Get-Command -Name Get-ExchangeServer -ErrorAction SilentlyContinue)) {
            try { Add-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction SilentlyContinue } catch {}
        }

        if ($collectExchangeCmdlets -and (Get-Command -Name Get-ExchangeServer -ErrorAction SilentlyContinue)) {
            $exchangeInfo.ExchangeCmdletsAvailable = $true
            try {
                $serverObject = Get-ExchangeServer -Identity $env:COMPUTERNAME -ErrorAction Stop
                $exchangeInfo.IsExchangeServer = $true
                $isEdge = ($serverObject.PSObject.Properties.Name -contains 'ServerRole') -and ([string]$serverObject.ServerRole -match 'Edge')
                $exchangeInfo.IsEdge = $isEdge
                $exchangeInfo.ServerRole = if ($isEdge) { 'Edge' } else { 'Mailbox' }
                $exchangeInfo.Name = $serverObject.Name
                $exchangeInfo.AdminDisplayVersion = [string]$serverObject.AdminDisplayVersion
                try {
                    $setupForBuild = Get-ItemProperty -Path $setupKey -ErrorAction Stop
                    if (($setupForBuild.PSObject.Properties.Name -contains 'OwaVersion') -and -not [string]::IsNullOrWhiteSpace([string]$setupForBuild.OwaVersion)) {
                        $exchangeInfo.BuildNumber = [string]$setupForBuild.OwaVersion
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('OwaVersion registry read failed: ' + $_.Exception.Message)
                }
                $exchangeInfo.Edition = [string]$serverObject.Edition
                $exchangeInfo.IsDagMember = ($serverObject.PSObject.Properties.Name -contains 'MemberOfDAG') -and -not [string]::IsNullOrWhiteSpace([string]$serverObject.MemberOfDAG)
                $exchangeInfo.DagName = if (($serverObject.PSObject.Properties.Name -contains 'MemberOfDAG') -and -not [string]::IsNullOrWhiteSpace([string]$serverObject.MemberOfDAG)) { [string]$serverObject.MemberOfDAG } else { '' }
                $exchangeInfo.AdSite = if ($serverObject.PSObject.Properties.Name -contains 'Site') { [string]$serverObject.Site } else { '' }
                if ($serverObject.PSObject.Properties.Name -contains 'ErrorReportingEnabled') {
                    $exchangeInfo.ErrorReportingEnabled = [bool]$serverObject.ErrorReportingEnabled
                }

                if ($exchangeInfo.AdminDisplayVersion -match 'Version 15\.1') {
                    $exchangeInfo.ProductLine = 'Exchange2016'
                }
                elseif ($exchangeInfo.AdminDisplayVersion -match 'Version 15\.2') {
                    $isSe = $false
                    if ($serverObject.PSObject.Properties.Name -contains 'IsExchangeServerSubscriptionEdition') {
                        $isSe = [bool]$serverObject.IsExchangeServerSubscriptionEdition
                    }
                    if (-not $isSe -and $exchangeInfo.AdminDisplayVersion -match 'Subscription|SE') {
                        $isSe = $true
                    }
                    if (-not $isSe -and $exchangeInfo.AdminDisplayVersion -match 'Build\s+(\d+)\.') {
                        if ([int]$matches[1] -ge 2562) {
                            $isSe = $true
                        }
                    }
                    $exchangeInfo.ProductLine = if ($isSe) { 'ExchangeSE' } else { 'Exchange2019' }
                }
            }
            catch {
                $exchangeInfo.CollectionWarnings += ('Get-ExchangeServer failed: ' + $_.Exception.Message)
            }

            foreach ($commandName in @('Get-MapiVirtualDirectory', 'Get-OwaVirtualDirectory', 'Get-EcpVirtualDirectory', 'Get-WebServicesVirtualDirectory', 'Get-ActiveSyncVirtualDirectory', 'Get-AutodiscoverVirtualDirectory')) {
                if (-not (Get-Command -Name $commandName -ErrorAction SilentlyContinue)) {
                    continue
                }

                try {
                    $items = & $commandName -Server $env:COMPUTERNAME -ErrorAction Stop
                    foreach ($item in $items) {
                        $exchangeInfo.ExtendedProtectionStatus += [pscustomobject]@{
                            VirtualDirectoryType            = $commandName
                            Identity                        = [string]$item.Identity
                            ExtendedProtectionTokenChecking = [string]$item.ExtendedProtectionTokenChecking
                            ExtendedProtectionFlags         = [string]$item.ExtendedProtectionFlags
                            ExtendedProtectionSPNList       = [string]$item.ExtendedProtectionSPNList
                            InternalAuthenticationMethods   = if ($item.PSObject.Properties.Name -contains 'InternalAuthenticationMethods') { [string]$item.InternalAuthenticationMethods } else { '' }
                            ExternalAuthenticationMethods   = if ($item.PSObject.Properties.Name -contains 'ExternalAuthenticationMethods') { [string]$item.ExternalAuthenticationMethods } else { '' }
                            IISAuthenticationMethods        = if ($item.PSObject.Properties.Name -contains 'IISAuthenticationMethods') { [string]$item.IISAuthenticationMethods } else { '' }
                        }
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('{0} failed: {1}' -f $commandName, $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-AdminAuditLogConfig -ErrorAction SilentlyContinue) {
                try {
                    $audit = Get-AdminAuditLogConfig -ErrorAction Stop
                    $exchangeInfo.AdminAuditLogEnabled = [bool]$audit.AdminAuditLogEnabled
                    if ($audit.PSObject.Properties.Name -contains 'AdminAuditLogPath' -and -not [string]::IsNullOrWhiteSpace([string]$audit.AdminAuditLogPath)) {
                        $exchangeInfo.AuditLogPath = [string]$audit.AdminAuditLogPath
                        try {
                            $auditLogAcl = Get-Acl -Path $exchangeInfo.AuditLogPath -ErrorAction Stop
                            $exchangeInfo.AuditLogPathAcl = @($auditLogAcl.Access | ForEach-Object {
                                    [pscustomobject]@{
                                        IdentityReference = [string]$_.IdentityReference
                                        FileSystemRights  = [string]$_.FileSystemRights
                                        AccessControlType = [string]$_.AccessControlType
                                        IsInherited       = [bool]$_.IsInherited
                                    }
                                })
                        }
                        catch {
                            $exchangeInfo.CollectionWarnings += ('Get-Acl for AuditLogPath failed: ' + $_.Exception.Message)
                        }
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-AdminAuditLogConfig failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-OutlookAnywhere -ErrorAction SilentlyContinue) {
                try {
                    $oaItems = @(Get-OutlookAnywhere -Server $env:COMPUTERNAME -ErrorAction Stop)
                    foreach ($oaItem in $oaItems) {
                        $exchangeInfo.OutlookAnywhereSSLOffloading += [pscustomobject]@{
                            Identity      = [string]$oaItem.Identity
                            SSLOffloading = if ($oaItem.PSObject.Properties.Name -contains 'SSLOffloading') { [nullable[bool]]$oaItem.SSLOffloading } else { $null }
                        }
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-OutlookAnywhere failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-OrganizationConfig -ErrorAction SilentlyContinue) {
                try {
                    $orgConfig = Get-OrganizationConfig -ErrorAction Stop
                    if ($orgConfig.PSObject.Properties.Name -contains 'OAuth2ClientProfileEnabled') {
                        $exchangeInfo.OAuth2ClientProfileEnabled = [bool]$orgConfig.OAuth2ClientProfileEnabled
                    }
                    if ($orgConfig.PSObject.Properties.Name -contains 'MitigationsEnabled' -and $null -ne $exchangeInfo.Eems) {
                        $exchangeInfo.Eems = [pscustomobject]@{
                            Present            = $exchangeInfo.Eems.Present
                            Status             = $exchangeInfo.Eems.Status
                            StartMode          = $exchangeInfo.Eems.StartMode
                            MitigationsEnabled = [bool]$orgConfig.MitigationsEnabled
                        }
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-OrganizationConfig failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-AcceptedDomain -ErrorAction SilentlyContinue) {
                try {
                    $acceptedDomains = @(Get-AcceptedDomain -ErrorAction Stop)
                    $domainSet = @{}
                    foreach ($acceptedDomain in $acceptedDomains) {
                        $domainValue = ''
                        if ($acceptedDomain.PSObject.Properties.Name -contains 'DomainName' -and $null -ne $acceptedDomain.DomainName) {
                            $domainValue = [string]$acceptedDomain.DomainName
                        }
                        elseif ($acceptedDomain.PSObject.Properties.Name -contains 'Name') {
                            $domainValue = [string]$acceptedDomain.Name
                        }

                        if ([string]::IsNullOrWhiteSpace($domainValue)) {
                            continue
                        }

                        $normalizedDomain = $domainValue.Trim().TrimEnd('.').ToLowerInvariant()
                        if ([string]::IsNullOrWhiteSpace($normalizedDomain)) {
                            continue
                        }

                        if (-not $domainSet.ContainsKey($normalizedDomain)) {
                            $domainSet[$normalizedDomain] = $true
                            $exchangeInfo.AcceptedDomains += $normalizedDomain
                        }
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-AcceptedDomain failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-MapiVirtualDirectory -ErrorAction SilentlyContinue) {
                try {
                    $mapiVirtualDirectories = @(Get-MapiVirtualDirectory -Server $env:COMPUTERNAME -ErrorAction Stop)
                    if ($mapiVirtualDirectories.Count -gt 0) {
                        $enabledCount = @($mapiVirtualDirectories | Where-Object { $null -ne $_.IISAuthenticationMethods }).Count
                        $exchangeInfo.MapiHttpEnabled = ($enabledCount -gt 0)
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-MapiVirtualDirectory (MAPI/HTTP) failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-ReceiveConnector -ErrorAction SilentlyContinue) {
                try {
                    $connectors = @(Get-ReceiveConnector -Server $env:COMPUTERNAME -ErrorAction Stop)
                    foreach ($connector in $connectors) {
                        $exchangeInfo.ReceiveConnectors += [pscustomobject]@{
                            Identity                 = [string]$connector.Identity
                            PermissionGroups         = [string]$connector.PermissionGroups
                            AuthMechanism            = [string]$connector.AuthMechanism
                            RemoteIPRangesCount      = @($connector.RemoteIPRanges).Count
                            Enabled                  = if ($connector.PSObject.Properties.Name -contains 'Enabled') { [bool]$connector.Enabled } else { $null }
                            ProtocolLoggingLevel     = if ($connector.PSObject.Properties.Name -contains 'ProtocolLoggingLevel') { [string]$connector.ProtocolLoggingLevel } else { $null }
                            MaxMessageSize           = if ($connector.PSObject.Properties.Name -contains 'MaxMessageSize' -and $null -ne $connector.MaxMessageSize) { [string]$connector.MaxMessageSize } else { $null }
                            MaxHopCount              = if ($connector.PSObject.Properties.Name -contains 'MaxHopCount') { [string]$connector.MaxHopCount } else { $null }
                            ConnectionTimeout        = if ($connector.PSObject.Properties.Name -contains 'ConnectionTimeout' -and $null -ne $connector.ConnectionTimeout) { [string]$connector.ConnectionTimeout } else { $null }
                            TransportRole            = if ($connector.PSObject.Properties.Name -contains 'TransportRole') { [string]$connector.TransportRole } else { $null }
                            Banner                   = if ($connector.PSObject.Properties.Name -contains 'Banner') { [string]$connector.Banner } else { $null }
                            RequireTLS               = if ($connector.PSObject.Properties.Name -contains 'RequireTLS') { [bool]$connector.RequireTLS } else { $null }
                            MaxRecipientsPerMessage  = if ($connector.PSObject.Properties.Name -contains 'MaxRecipientsPerMessage') { [string]$connector.MaxRecipientsPerMessage } else { $null }
                            TlsDomainCapabilities    = if ($connector.PSObject.Properties.Name -contains 'TlsDomainCapabilities') { [string]$connector.TlsDomainCapabilities } else { $null }
                            CloudServicesMailEnabled = if ($connector.PSObject.Properties.Name -contains 'CloudServicesMailEnabled') { [bool]$connector.CloudServicesMailEnabled } else { $null }
                        }
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-ReceiveConnector failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-OwaVirtualDirectory -ErrorAction SilentlyContinue) {
                try {
                    $owas = @(Get-OwaVirtualDirectory -Server $env:COMPUTERNAME -ErrorAction Stop)
                    if ($owas.Count -gt 0) {
                        $withDownloadDomains = @($owas | Where-Object {
                                $_.PSObject.Properties.Name -contains 'DownloadDomains' -and
                                -not [string]::IsNullOrWhiteSpace([string]$_.DownloadDomains)
                            }).Count
                        $exchangeInfo.OwaDownloadDomainsConfigured = ($withDownloadDomains -gt 0)
                        $withSmime = @($owas | Where-Object {
                                $_.PSObject.Properties.Name -contains 'SMIMEEnabled' -and [bool]$_.SMIMEEnabled
                            }).Count
                        $exchangeInfo.OwaSmimeEnabled = ($withSmime -gt 0)
                        $exchangeInfo.OwaFormsAuthentication = @($owas | ForEach-Object {
                                [pscustomobject]@{
                                    Identity            = [string]$_.Identity
                                    FormsAuthentication = if ($_.PSObject.Properties.Name -contains 'FormsAuthentication') { [bool]$_.FormsAuthentication } else { $null }
                                }
                            })
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-OwaVirtualDirectory (Download Domains) failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-EventLogLevel -ErrorAction SilentlyContinue) {
                try {
                    $exchangeInfo.EventLogLevels = @(Get-EventLogLevel -ErrorAction Stop | ForEach-Object {
                            [pscustomobject]@{
                                Identity   = [string]$_.Identity
                                EventLevel = [string]$_.EventLevel
                            }
                        })
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-EventLogLevel failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-RpcClientAccess -ErrorAction SilentlyContinue) {
                try {
                    $rpcAccess = Get-RpcClientAccess -Server $env:COMPUTERNAME -ErrorAction Stop
                    if ($null -ne $rpcAccess) {
                        $exchangeInfo.RpcClientAccessConfig = [pscustomobject]@{
                            EncryptionRequired = if ($rpcAccess.PSObject.Properties.Name -contains 'EncryptionRequired') { [bool]$rpcAccess.EncryptionRequired } else { $null }
                        }
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-RpcClientAccess failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-Mailbox -ErrorAction SilentlyContinue) {
                try {
                    $mailboxes = @(Get-Mailbox -ResultSize Unlimited -ErrorAction Stop)
                    $mismatchedUpn = @($mailboxes | Where-Object {
                            $_.RecipientTypeDetails -eq 'UserMailbox' -and
                            -not [string]::IsNullOrWhiteSpace([string]$_.UserPrincipalName) -and
                            -not [string]::IsNullOrWhiteSpace([string]$_.WindowsEmailAddress) -and
                            -not [string]::Equals([string]$_.UserPrincipalName, [string]$_.WindowsEmailAddress, [System.StringComparison]::OrdinalIgnoreCase)
                        })
                    $exchangeInfo.UpnPrimarySmtpMismatchCount = $mismatchedUpn.Count

                    $sharedLikeNames = @($mailboxes | Where-Object {
                            $_.RecipientTypeDetails -ne 'UserMailbox' -and
                            ($_.PSObject.Properties.Name -contains 'AccountDisabled') -and
                            -not [bool]$_.AccountDisabled
                        })
                    $exchangeInfo.SharedMailboxTypeMismatchCount = $sharedLikeNames.Count
                    $exchangeInfo.SharedMailboxTypeMismatches = @($sharedLikeNames | ForEach-Object { [string]$_.DisplayName })

                    $sirDisabled = @($mailboxes | Where-Object {
                            $_.RecipientTypeDetails -eq 'UserMailbox' -and
                            ($_.PSObject.Properties.Name -contains 'SingleItemRecoveryEnabled') -and
                            -not [bool]$_.SingleItemRecoveryEnabled
                        })
                    $exchangeInfo.SingleItemRecoveryDisabledCount = $sirDisabled.Count
                    $exchangeInfo.SingleItemRecoveryDisabledMailboxes = @($sirDisabled | ForEach-Object { [string]$_.DisplayName })
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-Mailbox baseline checks failed: ' + $_.Exception.Message)
                }
            }

            if (Get-Command -Name Get-MailboxDatabase -ErrorAction SilentlyContinue) {
                try {
                    $mailboxDatabases = @(Get-MailboxDatabase -Server $env:COMPUTERNAME -ErrorAction Stop)
                    $storagePathSet = @{}
                    foreach ($mailboxDatabase in $mailboxDatabases) {
                        $candidatePaths = @()
                        if ($mailboxDatabase.PSObject.Properties.Name -contains 'EdbFilePath' -and $null -ne $mailboxDatabase.EdbFilePath) {
                            $candidatePaths += [string]$mailboxDatabase.EdbFilePath
                        }
                        if ($mailboxDatabase.PSObject.Properties.Name -contains 'LogFolderPath' -and $null -ne $mailboxDatabase.LogFolderPath) {
                            $candidatePaths += [string]$mailboxDatabase.LogFolderPath
                        }

                        foreach ($candidatePath in $candidatePaths) {
                            if ([string]::IsNullOrWhiteSpace($candidatePath)) {
                                continue
                            }

                            $normalizedPath = $candidatePath.Trim()
                            if (-not $storagePathSet.ContainsKey($normalizedPath)) {
                                $storagePathSet[$normalizedPath] = $true
                                $exchangeInfo.DatabaseStoragePaths += $normalizedPath
                            }
                        }

                        $itemRetentionDays = $null
                        if ($mailboxDatabase.PSObject.Properties.Name -contains 'DeletedItemRetention' -and $null -ne $mailboxDatabase.DeletedItemRetention) {
                            try { $itemRetentionDays = [int]([timespan]$mailboxDatabase.DeletedItemRetention).TotalDays } catch {}
                        }
                        $mailboxRetentionDays = $null
                        if ($mailboxDatabase.PSObject.Properties.Name -contains 'MailboxRetention' -and $null -ne $mailboxDatabase.MailboxRetention) {
                            try { $mailboxRetentionDays = [int]([timespan]$mailboxDatabase.MailboxRetention).TotalDays } catch {}
                        }
                        $backupRestore = if ($mailboxDatabase.PSObject.Properties.Name -contains 'RetainDeletedItemsUntilBackup') { [bool]$mailboxDatabase.RetainDeletedItemsUntilBackup } else { $null }
                        $issueWarnQuotaIsUnlimited = $true
                        $issueWarnQuotaBytes = $null
                        if ($mailboxDatabase.PSObject.Properties.Name -contains 'IssueWarningQuota' -and $null -ne $mailboxDatabase.IssueWarningQuota) {
                            $iqStr = [string]$mailboxDatabase.IssueWarningQuota
                            if ($iqStr -ne 'Unlimited') {
                                $issueWarnQuotaIsUnlimited = $false
                                $iqMatch = [regex]::Match($iqStr, '\(([\d,]+)\s*bytes\)')
                                if ($iqMatch.Success) { try { $issueWarnQuotaBytes = [long]($iqMatch.Groups[1].Value -replace ',', '') } catch {} }
                            }
                        }
                        $prohibitSendQuotaIsUnlimited = $true
                        $prohibitSendQuotaBytes = $null
                        if ($mailboxDatabase.PSObject.Properties.Name -contains 'ProhibitSendQuota' -and $null -ne $mailboxDatabase.ProhibitSendQuota) {
                            $psqStr = [string]$mailboxDatabase.ProhibitSendQuota
                            if ($psqStr -ne 'Unlimited') {
                                $prohibitSendQuotaIsUnlimited = $false
                                $psqMatch = [regex]::Match($psqStr, '\(([\d,]+)\s*bytes\)')
                                if ($psqMatch.Success) { try { $prohibitSendQuotaBytes = [long]($psqMatch.Groups[1].Value -replace ',', '') } catch {} }
                            }
                        }
                        $prohibitSendReceiveQuotaIsUnlimited = $true
                        $prohibitSendReceiveQuotaBytes = $null
                        if ($mailboxDatabase.PSObject.Properties.Name -contains 'ProhibitSendReceiveQuota' -and $null -ne $mailboxDatabase.ProhibitSendReceiveQuota) {
                            $psrqStr = [string]$mailboxDatabase.ProhibitSendReceiveQuota
                            if ($psrqStr -ne 'Unlimited') {
                                $prohibitSendReceiveQuotaIsUnlimited = $false
                                $psrqMatch = [regex]::Match($psrqStr, '\(([\d,]+)\s*bytes\)')
                                if ($psrqMatch.Success) { try { $prohibitSendReceiveQuotaBytes = [long]($psrqMatch.Groups[1].Value -replace ',', '') } catch {} }
                            }
                        }
                        $exchangeInfo.MailboxDatabases += [pscustomobject]@{
                            Name                                = [string]$mailboxDatabase.Name
                            ItemRetentionDays                   = $itemRetentionDays
                            MailboxRetentionDays                = $mailboxRetentionDays
                            RetainDeletedItemsUntilBackup       = $backupRestore
                            IssueWarningQuotaIsUnlimited        = $issueWarnQuotaIsUnlimited
                            IssueWarningQuotaBytes              = $issueWarnQuotaBytes
                            ProhibitSendQuotaIsUnlimited        = $prohibitSendQuotaIsUnlimited
                            ProhibitSendQuotaBytes              = $prohibitSendQuotaBytes
                            ProhibitSendReceiveQuotaIsUnlimited = $prohibitSendReceiveQuotaIsUnlimited
                            ProhibitSendReceiveQuotaBytes       = $prohibitSendReceiveQuotaBytes
                            CircularLoggingEnabled              = if ($mailboxDatabase.PSObject.Properties.Name -contains 'CircularLoggingEnabled') { [bool]$mailboxDatabase.CircularLoggingEnabled } else { $null }
                            MountAtStartup                      = if ($mailboxDatabase.PSObject.Properties.Name -contains 'MountAtStartup') { [bool]$mailboxDatabase.MountAtStartup } else { $null }
                            EdbFilePath                         = if ($mailboxDatabase.PSObject.Properties.Name -contains 'EdbFilePath' -and $null -ne $mailboxDatabase.EdbFilePath) { [string]$mailboxDatabase.EdbFilePath } else { $null }
                            LogFolderPath                       = if ($mailboxDatabase.PSObject.Properties.Name -contains 'LogFolderPath' -and $null -ne $mailboxDatabase.LogFolderPath) { [string]$mailboxDatabase.LogFolderPath } else { $null }
                            DatabaseCopiesCount                 = if ($mailboxDatabase.PSObject.Properties.Name -contains 'DatabaseCopies') { @($mailboxDatabase.DatabaseCopies).Count } else { 1 }
                        }
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-MailboxDatabase storage path checks failed: ' + $_.Exception.Message)
                }
            }

            if ((Get-Command -Name Get-ClientAccessService -ErrorAction SilentlyContinue) -or (Get-Command -Name Get-ClientAccessServer -ErrorAction SilentlyContinue)) {
                try {
                    $clientAccessService = $null
                    $asaSourceCommand = $null

                    if (Get-Command -Name Get-ClientAccessService -ErrorAction SilentlyContinue) {
                        $asaSourceCommand = 'Get-ClientAccessService'
                        $clientAccessService = Get-ClientAccessService -Identity $env:COMPUTERNAME -ErrorAction Stop
                    }
                    else {
                        $asaSourceCommand = 'Get-ClientAccessServer'
                        $clientAccessService = Get-ClientAccessServer -Identity $env:COMPUTERNAME -IncludeAlternateServiceAccountCredentialStatus -ErrorAction Stop
                    }

                    $asaConfiguration = $null
                    if ($null -ne $clientAccessService -and ($clientAccessService.PSObject.Properties.Name -contains 'AlternateServiceAccountConfiguration')) {
                        $asaConfiguration = $clientAccessService.AlternateServiceAccountConfiguration
                    }

                    $effectiveCredentials = @()
                    $latestCredential = $null
                    $previousCredential = $null
                    $asaConfigurationText = if ($null -eq $asaConfiguration) { '' } else { [string]$asaConfiguration }

                    if ($null -ne $asaConfiguration -and ($asaConfiguration.PSObject.Properties.Name -contains 'EffectiveCredentials') -and $null -ne $asaConfiguration.EffectiveCredentials) {
                        $effectiveCredentials = @($asaConfiguration.EffectiveCredentials | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)
                    }

                    if ($null -ne $asaConfiguration -and ($asaConfiguration.PSObject.Properties.Name -contains 'Latest') -and $null -ne $asaConfiguration.Latest) {
                        $latestCredential = [string]$asaConfiguration.Latest
                    }

                    if ($null -ne $asaConfiguration -and ($asaConfiguration.PSObject.Properties.Name -contains 'Previous') -and $null -ne $asaConfiguration.Previous) {
                        $previousCredential = [string]$asaConfiguration.Previous
                    }

                    if ($effectiveCredentials.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($asaConfigurationText)) {
                        $credentialMatches = [regex]::Matches($asaConfigurationText, '(?im)\b[0-9a-zA-Z\.\-_]+\\[0-9a-zA-Z\.\-_\$]+\b')
                        foreach ($credentialMatch in $credentialMatches) {
                            $credentialValue = [string]$credentialMatch.Value
                            if (-not [string]::IsNullOrWhiteSpace($credentialValue) -and ($effectiveCredentials -notcontains $credentialValue)) {
                                $effectiveCredentials += $credentialValue
                            }
                        }
                    }

                    if ([string]::IsNullOrWhiteSpace($latestCredential) -and -not [string]::IsNullOrWhiteSpace($asaConfigurationText)) {
                        $latestMatch = [regex]::Match($asaConfigurationText, '(?im)Latest\s*:\s*[^,]+,\s*([0-9a-zA-Z\.\-_]+\\[0-9a-zA-Z\.\-_\$]+)')
                        if ($latestMatch.Success) {
                            $latestCredential = [string]$latestMatch.Groups[1].Value
                        }
                    }

                    if ([string]::IsNullOrWhiteSpace($previousCredential) -and -not [string]::IsNullOrWhiteSpace($asaConfigurationText)) {
                        $previousMatch = [regex]::Match($asaConfigurationText, '(?im)Previous\s*:\s*[^,]+,\s*([0-9a-zA-Z\.\-_]+\\[0-9a-zA-Z\.\-_\$]+)')
                        if ($previousMatch.Success) {
                            $previousCredential = [string]$previousMatch.Groups[1].Value
                        }
                    }

                    $configured = $false
                    if ($effectiveCredentials.Count -gt 0) {
                        $configured = $true
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($latestCredential) -or -not [string]::IsNullOrWhiteSpace($previousCredential)) {
                        $configured = $true
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($asaConfigurationText) -and $asaConfigurationText -match '(?i)latest\s*:') {
                        $configured = $true
                    }

                    $exchangeInfo.AlternateServiceAccount = [pscustomobject]@{
                        QuerySucceeded     = $true
                        SourceCommand      = $asaSourceCommand
                        Configured         = $configured
                        CredentialCount    = @($effectiveCredentials).Count
                        Credentials        = @($effectiveCredentials | Sort-Object -Unique)
                        LatestCredential   = $latestCredential
                        PreviousCredential = $previousCredential
                        RawConfiguration   = $asaConfigurationText
                    }
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Get-ClientAccessService/Get-ClientAccessServer (ASA) failed: ' + $_.Exception.Message)
                    $exchangeInfo.AlternateServiceAccount = [pscustomobject]@{
                        QuerySucceeded     = $false
                        SourceCommand      = 'Get-ClientAccessService/Get-ClientAccessServer'
                        Configured         = $null
                        CredentialCount    = 0
                        Credentials        = @()
                        LatestCredential   = $null
                        PreviousCredential = $null
                        RawConfiguration   = $null
                    }
                }
            }

            if (Get-Command -Name Test-ReplicationHealth -ErrorAction SilentlyContinue) {
                try {
                    $replication = Test-ReplicationHealth -Identity $env:COMPUTERNAME -ErrorAction Stop
                    $failed = $replication | Where-Object { $_.Result -ne 'Passed' }
                    $exchangeInfo.ReplicationHealthPassed = ($failed.Count -eq 0)
                }
                catch {
                    $exchangeInfo.CollectionWarnings += ('Test-ReplicationHealth failed: ' + $_.Exception.Message)
                }
            }
        }

        # OwaVersion from the setup registry key is always the authoritative source for BuildNumber.
        # Get-ExchangeServer AdminDisplayVersion does not reflect individual SU or minor CU changes.
        # This block always runs unconditionally so the correct build is reported regardless of
        # whether Exchange cmdlets are available or $collectExchangeCmdlets is set.
        if ($hasExchangeInstall) {
            try {
                $setupForBuild = Get-ItemProperty -Path $setupKey -ErrorAction Stop
                if (($setupForBuild.PSObject.Properties.Name -contains 'OwaVersion') -and
                    -not [string]::IsNullOrWhiteSpace([string]$setupForBuild.OwaVersion)) {
                    $exchangeInfo.BuildNumber = [string]$setupForBuild.OwaVersion
                }
                elseif ($null -eq $exchangeInfo.BuildNumber) {
                    # OwaVersion absent: compose version string from the four MSI component values.
                    $fbMajor = if ($setupForBuild.PSObject.Properties.Name -contains 'MsiProductMajor') { $setupForBuild.MsiProductMajor } else { $null }
                    $fbMinor = if ($setupForBuild.PSObject.Properties.Name -contains 'MsiProductMinor') { $setupForBuild.MsiProductMinor } else { $null }
                    $fbBuild = if ($setupForBuild.PSObject.Properties.Name -contains 'MsiBuildMajor') { $setupForBuild.MsiBuildMajor }   else { $null }
                    $fbRev = if ($setupForBuild.PSObject.Properties.Name -contains 'MsiBuildMinor') { $setupForBuild.MsiBuildMinor }   else { $null }
                    if ($null -ne $fbMajor -and $null -ne $fbMinor -and $null -ne $fbBuild -and $null -ne $fbRev) {
                        $exchangeInfo.BuildNumber = ('{0}.{1}.{2}.{3}' -f [int]$fbMajor, [int]$fbMinor, [int]$fbBuild, [int]$fbRev)
                    }
                }
            }
            catch {
                $exchangeInfo.CollectionWarnings += ('Registry build number read failed: ' + $_.Exception.Message)
            }
        }

        $inventory = [pscustomobject]@{
            Server       = $env:COMPUTERNAME
            OS           = $osInfo
            Tls          = $tlsInfo
            Services     = $services
            Certificates = $certificates
            Exchange     = $exchangeInfo
        }

        return ($inventory | ConvertTo-Json -Depth 12 -Compress)
    }

    $invokeTarget = $Server
    $isLocalTarget = $Server.Equals($env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase) -or
    $Server -in @('.', 'localhost')

    if ($isLocalTarget) {
        Write-Verbose ('Executing unified collection script block locally (no WinRM).')
        $rawInventoryJson = & $collectionScriptBlock $true
    }
    else {
        Write-Verbose ('Executing unified collection script block on {0} via Invoke-Command -ComputerName.' -f $invokeTarget)
        $rawInventoryJson = Invoke-Command -ComputerName $invokeTarget -ScriptBlock $collectionScriptBlock -ArgumentList $false -ErrorAction Stop
    }

    $inventory = $rawInventoryJson | ConvertFrom-Json
    if ($inventory.PSObject.Properties.Name -contains 'Server') {
        $inventory.Server = $Server
    }

    $isEdge = ($inventory.PSObject.Properties.Name -contains 'Exchange') -and
    $null -ne $inventory.Exchange -and
    ($inventory.Exchange.PSObject.Properties.Name -contains 'IsEdge') -and
    [bool]$inventory.Exchange.IsEdge

    if ($isEdge -and -not $isLocalTarget) {
        $inventory.Exchange.CollectionWarnings = @($inventory.Exchange.CollectionWarnings) + @('Edge Transport server detected: Exchange cmdlet collection requires running EDCA on the Edge server itself (use -Local or target the Edge server by name).')
        Write-EDCALog -Level 'WARN' -Message ('Edge Transport server {0}: Exchange cmdlet phase skipped. Run EDCA on the Edge server using -Local.' -f $Server)
        return $inventory
    }

    if (-not $isEdge -and ($inventory.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $inventory.Exchange -and ($inventory.Exchange.PSObject.Properties.Name -contains 'ExchangeComputerMembership')) {
        $computerCn = $Server -replace '\..*$', ''
        try {
            $gcRootDse = [System.DirectoryServices.DirectoryEntry]::new('GC://RootDSE')
            $forestRootNC = [string]$gcRootDse.Properties['rootDomainNamingContext'][0]
            $searcher = [System.DirectoryServices.DirectorySearcher]::new(
                [System.DirectoryServices.DirectoryEntry]::new(('GC://{0}' -f $forestRootNC))
            )
            $searcher.Filter = ('(&(objectCategory=computer)(objectClass=computer)(cn={0}))' -f $computerCn)
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $searcher.PageSize = 1
            [void]$searcher.PropertiesToLoad.Add('memberOf')
            [void]$searcher.PropertiesToLoad.Add('userAccountControl')
            $computerResult = $searcher.FindOne()

            if ($null -ne $computerResult) {
                $memberGroupNames = @()
                foreach ($groupDn in @($computerResult.Properties['memberOf'])) {
                    $groupDnText = [string]$groupDn
                    if ($groupDnText -match '^CN=([^,]+)') {
                        $memberGroupNames += $Matches[1]
                    }
                }

                $requiredGroups = @('Exchange Trusted Subsystem', 'Exchange Servers')
                $presentGroups = @()
                $missingGroups = @()
                foreach ($requiredGroup in $requiredGroups) {
                    if (@($memberGroupNames | Where-Object { [string]::Equals([string]$_, $requiredGroup, [System.StringComparison]::OrdinalIgnoreCase) }).Count -gt 0) {
                        $presentGroups += $requiredGroup
                    }
                    else {
                        $missingGroups += $requiredGroup
                    }
                }

                $inventory.Exchange.ExchangeComputerMembership = [pscustomobject]@{
                    QuerySucceeded       = $true
                    MissingGroups        = $missingGroups
                    PresentGroups        = $presentGroups
                    TrustedForDelegation = if ($computerResult.Properties['userAccountControl'].Count -gt 0) {
                        [bool]([int]$computerResult.Properties['userAccountControl'][0] -band 0x80000)
                    }
                    else { $null }
                }
            }
        }
        catch {
        }
    }

    $exchEndpointWarnings = @()
    if (-not $isEdge -and ($inventory.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $inventory.Exchange -and ($inventory.Exchange.PSObject.Properties.Name -contains 'IsExchangeServer') -and [bool]$inventory.Exchange.IsExchangeServer) {
        Write-Verbose ('Collecting Exchange cmdlet data for {0} via Exchange endpoint (ConnectionUri/Kerberos).' -f $invokeTarget)
        $cmdletsAvailable = $false

        try {
            $sb = [scriptblock]::Create("Get-ExchangeServer -Identity '$invokeTarget'")
            $remoteServer = Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb
            if ($null -ne $remoteServer) {
                $cmdletsAvailable = $true
                $inventory.Exchange.ExchangeCmdletsAvailable = $true
                $inventory.Exchange.IsExchangeServer = $true
                $isRemoteEdge = ($remoteServer.PSObject.Properties.Name -contains 'ServerRole') -and ([string]$remoteServer.ServerRole -match 'Edge')
                $inventory.Exchange.IsEdge = $isRemoteEdge
                $inventory.Exchange.ServerRole = if ($isRemoteEdge) { 'Edge' } else { 'Mailbox' }
                $isEdge = $isRemoteEdge
                if ($remoteServer.PSObject.Properties.Name -contains 'Name') {
                    $inventory.Exchange.Name = [string]$remoteServer.Name
                }
                if ($remoteServer.PSObject.Properties.Name -contains 'AdminDisplayVersion') {
                    $inventory.Exchange.AdminDisplayVersion = [string]$remoteServer.AdminDisplayVersion
                }
                if ($remoteServer.PSObject.Properties.Name -contains 'Edition') {
                    $inventory.Exchange.Edition = [string]$remoteServer.Edition
                }
                $inventory.Exchange.IsDagMember = ($remoteServer.PSObject.Properties.Name -contains 'MemberOfDAG') -and -not [string]::IsNullOrWhiteSpace([string]$remoteServer.MemberOfDAG)
                $inventory.Exchange.DagName = if (($remoteServer.PSObject.Properties.Name -contains 'MemberOfDAG') -and -not [string]::IsNullOrWhiteSpace([string]$remoteServer.MemberOfDAG)) { [string]$remoteServer.MemberOfDAG } else { '' }
                $inventory.Exchange.AdSite = if ($remoteServer.PSObject.Properties.Name -contains 'Site') { [string]$remoteServer.Site } else { '' }
                if ($remoteServer.PSObject.Properties.Name -contains 'ErrorReportingEnabled') {
                    $inventory.Exchange.ErrorReportingEnabled = [bool]$remoteServer.ErrorReportingEnabled
                }
                $adv = [string]$inventory.Exchange.AdminDisplayVersion
                if ($adv -match 'Version 15\.1') {
                    $inventory.Exchange.ProductLine = 'Exchange2016'
                }
                elseif ($adv -match 'Version 15\.2') {
                    $isSe = $false
                    if ($remoteServer.PSObject.Properties.Name -contains 'IsExchangeServerSubscriptionEdition') {
                        $isSe = [bool]$remoteServer.IsExchangeServerSubscriptionEdition
                    }
                    if (-not $isSe -and $adv -match 'Subscription|SE') { $isSe = $true }
                    if (-not $isSe -and $adv -match 'Build\s+(\d+)\.') {
                        if ([int]$matches[1] -ge 2562) { $isSe = $true }
                    }
                    $inventory.Exchange.ProductLine = if ($isSe) { 'ExchangeSE' } else { 'Exchange2019' }
                }
            }
        }
        catch {
            $exchEndpointWarnings += ('Get-ExchangeServer via endpoint failed: ' + (Get-EDCAExceptionMessage -ErrorRecord $_))
        }

        if ($cmdletsAvailable) {
            $virtualDirResults = @{}
            foreach ($vdirCmd in @('Get-MapiVirtualDirectory', 'Get-OwaVirtualDirectory', 'Get-EcpVirtualDirectory', 'Get-WebServicesVirtualDirectory', 'Get-ActiveSyncVirtualDirectory', 'Get-AutodiscoverVirtualDirectory')) {
                try {
                    $sb = [scriptblock]::Create("$vdirCmd -Server '$invokeTarget'")
                    $vdirs = @(Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb)
                    $virtualDirResults[$vdirCmd] = $vdirs
                    foreach ($vdir in $vdirs) {
                        $inventory.Exchange.ExtendedProtectionStatus = @($inventory.Exchange.ExtendedProtectionStatus) + @([pscustomobject]@{
                                VirtualDirectoryType            = $vdirCmd
                                Identity                        = [string]$vdir.Identity
                                ExtendedProtectionTokenChecking = if ($vdir.PSObject.Properties.Name -contains 'ExtendedProtectionTokenChecking') { [string]$vdir.ExtendedProtectionTokenChecking } else { '' }
                                ExtendedProtectionFlags         = if ($vdir.PSObject.Properties.Name -contains 'ExtendedProtectionFlags') { [string]$vdir.ExtendedProtectionFlags } else { '' }
                                ExtendedProtectionSPNList       = if ($vdir.PSObject.Properties.Name -contains 'ExtendedProtectionSPNList') { [string]$vdir.ExtendedProtectionSPNList } else { '' }
                                InternalAuthenticationMethods   = if ($vdir.PSObject.Properties.Name -contains 'InternalAuthenticationMethods') { [string]$vdir.InternalAuthenticationMethods } else { '' }
                                ExternalAuthenticationMethods   = if ($vdir.PSObject.Properties.Name -contains 'ExternalAuthenticationMethods') { [string]$vdir.ExternalAuthenticationMethods } else { '' }
                                IISAuthenticationMethods        = if ($vdir.PSObject.Properties.Name -contains 'IISAuthenticationMethods') { [string]$vdir.IISAuthenticationMethods } else { '' }
                                OAuthAuthentication             = if ($vdir.PSObject.Properties.Name -contains 'OAuthAuthentication') { [nullable[bool]]$vdir.OAuthAuthentication } else { $null }
                            })
                    }
                }
                catch {
                    $exchEndpointWarnings += ('{0} via endpoint failed: {1}' -f $vdirCmd, $_.Exception.Message)
                }
            }

            if ($virtualDirResults.ContainsKey('Get-MapiVirtualDirectory') -and $virtualDirResults['Get-MapiVirtualDirectory'].Count -gt 0) {
                $enabledCount = @($virtualDirResults['Get-MapiVirtualDirectory'] | Where-Object { $null -ne $_.IISAuthenticationMethods }).Count
                $inventory.Exchange.MapiHttpEnabled = ($enabledCount -gt 0)
            }

            if ($virtualDirResults.ContainsKey('Get-OwaVirtualDirectory') -and $virtualDirResults['Get-OwaVirtualDirectory'].Count -gt 0) {
                $withDL = @($virtualDirResults['Get-OwaVirtualDirectory'] | Where-Object {
                        $_.PSObject.Properties.Name -contains 'DownloadDomains' -and
                        -not [string]::IsNullOrWhiteSpace([string]$_.DownloadDomains)
                    }).Count
                $inventory.Exchange.OwaDownloadDomainsConfigured = ($withDL -gt 0)
                $withSmimeEP = @($virtualDirResults['Get-OwaVirtualDirectory'] | Where-Object {
                        $_.PSObject.Properties.Name -contains 'SMIMEEnabled' -and [bool]$_.SMIMEEnabled
                    }).Count
                $inventory.Exchange.OwaSmimeEnabled = ($withSmimeEP -gt 0)
                $inventory.Exchange.OwaFormsAuthentication = @($virtualDirResults['Get-OwaVirtualDirectory'] | ForEach-Object {
                        [pscustomobject]@{
                            Identity            = [string]$_.Identity
                            FormsAuthentication = if ($_.PSObject.Properties.Name -contains 'FormsAuthentication') { [bool]$_.FormsAuthentication } else { $null }
                        }
                    })
            }

            try {
                $sbOA = [scriptblock]::Create("Get-OutlookAnywhere -Server '$invokeTarget'")
                $oaItems = @(Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sbOA)
                foreach ($oaItem in $oaItems) {
                    $inventory.Exchange.OutlookAnywhereSSLOffloading = @($inventory.Exchange.OutlookAnywhereSSLOffloading) + @([pscustomobject]@{
                            Identity      = [string]$oaItem.Identity
                            SSLOffloading = if ($oaItem.PSObject.Properties.Name -contains 'SSLOffloading') { [nullable[bool]]$oaItem.SSLOffloading } else { $null }
                        })
                }
            }
            catch {
                $exchEndpointWarnings += ('Get-OutlookAnywhere via endpoint failed: ' + $_.Exception.Message)
            }

            try {
                $sbEvtLog = [scriptblock]::Create('Get-EventLogLevel')
                $inventory.Exchange.EventLogLevels = @(Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sbEvtLog | ForEach-Object {
                        [pscustomobject]@{
                            Identity   = [string]$_.Identity
                            EventLevel = [string]$_.EventLevel
                        }
                    })
            }
            catch {
                $exchEndpointWarnings += ('Get-EventLogLevel via endpoint failed: ' + $_.Exception.Message)
            }

            try {
                $sbRpc = [scriptblock]::Create("Get-RpcClientAccess -Server '$invokeTarget'")
                $rpcAccess = Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sbRpc
                if ($null -ne $rpcAccess) {
                    $inventory.Exchange.RpcClientAccessConfig = [pscustomobject]@{
                        EncryptionRequired = if ($rpcAccess.PSObject.Properties.Name -contains 'EncryptionRequired') { [bool]$rpcAccess.EncryptionRequired } else { $null }
                    }
                }
            }
            catch {
                $exchEndpointWarnings += ('Get-RpcClientAccess via endpoint failed: ' + $_.Exception.Message)
            }

            try {
                $asaSourceCommand = $null
                $clientAccessService = $null

                $sbCas = [scriptblock]::Create("Get-ClientAccessService -Identity '$invokeTarget' -ErrorAction Stop")
                try {
                    $clientAccessService = Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sbCas
                    $asaSourceCommand = 'Get-ClientAccessService'
                }
                catch {
                    if ($_.Exception.Message -notmatch 'CommandNotFoundException|is not recognized|not recognized as the name') {
                        throw
                    }
                    $sbCaLegacy = [scriptblock]::Create("Get-ClientAccessServer -Identity '$invokeTarget' -IncludeAlternateServiceAccountCredentialStatus -ErrorAction Stop")
                    $clientAccessService = Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sbCaLegacy
                    $asaSourceCommand = 'Get-ClientAccessServer'
                }

                if ([string]::IsNullOrWhiteSpace($asaSourceCommand) -or $null -eq $clientAccessService) {
                    $inventory.Exchange.AlternateServiceAccount = [pscustomobject]@{
                        QuerySucceeded     = $false
                        SourceCommand      = 'Get-ClientAccessService/Get-ClientAccessServer'
                        Configured         = $null
                        CredentialCount    = 0
                        Credentials        = @()
                        LatestCredential   = $null
                        PreviousCredential = $null
                        RawConfiguration   = $null
                    }
                }
                else {
                    $asaConfiguration = $null
                    if ($clientAccessService.PSObject.Properties.Name -contains 'AlternateServiceAccountConfiguration') {
                        $asaConfiguration = $clientAccessService.AlternateServiceAccountConfiguration
                    }

                    $effectiveCredentials = @()
                    $latestCredential = $null
                    $previousCredential = $null
                    $asaConfigurationText = if ($null -eq $asaConfiguration) { '' } else { [string]$asaConfiguration }

                    if ($null -ne $asaConfiguration -and ($asaConfiguration.PSObject.Properties.Name -contains 'EffectiveCredentials') -and $null -ne $asaConfiguration.EffectiveCredentials) {
                        $effectiveCredentials = @($asaConfiguration.EffectiveCredentials | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)
                    }

                    if ($null -ne $asaConfiguration -and ($asaConfiguration.PSObject.Properties.Name -contains 'Latest') -and $null -ne $asaConfiguration.Latest) {
                        $latestCredential = [string]$asaConfiguration.Latest
                    }

                    if ($null -ne $asaConfiguration -and ($asaConfiguration.PSObject.Properties.Name -contains 'Previous') -and $null -ne $asaConfiguration.Previous) {
                        $previousCredential = [string]$asaConfiguration.Previous
                    }

                    if ($effectiveCredentials.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($asaConfigurationText)) {
                        $credentialMatches = [regex]::Matches($asaConfigurationText, '(?im)\b[0-9a-zA-Z\.\-_]+\\[0-9a-zA-Z\.\-_\$]+\b')
                        foreach ($credentialMatch in $credentialMatches) {
                            $credentialValue = [string]$credentialMatch.Value
                            if (-not [string]::IsNullOrWhiteSpace($credentialValue) -and ($effectiveCredentials -notcontains $credentialValue)) {
                                $effectiveCredentials += $credentialValue
                            }
                        }
                    }

                    if ([string]::IsNullOrWhiteSpace($latestCredential) -and -not [string]::IsNullOrWhiteSpace($asaConfigurationText)) {
                        $latestMatch = [regex]::Match($asaConfigurationText, '(?im)Latest\s*:\s*[^,]+,\s*([0-9a-zA-Z\.\-_]+\\[0-9a-zA-Z\.\-_\$]+)')
                        if ($latestMatch.Success) {
                            $latestCredential = [string]$latestMatch.Groups[1].Value
                        }
                    }

                    if ([string]::IsNullOrWhiteSpace($previousCredential) -and -not [string]::IsNullOrWhiteSpace($asaConfigurationText)) {
                        $previousMatch = [regex]::Match($asaConfigurationText, '(?im)Previous\s*:\s*[^,]+,\s*([0-9a-zA-Z\.\-_]+\\[0-9a-zA-Z\.\-_\$]+)')
                        if ($previousMatch.Success) {
                            $previousCredential = [string]$previousMatch.Groups[1].Value
                        }
                    }

                    $configured = $false
                    if ($effectiveCredentials.Count -gt 0) {
                        $configured = $true
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($latestCredential) -or -not [string]::IsNullOrWhiteSpace($previousCredential)) {
                        $configured = $true
                    }
                    elseif (-not [string]::IsNullOrWhiteSpace($asaConfigurationText) -and $asaConfigurationText -match '(?i)latest\s*:') {
                        $configured = $true
                    }

                    $inventory.Exchange.AlternateServiceAccount = [pscustomobject]@{
                        QuerySucceeded     = $true
                        SourceCommand      = $asaSourceCommand
                        Configured         = $configured
                        CredentialCount    = @($effectiveCredentials).Count
                        Credentials        = @($effectiveCredentials | Sort-Object -Unique)
                        LatestCredential   = $latestCredential
                        PreviousCredential = $previousCredential
                        RawConfiguration   = $asaConfigurationText
                    }
                }
            }
            catch {
                $exchEndpointWarnings += ('Get-ClientAccessService/Get-ClientAccessServer (ASA) via endpoint failed: ' + $_.Exception.Message)
                $inventory.Exchange.AlternateServiceAccount = [pscustomobject]@{
                    QuerySucceeded     = $false
                    SourceCommand      = 'Get-ClientAccessService/Get-ClientAccessServer'
                    Configured         = $null
                    CredentialCount    = 0
                    Credentials        = @()
                    LatestCredential   = $null
                    PreviousCredential = $null
                    RawConfiguration   = $null
                }
            }

            try {
                $sb = [scriptblock]::Create('Get-AdminAuditLogConfig')
                $audit = Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb
                if ($null -ne $audit -and $audit.PSObject.Properties.Name -contains 'AdminAuditLogEnabled') {
                    $inventory.Exchange.AdminAuditLogEnabled = [bool]$audit.AdminAuditLogEnabled
                }
                if ($null -ne $audit -and $audit.PSObject.Properties.Name -contains 'AdminAuditLogPath' -and -not [string]::IsNullOrWhiteSpace([string]$audit.AdminAuditLogPath)) {
                    $inventory.Exchange.AuditLogPath = [string]$audit.AdminAuditLogPath
                }
            }
            catch {
                $exchEndpointWarnings += ('Get-AdminAuditLogConfig via endpoint failed: ' + $_.Exception.Message)
            }

            if ([string]::IsNullOrWhiteSpace([string]$inventory.Exchange.AuditLogPath) -and
                -not [string]::IsNullOrWhiteSpace([string]$inventory.Exchange.InstallPath)) {
                $inventory.Exchange.AuditLogPath = ([string]$inventory.Exchange.InstallPath).TrimEnd('\') + '\Logging'
            }

            if (-not [string]::IsNullOrWhiteSpace([string]$inventory.Exchange.AuditLogPath)) {
                try {
                    $auditPathArg = [string]$inventory.Exchange.AuditLogPath
                    $auditAclEntries = Invoke-Command -ComputerName $invokeTarget -ScriptBlock {
                        param($p)
                        $acl = Get-Acl -Path $p -ErrorAction Stop
                        @($acl.Access | ForEach-Object {
                                [pscustomobject]@{
                                    IdentityReference = [string]$_.IdentityReference
                                    FileSystemRights  = [string]$_.FileSystemRights
                                    AccessControlType = [string]$_.AccessControlType
                                    IsInherited       = [bool]$_.IsInherited
                                }
                            })
                    } -ArgumentList $auditPathArg -ErrorAction Stop
                    if ($null -ne $auditAclEntries) {
                        $inventory.Exchange.AuditLogPathAcl = @($auditAclEntries)
                    }
                }
                catch {
                    $exchEndpointWarnings += ('Get-Acl for AuditLogPath via endpoint failed: ' + $_.Exception.Message)
                }
            }

            try {
                $sb = [scriptblock]::Create("Get-TransportService -Identity '$invokeTarget'")
                $transportSvc = Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb
                if ($null -ne $transportSvc) {
                    $inventory.Exchange.TransportService = [pscustomobject]@{
                        ErrorReportingEnabled                  = if ($transportSvc.PSObject.Properties.Name -contains 'ErrorReportingEnabled') { [bool]$transportSvc.ErrorReportingEnabled } else { $null }
                        MaxOutboundConnections                 = if ($transportSvc.PSObject.Properties.Name -contains 'MaxOutboundConnections') { [string]$transportSvc.MaxOutboundConnections } else { $null }
                        MaxOutboundConnectionsPerDomain        = if ($transportSvc.PSObject.Properties.Name -contains 'MaxOutboundConnectionsPerDomain') { [string]$transportSvc.MaxOutboundConnectionsPerDomain } else { $null }
                        OutboundConnectionFailureRetryInterval = if ($transportSvc.PSObject.Properties.Name -contains 'OutboundConnectionFailureRetryInterval') { [string]$transportSvc.OutboundConnectionFailureRetryInterval } else { $null }
                    }
                }
            }
            catch {
                $exchEndpointWarnings += ('Get-TransportService via endpoint failed: ' + $_.Exception.Message)
            }

            try {
                $sb = [scriptblock]::Create('Get-TransportAgent')
                $transportAgents = @(Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb)
                foreach ($agent in $transportAgents) {
                    $inventory.Exchange.TransportAgents = @($inventory.Exchange.TransportAgents) + @([pscustomobject]@{
                            Identity = [string]$agent.Identity
                            Enabled  = if ($agent.PSObject.Properties.Name -contains 'Enabled') { [bool]$agent.Enabled } else { $null }
                        })
                }
            }
            catch {
                $exchEndpointWarnings += ('Get-TransportAgent via endpoint failed: ' + $_.Exception.Message)
            }

            try {
                $cfCfg = $null; $sfCfg = $null; $sidCfg = $null; $srCfg = $null
                try { $sb = [scriptblock]::Create('Get-ContentFilterConfig'); $cfCfg = Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb } catch {}
                try { $sb = [scriptblock]::Create('Get-SenderFilterConfig'); $sfCfg = Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb } catch {}
                try { $sb = [scriptblock]::Create('Get-SenderIdConfig'); $sidCfg = Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb } catch {}
                try { $sb = [scriptblock]::Create('Get-SenderReputationConfig'); $srCfg = Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb } catch {}
                if ($null -ne $cfCfg -or $null -ne $sfCfg -or $null -ne $sidCfg -or $null -ne $srCfg) {
                    $inventory.Exchange.AntiSpamConfigs = [pscustomobject]@{
                        ContentFilter    = if ($null -ne $cfCfg) { [pscustomobject]@{ Enabled = [bool]$cfCfg.Enabled } } else { $null }
                        SenderFilter     = if ($null -ne $sfCfg) { [pscustomobject]@{ Enabled = [bool]$sfCfg.Enabled } } else { $null }
                        SenderIdConfig   = if ($null -ne $sidCfg) { [pscustomobject]@{ Enabled = [bool]$sidCfg.Enabled } } else { $null }
                        SenderReputation = if ($null -ne $srCfg) { [pscustomobject]@{ Enabled = [bool]$srCfg.Enabled } } else { $null }
                    }
                }
            }
            catch {
                $exchEndpointWarnings += ('Anti-spam config collection via endpoint failed: ' + $_.Exception.Message)
            }

            try {
                $sb = [scriptblock]::Create('Get-OrganizationConfig')
                $orgConfig = Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb
                if ($null -ne $orgConfig -and $orgConfig.PSObject.Properties.Name -contains 'OAuth2ClientProfileEnabled') {
                    $inventory.Exchange.OAuth2ClientProfileEnabled = [bool]$orgConfig.OAuth2ClientProfileEnabled
                }
                if ($null -ne $orgConfig -and $orgConfig.PSObject.Properties.Name -contains 'MitigationsEnabled' -and $null -ne $inventory.Exchange.Eems) {
                    $inventory.Exchange.Eems = [pscustomobject]@{
                        Present            = $inventory.Exchange.Eems.Present
                        Status             = $inventory.Exchange.Eems.Status
                        StartMode          = $inventory.Exchange.Eems.StartMode
                        MitigationsEnabled = [bool]$orgConfig.MitigationsEnabled
                    }
                }
            }
            catch {
                $exchEndpointWarnings += ('Get-OrganizationConfig via endpoint failed: ' + $_.Exception.Message)
            }

            try {
                $sb = [scriptblock]::Create('Get-AcceptedDomain')
                $acceptedDomains = @(Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb)
                $domainSet = @{}
                foreach ($ad in $acceptedDomains) {
                    $domainValue = ''
                    if ($ad.PSObject.Properties.Name -contains 'DomainName' -and $null -ne $ad.DomainName) {
                        $domainValue = [string]$ad.DomainName
                    }
                    elseif ($ad.PSObject.Properties.Name -contains 'Name') {
                        $domainValue = [string]$ad.Name
                    }
                    if ([string]::IsNullOrWhiteSpace($domainValue)) { continue }
                    $nd = $domainValue.Trim().TrimEnd('.').ToLowerInvariant()
                    if (-not [string]::IsNullOrWhiteSpace($nd) -and -not $domainSet.ContainsKey($nd)) {
                        $domainSet[$nd] = $true
                        $inventory.Exchange.AcceptedDomains = @($inventory.Exchange.AcceptedDomains) + @($nd)
                    }
                }
            }
            catch {
                $exchEndpointWarnings += ('Get-AcceptedDomain via endpoint failed: ' + $_.Exception.Message)
            }

            try {
                $sb = [scriptblock]::Create("Get-ReceiveConnector -Server '$invokeTarget'")
                $connectors = @(Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb)
                foreach ($connector in $connectors) {
                    $inventory.Exchange.ReceiveConnectors = @($inventory.Exchange.ReceiveConnectors) + @([pscustomobject]@{
                            Identity                 = [string]$connector.Identity
                            PermissionGroups         = [string]$connector.PermissionGroups
                            AuthMechanism            = [string]$connector.AuthMechanism
                            RemoteIPRangesCount      = @($connector.RemoteIPRanges).Count
                            Enabled                  = if ($connector.PSObject.Properties.Name -contains 'Enabled') { [bool]$connector.Enabled } else { $null }
                            ProtocolLoggingLevel     = if ($connector.PSObject.Properties.Name -contains 'ProtocolLoggingLevel') { [string]$connector.ProtocolLoggingLevel } else { $null }
                            MaxMessageSize           = if ($connector.PSObject.Properties.Name -contains 'MaxMessageSize' -and $null -ne $connector.MaxMessageSize) { [string]$connector.MaxMessageSize } else { $null }
                            MaxHopCount              = if ($connector.PSObject.Properties.Name -contains 'MaxHopCount') { [string]$connector.MaxHopCount } else { $null }
                            ConnectionTimeout        = if ($connector.PSObject.Properties.Name -contains 'ConnectionTimeout' -and $null -ne $connector.ConnectionTimeout) { [string]$connector.ConnectionTimeout } else { $null }
                            TransportRole            = if ($connector.PSObject.Properties.Name -contains 'TransportRole') { [string]$connector.TransportRole } else { $null }
                            Banner                   = if ($connector.PSObject.Properties.Name -contains 'Banner') { [string]$connector.Banner } else { $null }
                            RequireTLS               = if ($connector.PSObject.Properties.Name -contains 'RequireTLS') { [bool]$connector.RequireTLS } else { $null }
                            MaxRecipientsPerMessage  = if ($connector.PSObject.Properties.Name -contains 'MaxRecipientsPerMessage') { [string]$connector.MaxRecipientsPerMessage } else { $null }
                            TlsDomainCapabilities    = if ($connector.PSObject.Properties.Name -contains 'TlsDomainCapabilities') { [string]$connector.TlsDomainCapabilities } else { $null }
                            CloudServicesMailEnabled = if ($connector.PSObject.Properties.Name -contains 'CloudServicesMailEnabled') { [bool]$connector.CloudServicesMailEnabled } else { $null }
                        })
                }
            }
            catch {
                $exchEndpointWarnings += ('Get-ReceiveConnector via endpoint failed: ' + $_.Exception.Message)
            }

            try {
                $sb = [scriptblock]::Create('Get-SendConnector')
                $sendConnectors = @(Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb)
                foreach ($connector in $sendConnectors) {
                    $smartHosts = @()
                    if ($connector.PSObject.Properties.Name -contains 'SmartHosts' -and $null -ne $connector.SmartHosts) {
                        $smartHosts = @($connector.SmartHosts | ForEach-Object { [string]$_ })
                    }

                    $addressSpaces = @()
                    if ($connector.PSObject.Properties.Name -contains 'AddressSpaces' -and $null -ne $connector.AddressSpaces) {
                        $addressSpaces = @($connector.AddressSpaces | ForEach-Object {
                                if ($_.PSObject.Properties.Name -contains 'Address') { [string]$_.Address } else { [string]$_ }
                            })
                    }

                    $tlsCertificateName = $null
                    if ($connector.PSObject.Properties.Name -contains 'TlsCertificateName' -and $null -ne $connector.TlsCertificateName) {
                        $tlsCertificateName = [string]$connector.TlsCertificateName
                    }

                    $tlsCertificateSyntaxValid = $null
                    if (-not [string]::IsNullOrWhiteSpace($tlsCertificateName)) {
                        $tlsCertificateSyntaxValid = ($tlsCertificateName -match '(?i)(<I>).*(<S>).*')
                    }

                    $sendConnMaxMsgSize = $null
                    if ($connector.PSObject.Properties.Name -contains 'MaxMessageSize' -and $null -ne $connector.MaxMessageSize) {
                        $scMsgSizeStr = [string]$connector.MaxMessageSize
                        if ($scMsgSizeStr -eq 'Unlimited') {
                            $sendConnMaxMsgSize = -1
                        }
                        else {
                            $scMsgSizeMatch = [regex]::Match($scMsgSizeStr, '\(([\d,]+)\s*bytes\)')
                            if ($scMsgSizeMatch.Success) { try { $sendConnMaxMsgSize = [long]($scMsgSizeMatch.Groups[1].Value -replace ',', '') } catch {} }
                        }
                    }
                    $inventory.Exchange.SendConnectors = @($inventory.Exchange.SendConnectors) + @([pscustomobject]@{
                            Identity                    = [string]$connector.Identity
                            Enabled                     = if ($connector.PSObject.Properties.Name -contains 'Enabled') { [bool]$connector.Enabled } else { $null }
                            CloudServicesMailEnabled    = if ($connector.PSObject.Properties.Name -contains 'CloudServicesMailEnabled') { [bool]$connector.CloudServicesMailEnabled } else { $null }
                            TlsAuthLevel                = if ($connector.PSObject.Properties.Name -contains 'TlsAuthLevel') { [string]$connector.TlsAuthLevel } else { $null }
                            RequireTLS                  = if ($connector.PSObject.Properties.Name -contains 'RequireTLS') { [bool]$connector.RequireTLS } else { $null }
                            TlsCertificateName          = $tlsCertificateName
                            TlsCertificateSyntaxValid   = $tlsCertificateSyntaxValid
                            TlsDomain                   = if ($connector.PSObject.Properties.Name -contains 'TlsDomain') { [string]$connector.TlsDomain } else { $null }
                            Fqdn                        = if ($connector.PSObject.Properties.Name -contains 'Fqdn' -and $null -ne $connector.Fqdn) { [string]$connector.Fqdn } else { $null }
                            SmartHosts                  = $smartHosts
                            AddressSpaces               = $addressSpaces
                            ProtocolLoggingLevel        = if ($connector.PSObject.Properties.Name -contains 'ProtocolLoggingLevel') { [string]$connector.ProtocolLoggingLevel } else { $null }
                            DNSRoutingEnabled           = if ($connector.PSObject.Properties.Name -contains 'DNSRoutingEnabled') { [bool]$connector.DNSRoutingEnabled } else { $null }
                            IgnoreStartTLS              = if ($connector.PSObject.Properties.Name -contains 'IgnoreStartTLS') { [bool]$connector.IgnoreStartTLS } else { $null }
                            DomainSecureEnabled         = if ($connector.PSObject.Properties.Name -contains 'DomainSecureEnabled') { [bool]$connector.DomainSecureEnabled } else { $null }
                            MaxMessageSizeBytes         = $sendConnMaxMsgSize
                            ConnectionInactivityTimeOut = if ($connector.PSObject.Properties.Name -contains 'ConnectionInactivityTimeOut' -and $null -ne $connector.ConnectionInactivityTimeOut) { [string]$connector.ConnectionInactivityTimeOut } else { $null }
                        })
                }
            }
            catch {
                $exchEndpointWarnings += ('Get-SendConnector via endpoint failed: ' + $_.Exception.Message)
            }

            try {
                $sb = [scriptblock]::Create('Get-Mailbox -ResultSize Unlimited')
                $mailboxes = @(Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb)
                $sharedLikeNames = @($mailboxes | Where-Object {
                        $_.RecipientTypeDetails -ne 'UserMailbox' -and
                        ($_.PSObject.Properties.Name -contains 'AccountDisabled') -and
                        -not [bool]$_.AccountDisabled
                    })
                $inventory.Exchange.SharedMailboxTypeMismatchCount = $sharedLikeNames.Count
                $inventory.Exchange.SharedMailboxTypeMismatches = @($sharedLikeNames | ForEach-Object { [string]$_.DisplayName })

                $sirDisabled = @($mailboxes | Where-Object {
                        $_.RecipientTypeDetails -eq 'UserMailbox' -and
                        ($_.PSObject.Properties.Name -contains 'SingleItemRecoveryEnabled') -and
                        -not [bool]$_.SingleItemRecoveryEnabled
                    })
                $inventory.Exchange.SingleItemRecoveryDisabledCount = $sirDisabled.Count
                $inventory.Exchange.SingleItemRecoveryDisabledMailboxes = @($sirDisabled | ForEach-Object { [string]$_.DisplayName })
            }
            catch {
                $exchEndpointWarnings += ('Get-Mailbox via endpoint failed: ' + $_.Exception.Message)
            }

            try {
                $sb = [scriptblock]::Create("Get-MailboxDatabase -Server '$invokeTarget'")
                $mailboxDatabases = @(Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb)
                $storagePathSet = @{}
                foreach ($mailboxDatabase in $mailboxDatabases) {
                    $candidatePaths = @()
                    if ($mailboxDatabase.PSObject.Properties.Name -contains 'EdbFilePath' -and $null -ne $mailboxDatabase.EdbFilePath) {
                        $candidatePaths += [string]$mailboxDatabase.EdbFilePath
                    }
                    if ($mailboxDatabase.PSObject.Properties.Name -contains 'LogFolderPath' -and $null -ne $mailboxDatabase.LogFolderPath) {
                        $candidatePaths += [string]$mailboxDatabase.LogFolderPath
                    }
                    foreach ($candidatePath in $candidatePaths) {
                        if (-not [string]::IsNullOrWhiteSpace($candidatePath)) {
                            $np = $candidatePath.Trim()
                            if (-not $storagePathSet.ContainsKey($np)) {
                                $storagePathSet[$np] = $true
                                $inventory.Exchange.DatabaseStoragePaths = @($inventory.Exchange.DatabaseStoragePaths) + @($np)
                            }
                        }
                    }
                    $itemRetDays = $null
                    if ($mailboxDatabase.PSObject.Properties.Name -contains 'DeletedItemRetention' -and $null -ne $mailboxDatabase.DeletedItemRetention) {
                        try { $itemRetDays = [int]([timespan]$mailboxDatabase.DeletedItemRetention).TotalDays } catch {}
                    }
                    $mbxRetDays = $null
                    if ($mailboxDatabase.PSObject.Properties.Name -contains 'MailboxRetention' -and $null -ne $mailboxDatabase.MailboxRetention) {
                        try { $mbxRetDays = [int]([timespan]$mailboxDatabase.MailboxRetention).TotalDays } catch {}
                    }
                    $bkpRestore = if ($mailboxDatabase.PSObject.Properties.Name -contains 'RetainDeletedItemsUntilBackup') { [bool]$mailboxDatabase.RetainDeletedItemsUntilBackup } else { $null }
                    $iqIsUnlimited = $true
                    $iqBytes = $null
                    if ($mailboxDatabase.PSObject.Properties.Name -contains 'IssueWarningQuota' -and $null -ne $mailboxDatabase.IssueWarningQuota) {
                        $iqStr = [string]$mailboxDatabase.IssueWarningQuota
                        if ($iqStr -ne 'Unlimited') {
                            $iqIsUnlimited = $false
                            $iqM = [regex]::Match($iqStr, '\(([\d,]+)\s*bytes\)')
                            if ($iqM.Success) { try { $iqBytes = [long]($iqM.Groups[1].Value -replace ',', '') } catch {} }
                        }
                    }
                    $psqIsUnlimited = $true
                    $psqBytes = $null
                    if ($mailboxDatabase.PSObject.Properties.Name -contains 'ProhibitSendQuota' -and $null -ne $mailboxDatabase.ProhibitSendQuota) {
                        $psqStr = [string]$mailboxDatabase.ProhibitSendQuota
                        if ($psqStr -ne 'Unlimited') {
                            $psqIsUnlimited = $false
                            $psqM = [regex]::Match($psqStr, '\(([\d,]+)\s*bytes\)')
                            if ($psqM.Success) { try { $psqBytes = [long]($psqM.Groups[1].Value -replace ',', '') } catch {} }
                        }
                    }
                    $psrqIsUnlimited = $true
                    $psrqBytes = $null
                    if ($mailboxDatabase.PSObject.Properties.Name -contains 'ProhibitSendReceiveQuota' -and $null -ne $mailboxDatabase.ProhibitSendReceiveQuota) {
                        $psrqStr = [string]$mailboxDatabase.ProhibitSendReceiveQuota
                        if ($psrqStr -ne 'Unlimited') {
                            $psrqIsUnlimited = $false
                            $psrqM = [regex]::Match($psrqStr, '\(([\d,]+)\s*bytes\)')
                            if ($psrqM.Success) { try { $psrqBytes = [long]($psrqM.Groups[1].Value -replace ',', '') } catch {} }
                        }
                    }
                    $inventory.Exchange.MailboxDatabases = @($inventory.Exchange.MailboxDatabases) + @([pscustomobject]@{
                            Name                                = [string]$mailboxDatabase.Name
                            ItemRetentionDays                   = $itemRetDays
                            MailboxRetentionDays                = $mbxRetDays
                            RetainDeletedItemsUntilBackup       = $bkpRestore
                            IssueWarningQuotaIsUnlimited        = $iqIsUnlimited
                            IssueWarningQuotaBytes              = $iqBytes
                            ProhibitSendQuotaIsUnlimited        = $psqIsUnlimited
                            ProhibitSendQuotaBytes              = $psqBytes
                            ProhibitSendReceiveQuotaIsUnlimited = $psrqIsUnlimited
                            ProhibitSendReceiveQuotaBytes       = $psrqBytes
                            CircularLoggingEnabled              = if ($mailboxDatabase.PSObject.Properties.Name -contains 'CircularLoggingEnabled') { [bool]$mailboxDatabase.CircularLoggingEnabled } else { $null }
                            MountAtStartup                      = if ($mailboxDatabase.PSObject.Properties.Name -contains 'MountAtStartup') { [bool]$mailboxDatabase.MountAtStartup } else { $null }
                            EdbFilePath                         = if ($mailboxDatabase.PSObject.Properties.Name -contains 'EdbFilePath' -and $null -ne $mailboxDatabase.EdbFilePath) { [string]$mailboxDatabase.EdbFilePath } else { $null }
                            LogFolderPath                       = if ($mailboxDatabase.PSObject.Properties.Name -contains 'LogFolderPath' -and $null -ne $mailboxDatabase.LogFolderPath) { [string]$mailboxDatabase.LogFolderPath } else { $null }
                            DatabaseCopiesCount                 = if ($mailboxDatabase.PSObject.Properties.Name -contains 'DatabaseCopies') { @($mailboxDatabase.DatabaseCopies).Count } else { 1 }
                        })
                }
            }
            catch {
                $exchEndpointWarnings += ('Get-MailboxDatabase via endpoint failed: ' + $_.Exception.Message)
            }

            try {
                $sb = [scriptblock]::Create("Test-ReplicationHealth -Identity '$invokeTarget'")
                $replication = @(Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb)
                $failed = @($replication | Where-Object { $_.Result -ne 'Passed' })
                $inventory.Exchange.ReplicationHealthPassed = ($failed.Count -eq 0)
            }
            catch {
                $exchEndpointWarnings += ('Test-ReplicationHealth via endpoint failed: ' + $_.Exception.Message)
            }

            try {
                $sb = [scriptblock]::Create('Get-AuthConfig')
                $authConfig = Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb
                $authCertificateThumbprint = $null
                if ($null -ne $authConfig -and $authConfig.PSObject.Properties.Name -contains 'CurrentCertificateThumbprint') {
                    $authCertificateThumbprint = [string]$authConfig.CurrentCertificateThumbprint
                }
                $inventory.Exchange.AuthCertificate = Get-EDCACertificateStatusFromInventory -Thumbprint $authCertificateThumbprint -Certificates @($inventory.Certificates)
            }
            catch {
                $exchEndpointWarnings += ('Get-AuthConfig via endpoint failed: ' + $_.Exception.Message)
            }

            try {
                $sb = [scriptblock]::Create("Get-TransportService -Identity '$invokeTarget'")
                $transportService = Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb
                if ($null -ne $transportService) {
                    $maxOutboundConnections = $null
                    if ($transportService.PSObject.Properties.Name -contains 'MaxOutboundConnections' -and $null -ne $transportService.MaxOutboundConnections) {
                        $mocStr = [string]$transportService.MaxOutboundConnections
                        if ($mocStr -ne 'Unlimited') { try { $maxOutboundConnections = [int]$mocStr } catch {} } else { $maxOutboundConnections = -1 }
                    }

                    $maxPerDomainOutboundConnections = $null
                    if ($transportService.PSObject.Properties.Name -contains 'MaxPerDomainOutboundConnections' -and $null -ne $transportService.MaxPerDomainOutboundConnections) {
                        $mpdocStr = [string]$transportService.MaxPerDomainOutboundConnections
                        if ($mpdocStr -ne 'Unlimited') { try { $maxPerDomainOutboundConnections = [int]$mpdocStr } catch {} } else { $maxPerDomainOutboundConnections = -1 }
                    }

                    $messageRetryIntervalMinutes = $null
                    if ($transportService.PSObject.Properties.Name -contains 'MessageRetryInterval' -and $null -ne $transportService.MessageRetryInterval) {
                        $messageRetryIntervalMinutes = Get-EDCAIntervalMinutes -Value $transportService.MessageRetryInterval
                    }

                    $connectivityLogEnabled = $null
                    if ($transportService.PSObject.Properties.Name -contains 'ConnectivityLogEnabled') {
                        $connectivityLogEnabled = [bool]$transportService.ConnectivityLogEnabled
                    }

                    $messageTrackingLogEnabled = $null
                    if ($transportService.PSObject.Properties.Name -contains 'MessageTrackingLogEnabled') {
                        $messageTrackingLogEnabled = [bool]$transportService.MessageTrackingLogEnabled
                    }

                    $messageTrackingLogSubjectLoggingEnabled = $null
                    if ($transportService.PSObject.Properties.Name -contains 'MessageTrackingLogSubjectLoggingEnabled') {
                        $messageTrackingLogSubjectLoggingEnabled = [bool]$transportService.MessageTrackingLogSubjectLoggingEnabled
                    }

                    $pickupDirectoryPath = $null
                    if ($transportService.PSObject.Properties.Name -contains 'PickupDirectoryPath' -and -not [string]::IsNullOrWhiteSpace([string]$transportService.PickupDirectoryPath)) {
                        $pickupDirectoryPath = [string]$transportService.PickupDirectoryPath
                    }

                    $inventory.Exchange.TransportRetryConfig = [pscustomobject]@{
                        MaxOutboundConnections                  = $maxOutboundConnections
                        MaxPerDomainOutboundConnections         = $maxPerDomainOutboundConnections
                        MessageRetryIntervalMinutes             = $messageRetryIntervalMinutes
                        ConnectivityLogEnabled                  = $connectivityLogEnabled
                        MessageTrackingLogEnabled               = $messageTrackingLogEnabled
                        MessageTrackingLogSubjectLoggingEnabled = $messageTrackingLogSubjectLoggingEnabled
                        PickupDirectoryPath                     = $pickupDirectoryPath
                    }

                    $internalTransportCertificateThumbprint = $null
                    if ($transportService.PSObject.Properties.Name -contains 'InternalTransportCertificateThumbprint') {
                        $internalTransportCertificateThumbprint = [string]$transportService.InternalTransportCertificateThumbprint
                    }

                    $inventory.Exchange.InternalTransportCertificate = Get-EDCACertificateStatusFromInventory -Thumbprint $internalTransportCertificateThumbprint -Certificates @($inventory.Certificates)
                }
            }
            catch {
                $exchEndpointWarnings += ('Get-TransportService via endpoint failed: ' + $_.Exception.Message)
            }

            $settingOverrides = @()
            try {
                $sb = [scriptblock]::Create('Get-SettingOverride')
                $settingOverrides = @(Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb)
                $settingOverrideNames = @($settingOverrides | ForEach-Object { [string]$_.Name } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)
                $settingOverrideDetails = @($settingOverrides | ForEach-Object {
                        $n = if ($_.PSObject.Properties.Name -contains 'Name') { [string]$_.Name } else { '' }
                        $s = if (($_.PSObject.Properties.Name -contains 'Server') -and ($null -ne $_.Server)) { [string]$_.Server } else { '' }
                        [pscustomobject]@{ Name = $n; Server = $s }
                    } | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Name) })
                $inventory.Exchange.SettingOverrides = [pscustomobject]@{
                    Count   = $settingOverrides.Count
                    Names   = $settingOverrideNames
                    Details = $settingOverrideDetails
                }

                if ($null -ne $inventory.Exchange.Amsi) {
                    $amsiDisabledBySettingOverride = @($settingOverrides | Where-Object {
                            $componentName = if ($_.PSObject.Properties.Name -contains 'ComponentName') { [string]$_.ComponentName } else { '' }
                            $sectionName = if ($_.PSObject.Properties.Name -contains 'SectionName') { [string]$_.SectionName } else { '' }
                            $parametersText = ''
                            if ($_.PSObject.Properties.Name -contains 'Parameters' -and $null -ne $_.Parameters) {
                                $parametersText = [string]::Join(';', @($_.Parameters | ForEach-Object { [string]$_ }))
                            }

                            $componentName -eq 'Cafe' -and
                            $sectionName -eq 'HttpRequestFiltering' -and
                            $parametersText -match 'Enabled\s*=\s*false'
                        }).Count -gt 0

                    $inventory.Exchange.Amsi = [pscustomobject]@{
                        ProviderCount             = $inventory.Exchange.Amsi.ProviderCount
                        ProviderIds               = $inventory.Exchange.Amsi.ProviderIds
                        DisabledBySettingOverride = $amsiDisabledBySettingOverride
                    }
                }
            }
            catch {
                $exchEndpointWarnings += ('Get-SettingOverride via endpoint failed: ' + $_.Exception.Message)
            }

            # Derive SerializedDataSigningEnabled from SettingOverrides + build version.
            # Exchange 2016/2019/SE: feature is controlled by SettingOverride (Component=Data,
            #   Section=EnableSerializationDataSigning, Parameter=Enabled).  Exchange SE and builds
            #   >= Nov23SU have it enabled by default when no override is present.
            # Exchange 2013: controlled by registry key (already read in the collection script block).
            $productLine = if (($inventory.Exchange.PSObject.Properties.Name -contains 'ProductLine')) { [string]$inventory.Exchange.ProductLine } else { '' }
            if ($productLine -in @('Exchange2016', 'Exchange2019', 'ExchangeSE')) {
                try {
                    # Parse build numbers from AdminDisplayVersion ("Version 15.2 (Build 1118.40)").
                    $adv = if ($inventory.Exchange.PSObject.Properties.Name -contains 'AdminDisplayVersion') { [string]$inventory.Exchange.AdminDisplayVersion } else { '' }
                    $advBuildMajor = 0
                    $advBuildMinor = 0
                    if ($adv -match 'Build\s+(\d+)\.(\d+)') {
                        $advBuildMajor = [int]$matches[1]
                        $advBuildMinor = [int]$matches[2]
                    }

                    # Nov23SU thresholds (first build where feature is on by default):
                    #   Exchange 2016 CU23 Nov23SU : 15.1.2507.35
                    #   Exchange 2019 CU13 Nov23SU : 15.2.1118.35
                    #   Exchange SE                : always on by default
                    $enabledByDefault = $false
                    if ($productLine -eq 'ExchangeSE') {
                        $enabledByDefault = $true
                    }
                    elseif ($productLine -eq 'Exchange2016') {
                        $enabledByDefault = ($advBuildMajor -gt 2507) -or ($advBuildMajor -eq 2507 -and $advBuildMinor -ge 35)
                    }
                    elseif ($productLine -eq 'Exchange2019') {
                        $enabledByDefault = ($advBuildMajor -gt 1118) -or ($advBuildMajor -eq 1118 -and $advBuildMinor -ge 35)
                    }

                    # Find a SettingOverride that explicitly configures the feature for this server.
                    $sdsOverride = $settingOverrides | Where-Object {
                        $cn = if ($_.PSObject.Properties.Name -contains 'ComponentName') { [string]$_.ComponentName } else { '' }
                        $sn = if ($_.PSObject.Properties.Name -contains 'SectionName') { [string]$_.SectionName } else { '' }
                        $cn -eq 'Data' -and $sn -eq 'EnableSerializationDataSigning'
                    } | Select-Object -First 1

                    if ($null -ne $sdsOverride) {
                        $paramText = ''
                        if ($sdsOverride.PSObject.Properties.Name -contains 'Parameters' -and $null -ne $sdsOverride.Parameters) {
                            $paramText = [string]::Join(';', @($sdsOverride.Parameters | ForEach-Object { [string]$_ }))
                        }
                        if ($paramText -match 'Enabled\s*=\s*True') {
                            $inventory.Exchange.SerializedDataSigningEnabled = $true
                        }
                        elseif ($paramText -match 'Enabled\s*=\s*False') {
                            $inventory.Exchange.SerializedDataSigningEnabled = $false
                        }
                        # Unknown parameter value - leave as $null so analysis reports Unknown.
                    }
                    else {
                        # No override: use version-derived default.
                        $inventory.Exchange.SerializedDataSigningEnabled = $enabledByDefault
                    }
                }
                catch {
                    $exchEndpointWarnings += ('SerializedDataSigning state determination failed: ' + $_.Exception.Message)
                }
            }
            # Exchange 2013: SerializedDataSigningEnabled already set from registry in script block.

            $sharedExchangeOnlineAppId = '00000002-0000-0ff1-ce00-000000000000'
            $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

            try {
                $sb = [scriptblock]::Create('Get-AuthServer')
                $authServers = @(Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb)
                $evoStsAuthServers = @($authServers | Where-Object {
                        $_.PSObject.Properties.Name -contains 'Name' -and
                        $_.PSObject.Properties.Name -contains 'Type' -and
                        $_.PSObject.Properties.Name -contains 'Enabled' -and
                        ([string]$_.Name -like 'EvoSTS*') -and
                        ([string]$_.Type -eq 'AzureAD') -and
                        [bool]$_.Enabled
                    })

                $acsAuthServers = @($authServers | Where-Object {
                        $_.PSObject.Properties.Name -contains 'Type' -and
                        $_.PSObject.Properties.Name -contains 'Enabled' -and
                        ([string]$_.Type -eq 'MicrosoftACS') -and
                        [bool]$_.Enabled
                    })

                $exchangeOnlinePartnerApplication = @()
                try {
                    $sb = [scriptblock]::Create('Get-PartnerApplication')
                    $partnerApplications = @(Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock $sb)
                    $exchangeOnlinePartnerApplication = @($partnerApplications | Where-Object {
                            $applicationIdentifier = if ($_.PSObject.Properties.Name -contains 'ApplicationIdentifier') { [string]$_.ApplicationIdentifier } else { '' }
                            $enabled = if ($_.PSObject.Properties.Name -contains 'Enabled') { [bool]$_.Enabled } else { $true }

                            $enabled -and ($applicationIdentifier -eq $sharedExchangeOnlineAppId)
                        })
                }
                catch {
                    $exchEndpointWarnings += ('Get-PartnerApplication via endpoint failed: ' + $_.Exception.Message)
                }

                $enabledHybridPartnerApplication = ($exchangeOnlinePartnerApplication.Count -gt 0)

                $oAuthConfigured = ((($evoStsAuthServers.Count -or $acsAuthServers.Count) -gt 0) -and ($exchangeOnlinePartnerApplication.Count -gt 0))

                $dedicatedHybridAppOverrides = @($settingOverrides | Where-Object {
                        $componentName = if ($_.PSObject.Properties.Name -contains 'ComponentName') { [string]$_.ComponentName } else { '' }
                        $sectionName = if ($_.PSObject.Properties.Name -contains 'SectionName') { [string]$_.SectionName } else { '' }
                        $componentName -eq 'Global' -and $sectionName -eq 'ExchangeOnpremAsThirdPartyAppId'
                    })

                $sharedAppAuthServers = @($evoStsAuthServers | Where-Object {
                        ([string]$_.ApplicationIdentifier) -eq $sharedExchangeOnlineAppId
                    })

                $dedicatedAppAuthServers = @($evoStsAuthServers | Where-Object {
                        $applicationIdentifier = [string]$_.ApplicationIdentifier
                        ($applicationIdentifier -match $guidPattern) -and ($applicationIdentifier -ne $sharedExchangeOnlineAppId)
                    })

                $dedicatedHybridAppConfigured = ($dedicatedHybridAppOverrides.Count -ge 1) -and ($dedicatedAppAuthServers.Count -ge 1) -and ($sharedAppAuthServers.Count -eq 0)

                $evoStsIsDefaultAuthorizationEndpoint = (@($evoStsAuthServers | Where-Object {
                            $_.PSObject.Properties.Name -contains 'IsDefaultAuthorizationEndpoint' -and
                            [bool]$_.IsDefaultAuthorizationEndpoint
                        }).Count -gt 0)

                $defaultAuthorizationServer = @($authServers | Where-Object {
                        $_.PSObject.Properties.Name -contains 'IsDefaultAuthorizationEndpoint' -and
                        [bool]$_.IsDefaultAuthorizationEndpoint -eq $true
                    }) | Select-Object -First 1
                $defaultAuthServerUrl = if ($null -ne $defaultAuthorizationServer -and
                    $defaultAuthorizationServer.PSObject.Properties.Name -contains 'AuthMetadataUrl' -and
                    -not [string]::IsNullOrWhiteSpace([string]$defaultAuthorizationServer.AuthMetadataUrl)) {
                    [string]$defaultAuthorizationServer.AuthMetadataUrl
                }
                else { '' }
                $modernAuthType = if ([string]::IsNullOrWhiteSpace($defaultAuthServerUrl)) { 'None' }
                elseif ($defaultAuthServerUrl -match 'login\.windows\.net|login\.microsoftonline\.com') { 'HMA' }
                else { 'ADFS' }

                $hmaDownloadDomainOverride = @($settingOverrides | Where-Object {
                        $cn = if ($_.PSObject.Properties.Name -contains 'ComponentName') { [string]$_.ComponentName } else { '' }
                        $sn = if ($_.PSObject.Properties.Name -contains 'SectionName') { [string]$_.SectionName } else { '' }
                        $pt = if ($_.PSObject.Properties.Name -contains 'Parameters' -and $null -ne $_.Parameters) { [string]::Join(';', @($_.Parameters | ForEach-Object { [string]$_ })) } else { '' }
                        $cn -eq 'OAuth' -and $sn -eq 'OAuthIdentityCacheFixForDownloadDomains' -and $pt -match 'Enabled\s*=\s*True'
                    })
                $inventory.Exchange.OAuthHmaDownloadDomainOverrideConfigured = ($hmaDownloadDomainOverride.Count -gt 0)

                $hybridConfigured = $oAuthConfigured
                $inventory.Exchange.HybridApplication = [pscustomobject]@{
                    Configured                             = $hybridConfigured
                    EvoStsIsDefaultAuthorizationEndpoint   = $evoStsIsDefaultAuthorizationEndpoint
                    DedicatedHybridAppConfigured           = $dedicatedHybridAppConfigured
                    DedicatedHybridAppOverrideCount        = $dedicatedHybridAppOverrides.Count
                    DedicatedHybridAppAuthServerCount      = $dedicatedAppAuthServers.Count
                    SharedExchangeOnlineAppAuthServerCount = $sharedAppAuthServers.Count
                    DefaultAuthServerAuthMetadataUrl       = $defaultAuthServerUrl
                    ModernAuthType                         = $modernAuthType
                    Details                                = ('OAuth hybrid detected: {0}; EvoSTS auth servers: {1}; ACS auth servers: {2}; Exchange Online partner app enabled: {3}; dedicated-hybrid-app override count: {4}; dedicated-app auth server count: {5}; shared-app auth server count: {6}; EvoSTS IsDefaultAuthorizationEndpoint: {7}; modern auth type: {8}; default auth server URL: {9}' -f $hybridConfigured, $evoStsAuthServers.Count, $acsAuthServers.Count, $enabledHybridPartnerApplication, $dedicatedHybridAppOverrides.Count, $dedicatedAppAuthServers.Count, $sharedAppAuthServers.Count, $evoStsIsDefaultAuthorizationEndpoint, $modernAuthType, $defaultAuthServerUrl)
                }
            }
            catch {
                $exchEndpointWarnings += ('Get-AuthServer via endpoint failed: ' + $_.Exception.Message)
            }

            try {
                $certSvcResult = @(Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock {
                        Get-ExchangeCertificate -ErrorAction Stop | Select-Object -Property Thumbprint, Services
                    })
                $certSvcMap = @{}
                foreach ($ec in $certSvcResult) {
                    if (-not [string]::IsNullOrWhiteSpace([string]$ec.Thumbprint)) {
                        $certSvcMap[[string]$ec.Thumbprint] = [string]$ec.Services
                    }
                }
                $updatedCerts = @()
                foreach ($cert in @($inventory.Certificates)) {
                    $svc = if ($certSvcMap.ContainsKey([string]$cert.Thumbprint)) { $certSvcMap[[string]$cert.Thumbprint] } else { 'None' }
                    $updatedCerts += [pscustomobject]@{
                        Subject    = [string]$cert.Subject
                        Thumbprint = [string]$cert.Thumbprint
                        NotAfter   = $cert.NotAfter
                        IsExpired  = [bool]$cert.IsExpired
                        Services   = $svc
                    }
                }
                $inventory | Add-Member -MemberType NoteProperty -Name Certificates -Value $updatedCerts -Force
            }
            catch {
                $exchEndpointWarnings += ('Get-ExchangeCertificate via endpoint failed: ' + $_.Exception.Message)
            }

            try {
                $inventory.Exchange.ServiceHealth = @(Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -ScriptBlock {
                        Test-ServiceHealth -ErrorAction Stop | Select-Object -Property Role, RequiredServicesRunning, ServicesNotRunning
                    })
            }
            catch {
                $exchEndpointWarnings += ('Test-ServiceHealth via endpoint failed: ' + $_.Exception.Message)
            }
        }
    }

    if ($isEdge -and ($inventory.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $inventory.Exchange -and [bool]$inventory.Exchange.IsExchangeServer) {
        Write-Verbose ('Collecting Exchange cmdlet data for Edge server {0} via {1}.' -f $invokeTarget, $(if ($isLocalTarget) { 'direct invocation (PSSnapin)' } else { 'Exchange endpoint (ConnectionUri/Negotiate)' }))
        $edgeEndpointWarnings = @()
        $edgeCmdletsAvailable = $false
        $edgeData = [pscustomobject]@{
            AntispamAgentsEnabled    = $null
            EdgeSubscriptions        = @()
            ContentFilterConfig      = $null
            RecipientFilterConfig    = $null
            SenderFilterConfig       = $null
            ConnectionFilteringAgent = $null
            SendConnectors           = @()
            ReceiveConnectors        = @()
            SenderReputationConfig   = $null
            SenderIdConfig           = $null
        }

        $invokeEdge = if ($isLocalTarget) {
            { param([scriptblock]$Cmd) & $Cmd }
        }
        else {
            { param([scriptblock]$Cmd) Invoke-EDCAExchangeEndpointCommand -Server $invokeTarget -Authentication Negotiate -ScriptBlock $Cmd }
        }

        try {
            $sbEdgeSrv = [scriptblock]::Create("Get-ExchangeServer -Identity '$invokeTarget'")
            $edgeServer = & $invokeEdge $sbEdgeSrv
            if ($null -ne $edgeServer) {
                $edgeCmdletsAvailable = $true
                $inventory.Exchange.ExchangeCmdletsAvailable = $true
                if ($edgeServer.PSObject.Properties.Name -contains 'Name') { $inventory.Exchange.Name = [string]$edgeServer.Name }
                if ($edgeServer.PSObject.Properties.Name -contains 'AdminDisplayVersion') { $inventory.Exchange.AdminDisplayVersion = [string]$edgeServer.AdminDisplayVersion }
                if ($edgeServer.PSObject.Properties.Name -contains 'Edition') { $inventory.Exchange.Edition = [string]$edgeServer.Edition }
                $adv = [string]$inventory.Exchange.AdminDisplayVersion
                if ($adv -match 'Version 15\.1') { $inventory.Exchange.ProductLine = 'Exchange2016' }
                elseif ($adv -match 'Version 15\.2') {
                    $isSe = $false
                    if ($edgeServer.PSObject.Properties.Name -contains 'IsExchangeServerSubscriptionEdition') { $isSe = [bool]$edgeServer.IsExchangeServerSubscriptionEdition }
                    if (-not $isSe -and $adv -match 'Subscription|SE') { $isSe = $true }
                    if (-not $isSe -and $adv -match 'Build\s+(\d+)\.') { if ([int]$matches[1] -ge 2562) { $isSe = $true } }
                    $inventory.Exchange.ProductLine = if ($isSe) { 'ExchangeSE' } else { 'Exchange2019' }
                }
            }
        }
        catch {
            $edgeEndpointWarnings += ('Get-ExchangeServer (Edge/Negotiate) failed: ' + $_.Exception.Message)
        }

        if ($edgeCmdletsAvailable) {
            try {
                $certSvcResult = @(& $invokeEdge {
                        Get-ExchangeCertificate -ErrorAction Stop | Select-Object -Property Thumbprint, Services
                    })
                $certSvcMap = @{}
                foreach ($ec in $certSvcResult) {
                    if (-not [string]::IsNullOrWhiteSpace([string]$ec.Thumbprint)) { $certSvcMap[[string]$ec.Thumbprint] = [string]$ec.Services }
                }
                $updatedCerts = @()
                foreach ($cert in @($inventory.Certificates)) {
                    $svc = if ($certSvcMap.ContainsKey([string]$cert.Thumbprint)) { $certSvcMap[[string]$cert.Thumbprint] } else { 'None' }
                    $updatedCerts += [pscustomobject]@{
                        Subject    = [string]$cert.Subject
                        Thumbprint = [string]$cert.Thumbprint
                        NotAfter   = $cert.NotAfter
                        IsExpired  = [bool]$cert.IsExpired
                        Services   = $svc
                    }
                }
                $inventory | Add-Member -MemberType NoteProperty -Name Certificates -Value $updatedCerts -Force
            }
            catch {
                $edgeEndpointWarnings += ('Get-ExchangeCertificate (Edge/Negotiate) failed: ' + $_.Exception.Message)
            }

            try {
                $edgeData.EdgeSubscriptions = @(& $invokeEdge {
                        Get-EdgeSubscription -ErrorAction Stop | Select-Object -Property Name, Domain, Site, CreateUtc, LifeTime, LeaseType, IsValid
                    })
            }
            catch {
                $edgeEndpointWarnings += ('Get-EdgeSubscription (Edge/Negotiate) failed: ' + $_.Exception.Message)
            }

            try {
                $edgeData.ContentFilterConfig = & $invokeEdge {
                    Get-ContentFilterConfig -ErrorAction Stop | Select-Object -Property Enabled, QuarantineMailbox, RejectionResponse, SCLRejectEnabled, SCLDeleteEnabled
                }
            }
            catch {
                $edgeEndpointWarnings += ('Get-ContentFilterConfig (Edge/Negotiate) failed: ' + $_.Exception.Message)
            }

            try {
                $edgeData.RecipientFilterConfig = & $invokeEdge {
                    Get-RecipientFilterConfig -ErrorAction Stop | Select-Object -Property Enabled, BlockListEnabled, RecipientValidationEnabled
                }
            }
            catch {
                $edgeEndpointWarnings += ('Get-RecipientFilterConfig (Edge/Negotiate) failed: ' + $_.Exception.Message)
            }

            try {
                $edgeData.SenderFilterConfig = & $invokeEdge {
                    Get-SenderFilterConfig -ErrorAction Stop | Select-Object -Property Enabled, BlankSenderBlockingEnabled, BlockedSenders, BlockedDomains
                }
            }
            catch {
                $edgeEndpointWarnings += ('Get-SenderFilterConfig (Edge/Negotiate) failed: ' + $_.Exception.Message)
            }

            try {
                $cfAgent = & $invokeEdge {
                    Get-TransportAgent -Identity 'Connection Filtering Agent' -ErrorAction Stop
                }
                $edgeData.ConnectionFilteringAgent = [pscustomobject]@{
                    Enabled = if ($null -ne $cfAgent -and $cfAgent.PSObject.Properties.Name -contains 'Enabled') { [bool]$cfAgent.Enabled } else { $false }
                }
            }
            catch {
                $edgeEndpointWarnings += ('Get-TransportAgent "Connection Filtering Agent" (Edge/Negotiate) failed: ' + $_.Exception.Message)
            }

            try {
                $edgeData.SendConnectors = @(& $invokeEdge {
                        Get-SendConnector -ErrorAction Stop | Select-Object -Property Identity, RequireTls, TlsAuthLevel, TlsDomain, DomainSecureEnabled, Enabled, ProtocolLoggingLevel, SmartHosts, DNSRoutingEnabled, SmartHostAuthMechanism, MaxMessageSize
                    })
            }
            catch {
                $edgeEndpointWarnings += ('Get-SendConnector (Edge/Negotiate) failed: ' + $_.Exception.Message)
            }

            try {
                $edgeData.ReceiveConnectors = @(& $invokeEdge {
                        Get-ReceiveConnector -ErrorAction Stop | Select-Object -Property Identity, AuthMechanism, PermissionGroups, RequireTLS, DomainSecureEnabled, @{N = 'TarpitInterval'; E = { if ($null -ne $_.TarpitInterval) { [pscustomobject]@{Ticks = [long]$_.TarpitInterval.Ticks } } else { $null } } }, Banner, @{N = 'Bindings'; E = { @($_.Bindings | ForEach-Object { [string]$_ }) } }, Enabled
                    })
            }
            catch {
                $edgeEndpointWarnings += ('Get-ReceiveConnector (Edge/Negotiate) failed: ' + $_.Exception.Message)
            }

            try {
                $edgeData.SenderReputationConfig = & $invokeEdge {
                    Get-SenderReputationConfig -ErrorAction Stop | Select-Object -Property Enabled, SenderBlockingEnabled, SenderBlockingPeriod, MinimumSenderReputationLevel
                }
            }
            catch {
                $edgeEndpointWarnings += ('Get-SenderReputationConfig (Edge/Negotiate) failed: ' + $_.Exception.Message)
            }

            try {
                $edgeData.SenderIdConfig = & $invokeEdge {
                    Get-SenderIdConfig -ErrorAction Stop | Select-Object -Property Enabled, SpoofedDomainAction
                }
            }
            catch {
                $edgeEndpointWarnings += ('Get-SenderIdConfig (Edge/Negotiate) failed: ' + $_.Exception.Message)
            }

            try {
                $inventory.Exchange.ServiceHealth = @(& $invokeEdge {
                        Test-ServiceHealth -ErrorAction Stop | Select-Object -Property Role, RequiredServicesRunning, ServicesNotRunning
                    })
            }
            catch {
                $edgeEndpointWarnings += ('Test-ServiceHealth (Edge/Negotiate) failed: ' + $_.Exception.Message)
            }

            try {
                $sbEdgeTrans = [scriptblock]::Create("Get-TransportService -Identity '$invokeTarget'")
                $edgeTransportService = & $invokeEdge $sbEdgeTrans
                if ($null -ne $edgeTransportService) {
                    $maxOutboundConnections = $null
                    if ($edgeTransportService.PSObject.Properties.Name -contains 'MaxOutboundConnections' -and $null -ne $edgeTransportService.MaxOutboundConnections) {
                        $mocStr = [string]$edgeTransportService.MaxOutboundConnections
                        if ($mocStr -ne 'Unlimited') { try { $maxOutboundConnections = [int]$mocStr } catch {} } else { $maxOutboundConnections = -1 }
                    }

                    $maxPerDomainOutboundConnections = $null
                    if ($edgeTransportService.PSObject.Properties.Name -contains 'MaxPerDomainOutboundConnections' -and $null -ne $edgeTransportService.MaxPerDomainOutboundConnections) {
                        $mpdocStr = [string]$edgeTransportService.MaxPerDomainOutboundConnections
                        if ($mpdocStr -ne 'Unlimited') { try { $maxPerDomainOutboundConnections = [int]$mpdocStr } catch {} } else { $maxPerDomainOutboundConnections = -1 }
                    }

                    $messageRetryIntervalMinutes = $null
                    if ($edgeTransportService.PSObject.Properties.Name -contains 'MessageRetryInterval' -and $null -ne $edgeTransportService.MessageRetryInterval) {
                        $messageRetryIntervalMinutes = Get-EDCAIntervalMinutes -Value $edgeTransportService.MessageRetryInterval
                    }

                    $connectivityLogEnabled = $null
                    if ($edgeTransportService.PSObject.Properties.Name -contains 'ConnectivityLogEnabled') {
                        $connectivityLogEnabled = [bool]$edgeTransportService.ConnectivityLogEnabled
                    }

                    $messageTrackingLogEnabled = $null
                    if ($edgeTransportService.PSObject.Properties.Name -contains 'MessageTrackingLogEnabled') {
                        $messageTrackingLogEnabled = [bool]$edgeTransportService.MessageTrackingLogEnabled
                    }

                    $messageTrackingLogSubjectLoggingEnabled = $null
                    if ($edgeTransportService.PSObject.Properties.Name -contains 'MessageTrackingLogSubjectLoggingEnabled') {
                        $messageTrackingLogSubjectLoggingEnabled = [bool]$edgeTransportService.MessageTrackingLogSubjectLoggingEnabled
                    }

                    $pickupDirectoryPath = $null
                    if ($edgeTransportService.PSObject.Properties.Name -contains 'PickupDirectoryPath' -and -not [string]::IsNullOrWhiteSpace([string]$edgeTransportService.PickupDirectoryPath)) {
                        $pickupDirectoryPath = [string]$edgeTransportService.PickupDirectoryPath
                    }

                    if ($edgeTransportService.PSObject.Properties.Name -contains 'AntispamAgentsEnabled') {
                        $edgeData.AntispamAgentsEnabled = [bool]$edgeTransportService.AntispamAgentsEnabled
                    }

                    $inventory.Exchange.TransportRetryConfig = [pscustomobject]@{
                        MaxOutboundConnections                  = $maxOutboundConnections
                        MaxPerDomainOutboundConnections         = $maxPerDomainOutboundConnections
                        MessageRetryIntervalMinutes             = $messageRetryIntervalMinutes
                        ConnectivityLogEnabled                  = $connectivityLogEnabled
                        MessageTrackingLogEnabled               = $messageTrackingLogEnabled
                        MessageTrackingLogSubjectLoggingEnabled = $messageTrackingLogSubjectLoggingEnabled
                        PickupDirectoryPath                     = $pickupDirectoryPath
                    }
                }
            }
            catch {
                $edgeEndpointWarnings += ('Get-TransportService (Edge/Negotiate) failed: ' + $_.Exception.Message)
            }

            try {
                $edgeTransportAgents = @(& $invokeEdge {
                        Get-TransportAgent -ErrorAction Stop | Select-Object -Property Identity, Enabled
                    })
                foreach ($agent in $edgeTransportAgents) {
                    $inventory.Exchange.TransportAgents = @($inventory.Exchange.TransportAgents) + @([pscustomobject]@{
                            Identity = [string]$agent.Identity
                            Enabled  = if ($agent.PSObject.Properties.Name -contains 'Enabled') { [bool]$agent.Enabled } else { $null }
                        })
                }
            }
            catch {
                $edgeEndpointWarnings += ('Get-TransportAgent (Edge/Negotiate) failed: ' + $_.Exception.Message)
            }

            $inventory.Exchange.EdgeData = $edgeData
        }

        foreach ($w in $edgeEndpointWarnings) {
            $inventory.Exchange.CollectionWarnings = @($inventory.Exchange.CollectionWarnings) + @($w)
        }
    }

    foreach ($w in $exchEndpointWarnings) {
        $inventory.Exchange.CollectionWarnings = @($inventory.Exchange.CollectionWarnings) + @($w)
    }

    return $inventory
}

function Invoke-EDCAServerCollectionWorker {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    Write-Verbose ('Starting server worker for {0}.' -f $Server)
    $connectivity = Test-EDCAServerRemoteConnectivity -Server $Server
    Write-Verbose ('Precheck result for {0}: CanConnect={1}; CanReadRemoteRegistry={2}' -f $Server, [bool]$connectivity.CanConnect, [bool]$connectivity.CanReadRemoteRegistry)
    if (-not $connectivity.CanConnect -or -not $connectivity.CanReadRemoteRegistry) {
        $failureReason = if (-not $connectivity.CanConnect) {
            'Remote connectivity precheck failed.'
        }
        else {
            'Remote connectivity succeeded but registry access check failed.'
        }

        Write-EDCALog -Level 'WARN' -Message ('Skipping {0}: {1} {2}' -f $Server, $failureReason, $connectivity.Details)
        return [pscustomobject]@{
            Server               = $Server
            CollectionError      = ('{0} {1}' -f $failureReason, $connectivity.Details).Trim()
            ConnectivityPrecheck = $connectivity
        }
    }

    try {
        Write-EDCALog -Message ('Collecting from server: {0}' -f $Server)
        Write-Verbose ('Collecting inventory categories for {0}: OS, TLS, services, certificates, Exchange.' -f $Server)
        $inventory = Get-EDCAServerInventory -Server $Server
        $inventory | Add-Member -MemberType NoteProperty -Name ConnectivityPrecheck -Value $connectivity -Force
        $collectionWarnings = @()
        if ($inventory.PSObject.Properties.Name -contains 'Exchange' -and $null -ne $inventory.Exchange -and $inventory.Exchange.PSObject.Properties.Name -contains 'CollectionWarnings') {
            $collectionWarnings = @($inventory.Exchange.CollectionWarnings)
        }

        if ($collectionWarnings.Count -gt 0) {
            Write-EDCALog -Level 'WARN' -Message ('Collection on {0} completed with {1} warning(s):' -f $Server, $collectionWarnings.Count)
            foreach ($w in $collectionWarnings) {
                Write-EDCALog -Level 'WARN' -Message ('  {0}: {1}' -f $Server, $w)
            }
        }

        Write-Verbose ('Server worker completed for {0}.' -f $Server)
        return $inventory
    }
    catch {
        $errorDetail = Get-EDCAExceptionMessage -ErrorRecord $_
        Write-EDCALog -Level 'WARN' -Message ('Collection failed on {0}: {1}' -f $Server, $errorDetail)
        return [pscustomobject]@{
            Server               = $Server
            CollectionError      = $errorDetail
            ConnectivityPrecheck = $connectivity
        }
    }
}

function Invoke-EDCAParallelServerCollection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Servers,
        [ValidateRange(1, 128)]
        [int]$ThrottleLimit = 4
    )

    $targetServers = @($Servers | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).Trim() })
    if ($targetServers.Count -eq 0) {
        return @()
    }

    $canUseThreadJob = ($null -ne (Get-Command -Name Start-ThreadJob -ErrorAction SilentlyContinue))
    $jobBackend = if ($canUseThreadJob) { 'Start-ThreadJob' } else { 'Start-Job' }

    Write-Verbose ('Using parallel server collection for {0} target(s) with throttle {1} via {2}.' -f $targetServers.Count, $ThrottleLimit, $jobBackend)
    Write-EDCALog -Message ('Collecting data from {0} server(s).' -f $targetServers.Count)

    $commonModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Common.ps1'
    $collectionModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Collection.ps1'

    $jobScript = {
        param(
            [string]$TargetServer,
            [string]$CommonPath,
            [string]$CollectionPath
        )

        Set-StrictMode -Version Latest
        . $CommonPath
        . $CollectionPath

        Invoke-EDCAServerCollectionWorker -Server $TargetServer
    }

    $pendingQueue = [System.Collections.Queue]::new()
    for ($index = 0; $index -lt $targetServers.Count; $index++) {
        $pendingQueue.Enqueue([pscustomobject]@{
                Index  = $index
                Server = $targetServers[$index]
            })
    }

    $activeJobs = @()
    $resultsByIndex = @{}

    while ($pendingQueue.Count -gt 0 -or $activeJobs.Count -gt 0) {
        while ($pendingQueue.Count -gt 0 -and $activeJobs.Count -lt $ThrottleLimit) {
            $jobTarget = $pendingQueue.Dequeue()
            $job = if ($canUseThreadJob) {
                Start-ThreadJob -ScriptBlock $jobScript -ArgumentList @($jobTarget.Server, $commonModulePath, $collectionModulePath)
            }
            else {
                Start-Job -ScriptBlock $jobScript -ArgumentList @($jobTarget.Server, $commonModulePath, $collectionModulePath)
            }

            $activeJobs += [pscustomobject]@{
                Index  = $jobTarget.Index
                Server = $jobTarget.Server
                Job    = $job
            }
            Write-EDCALog -Message ('[{0}/{1}] Starting collection: {2}' -f ($jobTarget.Index + 1), $targetServers.Count, $jobTarget.Server)
        }

        if ($activeJobs.Count -eq 0) {
            continue
        }

        $completedJob = Wait-Job -Job @($activeJobs | ForEach-Object { $_.Job }) -Any
        $completedMeta = @($activeJobs | Where-Object { $_.Job.Id -eq $completedJob.Id } | Select-Object -First 1)
        if ($completedMeta.Count -eq 0) {
            continue
        }

        $meta = $completedMeta[0]
        $result = $null
        try {
            $jobOutput = @(Receive-Job -Job $completedJob -ErrorAction Stop)
            if ($jobOutput.Count -gt 0) {
                $result = $jobOutput[-1]
            }
            else {
                $result = [pscustomobject]@{
                    Server               = $meta.Server
                    CollectionError      = 'Parallel collection worker returned no result.'
                    ConnectivityPrecheck = $null
                }
            }
        }
        catch {
            $result = [pscustomobject]@{
                Server               = $meta.Server
                CollectionError      = ('Parallel collection worker failed: {0}' -f $_.Exception.Message)
                ConnectivityPrecheck = $null
            }
        }
        finally {
            Remove-Job -Job $completedJob -Force -ErrorAction SilentlyContinue
        }

        $resultsByIndex[$meta.Index] = $result
        $activeJobs = @($activeJobs | Where-Object { $_.Job.Id -ne $completedJob.Id })
        $collectionError = if ($result.PSObject.Properties.Name -contains 'CollectionError') { $result.CollectionError } else { $null }
        if (-not [string]::IsNullOrWhiteSpace($collectionError)) {
            Write-EDCALog -Level 'ERROR' -Message ('[{0}/{1}] {2}: {3}' -f ($meta.Index + 1), $targetServers.Count, $meta.Server, $collectionError)
        }
        else {
            Write-EDCALog -Message ('[{0}/{1}] Done: {2}' -f ($meta.Index + 1), $targetServers.Count, $meta.Server)
        }
    }

    $orderedResults = @()
    for ($index = 0; $index -lt $targetServers.Count; $index++) {
        if ($resultsByIndex.ContainsKey($index)) {
            $orderedResults += $resultsByIndex[$index]
        }
        else {
            $orderedResults += [pscustomobject]@{
                Server               = $targetServers[$index]
                CollectionError      = 'Parallel collection worker did not report a result.'
                ConnectivityPrecheck = $null
            }
        }
    }

    $errorCount = @($orderedResults | Where-Object { ($_.PSObject.Properties.Name -contains 'CollectionError') -and -not [string]::IsNullOrWhiteSpace($_.CollectionError) }).Count
    if ($errorCount -gt 0) {
        Write-EDCALog -Message ('Collection complete: {0} succeeded, {1} failed.' -f ($targetServers.Count - $errorCount), $errorCount) -Level WARN
    }
    else {
        Write-EDCALog -Message ('Collection complete: all {0} server(s) succeeded.' -f $targetServers.Count)
    }

    return $orderedResults
}

function Get-EDCAExchangeEnvironmentServers {
    [CmdletBinding()]
    param()

    # Discover Exchange servers via the well-known "Exchange Servers" universal security group.
    # Exchange Setup adds every Exchange server computer account to this group; membership is
    # authoritative. Uses .NET System.DirectoryServices - no RSAT/AD module required.
    Write-Verbose 'Discovering Exchange servers via AD group membership of "Exchange Servers" using .NET DirectoryServices.'

    try {
        $rootDse = [System.DirectoryServices.DirectoryEntry]::new('GC://RootDSE')
        $forestRootNC = [string]$rootDse.Properties['rootDomainNamingContext'][0]
    }
    catch {
        throw ('Failed to connect to Active Directory via LDAP: {0}. Provide -Servers explicitly.' -f $_.Exception.Message)
    }
    $gcForestRoot = [System.DirectoryServices.DirectoryEntry]::new(('GC://{0}' -f $forestRootNC))

    # Find the "Exchange Servers" group DN.
    $groupDn = $null
    try {
        $groupSearcher = [System.DirectoryServices.DirectorySearcher]::new($gcForestRoot)
        $groupSearcher.Filter = '(&(objectClass=group)(cn=Exchange Servers))'
        $groupSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $null = $groupSearcher.PropertiesToLoad.Add('distinguishedName')
        $groupResult = $groupSearcher.FindOne()
        if ($null -eq $groupResult) {
            throw '"Exchange Servers" group not found in Active Directory. Provide -Servers explicitly.'
        }
        $groupDn = [string]$groupResult.Properties['distinguishedName'][0]
    }
    catch {
        throw ('Exchange server discovery failed while locating group: {0}. Provide -Servers explicitly.' -f $_.Exception.Message)
    }

    Write-Verbose ('"Exchange Servers" group found: {0}' -f $groupDn)

    # Recursively enumerate computer members using LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941).
    $serverNames = [System.Collections.Generic.List[string]]::new()
    try {
        $memberSearcher = [System.DirectoryServices.DirectorySearcher]::new($gcForestRoot)
        $escapedDn = $groupDn -replace '\\', '\5c' -replace '\(', '\28' -replace '\)', '\29' -replace '\*', '\2a'
        $memberSearcher.Filter = ('(&(objectClass=computer)(memberOf:1.2.840.113556.1.4.1941:={0}))' -f $escapedDn)
        $memberSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
        $memberSearcher.PageSize = 1000
        $null = $memberSearcher.PropertiesToLoad.Add('name')
        $null = $memberSearcher.PropertiesToLoad.Add('dNSHostName')

        $results = $memberSearcher.FindAll()
        foreach ($result in $results) {
            $dns = if ($result.Properties['dNSHostName'].Count -gt 0) { [string]$result.Properties['dNSHostName'][0] } else { $null }
            $name = if ($result.Properties['name'].Count -gt 0) { [string]$result.Properties['name'][0] } else { $null }
            $resolved = if (-not [string]::IsNullOrWhiteSpace($dns)) { $dns } elseif (-not [string]::IsNullOrWhiteSpace($name)) { $name } else { $null }
            if (-not [string]::IsNullOrWhiteSpace($resolved)) {
                $serverNames.Add($resolved)
            }
        }
        $results.Dispose()
    }
    catch {
        throw ('Exchange server discovery failed while enumerating members: {0}. Provide -Servers explicitly.' -f $_.Exception.Message)
    }

    $unique = @($serverNames | Sort-Object -Unique)

    if ($unique.Count -eq 0) {
        throw 'The "Exchange Servers" group exists but contains no computer members. Provide -Servers explicitly.'
    }

    Write-Verbose ('Automatic discovery found {0} server(s): {1}' -f $unique.Count, ($unique -join ', '))

    return $unique
}

function Invoke-EDCAExchangeEndpointCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [ValidateSet('Kerberos', 'Negotiate')]
        [string]$Authentication = 'Kerberos'
    )

    $connectionHost = $Server
    if ($connectionHost -in @('.', 'localhost')) {
        $connectionHost = $env:COMPUTERNAME
    }

    if ($connectionHost.Equals($env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase)) {
        $userDnsDomain = [string]$env:USERDNSDOMAIN
        if (-not [string]::IsNullOrWhiteSpace($userDnsDomain)) {
            $connectionHost = ('{0}.{1}' -f $env:COMPUTERNAME, $userDnsDomain)
        }
    }

    $connectionUri = ('http://{0}/PowerShell' -f $connectionHost)

    return Invoke-Command -ConnectionUri $connectionUri -ConfigurationName Microsoft.Exchange -ScriptBlock $ScriptBlock -Authentication $Authentication -ErrorAction Stop
}

function Get-EDCAOrganizationInventory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    $organization = [pscustomobject]@{
        Available                          = $false
        SourceServer                       = $Server
        ExchangeCmdletsAvailable           = $true
        OrganizationIdentity               = $null
        OAuth2ClientProfileEnabled         = $null
        AdSplitPermissionEnabled           = $null
        CustomerFeedbackEnabled            = $null
        MaxRecipientEnvelopeLimit          = $null
        UpnPrimarySmtpMismatchCount        = $null
        AcceptedDomains                    = @()
        ForestFunctionalLevel              = $null
        DomainFunctionalLevel              = $null
        AdSiteCount                        = $null
        DefaultAuthPolicyName              = $null
        DefaultAuthPolicyBasicAuth         = $null
        AuthCertificate                    = $null
        TransportConfig                    = $null
        RemoteDomains                      = @()
        EdgeServers                        = @()
        MobileDevicePolicies               = @()
        IrmConfiguration                   = $null
        DcCoreRatio                        = $null
        DomainObjectDacl                   = $null
        ClientAccessRules                  = $null
        NonAdminRemotePowerShellUsers      = $null
        NonAdminRemotePowerShellCountTotal = $null
        CollectionWarnings                 = @()
    }

    Write-EDCALog -Message ('Collecting organization-level Exchange settings via {0}' -f $Server)

    try {
        $orgConfigResult = Invoke-EDCAExchangeEndpointCommand -Server $Server -ScriptBlock {
            Get-OrganizationConfig -ErrorAction Stop | Select-Object -First 1 -Property Identity, OAuth2ClientProfileEnabled, AdSplitPermissionEnabled, DefaultAuthenticationPolicy, CustomerFeedbackEnabled
        }

        if ($null -ne $orgConfigResult -and $orgConfigResult.PSObject.Properties.Name -contains 'Identity' -and -not [string]::IsNullOrWhiteSpace([string]$orgConfigResult.Identity)) {
            $organization.OrganizationIdentity = [string]$orgConfigResult.Identity
        }

        if ($null -ne $orgConfigResult -and $orgConfigResult.PSObject.Properties.Name -contains 'OAuth2ClientProfileEnabled') {
            $organization.OAuth2ClientProfileEnabled = [bool]$orgConfigResult.OAuth2ClientProfileEnabled
        }

        if ($null -ne $orgConfigResult -and $orgConfigResult.PSObject.Properties.Name -contains 'CustomerFeedbackEnabled' -and $null -ne $orgConfigResult.CustomerFeedbackEnabled) {
            $organization.CustomerFeedbackEnabled = [bool]$orgConfigResult.CustomerFeedbackEnabled
        }

        if ($null -ne $orgConfigResult -and $orgConfigResult.PSObject.Properties.Name -contains 'AdSplitPermissionEnabled' -and $null -ne $orgConfigResult.AdSplitPermissionEnabled) {
            $organization.AdSplitPermissionEnabled = [bool]$orgConfigResult.AdSplitPermissionEnabled
        }
        elseif ($null -ne $orgConfigResult -and $orgConfigResult.PSObject.Properties.Name -contains 'ADSplitPermissionEnabled' -and $null -ne $orgConfigResult.ADSplitPermissionEnabled) {
            $organization.AdSplitPermissionEnabled = [bool]$orgConfigResult.ADSplitPermissionEnabled
        }

        if ($null -ne $orgConfigResult -and $orgConfigResult.PSObject.Properties.Name -contains 'DefaultAuthenticationPolicy' -and -not [string]::IsNullOrWhiteSpace([string]$orgConfigResult.DefaultAuthenticationPolicy)) {
            $rawPolicyId = [string]$orgConfigResult.DefaultAuthenticationPolicy
            # DefaultAuthenticationPolicy may be returned as a DN (CN=name,...) - extract just the display name
            if ($rawPolicyId -match '^CN=([^,]+)') {
                $organization.DefaultAuthPolicyName = $Matches[1]
            }
            else {
                $organization.DefaultAuthPolicyName = $rawPolicyId
            }
        }
    }
    catch {
        $organization.CollectionWarnings += ('Get-OrganizationConfig failed: ' + $_.Exception.Message)
    }

    try {
        $acceptedDomainResults = @(Invoke-EDCAExchangeEndpointCommand -Server $Server -ScriptBlock {
                Get-AcceptedDomain -ErrorAction Stop | Select-Object -Property DomainName, Name
            })

        $domainSet = @{}
        foreach ($acceptedDomain in $acceptedDomainResults) {
            $domainValue = ''
            if ($acceptedDomain.PSObject.Properties.Name -contains 'DomainName' -and $null -ne $acceptedDomain.DomainName) {
                $domainValue = [string]$acceptedDomain.DomainName
            }
            elseif ($acceptedDomain.PSObject.Properties.Name -contains 'Name') {
                $domainValue = [string]$acceptedDomain.Name
            }

            if ([string]::IsNullOrWhiteSpace($domainValue)) {
                continue
            }

            $normalizedDomain = $domainValue.Trim().TrimEnd('.').ToLowerInvariant()
            if ([string]::IsNullOrWhiteSpace($normalizedDomain)) {
                continue
            }

            if (-not $domainSet.ContainsKey($normalizedDomain)) {
                $domainSet[$normalizedDomain] = $true
                $organization.AcceptedDomains += $normalizedDomain
            }
        }
    }
    catch {
        $organization.CollectionWarnings += ('Get-AcceptedDomain failed: ' + $_.Exception.Message)
    }

    try {
        $sb = [scriptblock]::Create('Get-AuthenticationPolicy -ErrorAction Stop | Select-Object -Property Name, AllowBasicAuthActiveSync, AllowBasicAuthAutodiscover, AllowBasicAuthImap, AllowBasicAuthMapi, AllowBasicAuthOfflineAddressBook, AllowBasicAuthOutlookService, AllowBasicAuthPop, AllowBasicAuthReportingWebServices, AllowBasicAuthRest, AllowBasicAuthRpc, AllowBasicAuthSmtp, AllowBasicAuthWebServices, AllowBasicAuthWindowsLiveId')
        $allAuthPolicies = @(Invoke-EDCAExchangeEndpointCommand -Server $Server -ScriptBlock $sb)

        $targetPolicy = $null
        if (-not [string]::IsNullOrWhiteSpace($organization.DefaultAuthPolicyName)) {
            $targetPolicy = $allAuthPolicies | Where-Object { [string]$_.Name -eq $organization.DefaultAuthPolicyName } | Select-Object -First 1
        }
        if ($null -eq $targetPolicy -and $allAuthPolicies.Count -gt 0) {
            $targetPolicy = $allAuthPolicies[0]
        }

        if ($null -ne $targetPolicy) {
            $basicAuthPropNames = @('AllowBasicAuthActiveSync', 'AllowBasicAuthAutodiscover', 'AllowBasicAuthImap', 'AllowBasicAuthMapi', 'AllowBasicAuthOfflineAddressBook', 'AllowBasicAuthOutlookService', 'AllowBasicAuthPop', 'AllowBasicAuthReportingWebServices', 'AllowBasicAuthRest', 'AllowBasicAuthRpc', 'AllowBasicAuthSmtp', 'AllowBasicAuthWebServices', 'AllowBasicAuthWindowsLiveId')
            $basicAuthProps = [ordered]@{}
            foreach ($prop in $basicAuthPropNames) {
                if ($targetPolicy.PSObject.Properties.Name -contains $prop) {
                    $basicAuthProps[$prop] = [bool]$targetPolicy.$prop
                }
            }
            if ($basicAuthProps.Keys.Count -gt 0) {
                $organization.DefaultAuthPolicyBasicAuth = [pscustomobject]$basicAuthProps
            }
        }
    }
    catch {
        $organization.CollectionWarnings += ('Get-AuthenticationPolicy failed: ' + $_.Exception.Message)
    }

    try {
        $sb = [scriptblock]::Create('Get-Mailbox -ResultSize Unlimited')
        $orgMailboxes = @(Invoke-EDCAExchangeEndpointCommand -Server $Server -ScriptBlock $sb)
        $mismatchedUpn = @($orgMailboxes | Where-Object {
                $_.RecipientTypeDetails -eq 'UserMailbox' -and
                -not [string]::IsNullOrWhiteSpace([string]$_.UserPrincipalName) -and
                -not [string]::IsNullOrWhiteSpace([string]$_.WindowsEmailAddress) -and
                -not [string]::Equals([string]$_.UserPrincipalName, [string]$_.WindowsEmailAddress, [System.StringComparison]::OrdinalIgnoreCase)
            })
        $organization.UpnPrimarySmtpMismatchCount = $mismatchedUpn.Count
    }
    catch {
        $organization.CollectionWarnings += ('Get-Mailbox (UPN/SMTP check) failed: ' + $_.Exception.Message)
    }

    try {
        $rootDseFL = [System.DirectoryServices.DirectoryEntry]::new('GC://RootDSE')
        $forestFL = $rootDseFL.Properties['forestFunctionality']
        $domainFL = $rootDseFL.Properties['domainFunctionality']
        if ($null -ne $forestFL -and $forestFL.Count -gt 0) {
            $organization.ForestFunctionalLevel = [int]([string]$forestFL[0])
        }
        if ($null -ne $domainFL -and $domainFL.Count -gt 0) {
            $organization.DomainFunctionalLevel = [int]([string]$domainFL[0])
        }
    }
    catch {
        $organization.CollectionWarnings += ('AD functional level collection via RootDSE failed: ' + $_.Exception.Message)
    }

    try {
        $domainName = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name
        $rootDseSites = [System.DirectoryServices.DirectoryEntry]::new(('GC://{0}/RootDSE' -f $domainName))
        $configDN = [string]$rootDseSites.Properties['configurationNamingContext'][0]
        $sitesContainerDN = ('CN=Sites,' + $configDN)
        $sitesRoot = [System.DirectoryServices.DirectoryEntry]::new(('GC://{0}' -f $sitesContainerDN))
        $siteSearcher = [System.DirectoryServices.DirectorySearcher]::new($sitesRoot, '(objectCategory=site)')
        $siteSearcher.PageSize = 100
        $organization.AdSiteCount = ($siteSearcher.FindAll()).Count
    }
    catch {
        $organization.CollectionWarnings += ('AD site count collection failed: ' + $_.Exception.Message)
    }

    try {
        # Use a simple pipeline-only scriptblock (no language constructs) so the call succeeds
        # even when the Exchange PowerShell endpoint restricts the runspace to no-language mode.
        # Byte conversions and object construction are performed locally after the remote call.
        $tcRaw = Invoke-EDCAExchangeEndpointCommand -Server $Server -ScriptBlock {
            Get-TransportConfig -ErrorAction Stop | Select-Object -Property MaxSendSize, MaxReceiveSize, MaxRecipientEnvelopeLimit
        }
        if ($null -ne $tcRaw) {
            $sndDisplay = if ($null -ne $tcRaw.MaxSendSize) { [string]$tcRaw.MaxSendSize } else { $null }
            $rcvDisplay = if ($null -ne $tcRaw.MaxReceiveSize) { [string]$tcRaw.MaxReceiveSize } else { $null }
            $sndBytes = $null
            $rcvBytes = $null
            # Exchange ByteQuantifiedSize serialises as e.g. "25 MB (26,214,400 bytes)" - parse byte count from string.
            if (-not [string]::IsNullOrEmpty($sndDisplay) -and $sndDisplay -match '\(([0-9,]+)\s+bytes?\)') {
                $null = [long]::TryParse(($Matches[1] -replace ',', ''), [ref]$sndBytes)
            }
            if (-not [string]::IsNullOrEmpty($rcvDisplay) -and $rcvDisplay -match '\(([0-9,]+)\s+bytes?\)') {
                $null = [long]::TryParse(($Matches[1] -replace ',', ''), [ref]$rcvBytes)
            }
            # Exchange Unlimited[int] serialises as "500" or "Unlimited".
            $mreLimit = if ($null -ne $tcRaw.MaxRecipientEnvelopeLimit) { [string]$tcRaw.MaxRecipientEnvelopeLimit } else { $null }
            $organization.TransportConfig = [pscustomobject]@{
                MaxSendSizeBytes          = $sndBytes
                MaxReceiveSizeBytes       = $rcvBytes
                MaxSendSizeDisplay        = $sndDisplay
                MaxReceiveSizeDisplay     = $rcvDisplay
                MaxRecipientEnvelopeLimit = $mreLimit
            }
            if (-not [string]::IsNullOrEmpty($mreLimit)) {
                $organization.MaxRecipientEnvelopeLimit = $mreLimit
            }
        }
    }
    catch {
        $organization.CollectionWarnings += ('Get-TransportConfig failed: ' + $_.Exception.Message)
    }

    try {
        $rdResults = @(Invoke-EDCAExchangeEndpointCommand -Server $Server -ScriptBlock {
                Get-RemoteDomain -ErrorAction Stop | Select-Object Name, DomainName, AutoForwardEnabled, AutoReplyEnabled, NDREnabled, AllowedOOFType, IsInternal
            })
        foreach ($rd in $rdResults) {
            $organization.RemoteDomains += [pscustomobject]@{
                Name               = [string]$rd.Name
                DomainName         = if ($rd.PSObject.Properties.Name -contains 'DomainName') { [string]$rd.DomainName } else { [string]$rd.Name }
                AutoForwardEnabled = if ($rd.PSObject.Properties.Name -contains 'AutoForwardEnabled') { [bool]$rd.AutoForwardEnabled } else { $null }
                AutoReplyEnabled   = if ($rd.PSObject.Properties.Name -contains 'AutoReplyEnabled') { [bool]$rd.AutoReplyEnabled } else { $null }
                NDREnabled         = if ($rd.PSObject.Properties.Name -contains 'NDREnabled') { [bool]$rd.NDREnabled } else { $null }
                AllowedOOFType     = if ($rd.PSObject.Properties.Name -contains 'AllowedOOFType') { [string]$rd.AllowedOOFType } else { $null }
                IsInternal         = if ($rd.PSObject.Properties.Name -contains 'IsInternal') { [bool]$rd.IsInternal } else { $false }
            }
        }
    }
    catch {
        $organization.CollectionWarnings += ('Get-RemoteDomain failed: ' + $_.Exception.Message)
    }

    try {
        $allExSvrsEdge = @(Invoke-EDCAExchangeEndpointCommand -Server $Server -ScriptBlock {
                Get-ExchangeServer -ErrorAction Stop | Select-Object Name, ServerRole, AdminDisplayVersion, Edition
            })
        $edgeResults = @($allExSvrsEdge | Where-Object { [string]$_.ServerRole -like '*Edge*' })
        foreach ($es in $edgeResults) {
            $organization.EdgeServers += [pscustomobject]@{
                Name                = [string]$es.Name
                AdminDisplayVersion = if ($es.PSObject.Properties.Name -contains 'AdminDisplayVersion') { [string]$es.AdminDisplayVersion } else { $null }
                Edition             = if ($es.PSObject.Properties.Name -contains 'Edition') { [string]$es.Edition } else { $null }
            }
        }
    }
    catch {
        $organization.CollectionWarnings += ('Get-ExchangeServer (Edge detection) failed: ' + $_.Exception.Message)
    }

    try {
        $authConfigResult = Invoke-EDCAExchangeEndpointCommand -Server $Server -ScriptBlock {
            Get-AuthConfig -ErrorAction Stop | Select-Object -First 1 -Property CurrentCertificateThumbprint
        }
        $authThumbprint = $null
        if ($null -ne $authConfigResult -and $authConfigResult.PSObject.Properties.Name -contains 'CurrentCertificateThumbprint') {
            $authThumbprint = [string]$authConfigResult.CurrentCertificateThumbprint
        }
        if (-not [string]::IsNullOrWhiteSpace($authThumbprint)) {
            $authThumbprint = $authThumbprint.Trim().ToUpperInvariant()
            $authCertResult = Invoke-EDCAExchangeEndpointCommand -Server $Server -ScriptBlock ([scriptblock]::Create(
                    "Get-ExchangeCertificate -Thumbprint '$authThumbprint' -ErrorAction SilentlyContinue | Select-Object -First 1 -Property Thumbprint, NotAfter"
                ))
            if ($null -ne $authCertResult -and $authCertResult.PSObject.Properties.Name -contains 'NotAfter' -and $null -ne $authCertResult.NotAfter) {
                $notAfter = [datetime]$authCertResult.NotAfter
                $now = [datetime]::UtcNow
                $organization.AuthCertificate = [pscustomobject]@{
                    Thumbprint    = $authThumbprint
                    Found         = $true
                    NotAfter      = $notAfter
                    IsExpired     = ($notAfter -lt $now)
                    DaysRemaining = [int][math]::Floor(($notAfter - $now).TotalDays)
                }
            }
            else {
                $organization.AuthCertificate = [pscustomobject]@{
                    Thumbprint    = $authThumbprint
                    Found         = $false
                    NotAfter      = $null
                    IsExpired     = $null
                    DaysRemaining = $null
                }
            }
        }
        else {
            $organization.AuthCertificate = [pscustomobject]@{
                Thumbprint    = $null
                Found         = $false
                NotAfter      = $null
                IsExpired     = $null
                DaysRemaining = $null
            }
        }
    }
    catch {
        $organization.CollectionWarnings += ('Get-AuthConfig failed: ' + $_.Exception.Message)
    }

    $organization.Available = ($null -ne $organization.OAuth2ClientProfileEnabled) -or ($null -ne $organization.AdSplitPermissionEnabled) -or ($null -ne $organization.CustomerFeedbackEnabled) -or ($null -ne $organization.UpnPrimarySmtpMismatchCount) -or (@($organization.AcceptedDomains).Count -gt 0) -or ($null -ne $organization.DefaultAuthPolicyBasicAuth)

    try {
        $sbMdm = [scriptblock]::Create('Get-MobileDeviceMailboxPolicy -ErrorAction Stop')
        $mdmPolicies = @(Invoke-EDCAExchangeEndpointCommand -Server $Server -ScriptBlock $sbMdm)
        foreach ($mdmPolicy in $mdmPolicies) {
            $organization.MobileDevicePolicies += [pscustomobject]@{
                Name                         = [string]$mdmPolicy.Name
                IsDefault                    = if ($mdmPolicy.PSObject.Properties.Name -contains 'IsDefault') { [bool]$mdmPolicy.IsDefault } else { $null }
                AllowSimplePassword          = if ($mdmPolicy.PSObject.Properties.Name -contains 'AllowSimplePassword') { [bool]$mdmPolicy.AllowSimplePassword } else { $null }
                AllowNonProvisionableDevices = if ($mdmPolicy.PSObject.Properties.Name -contains 'AllowNonProvisionableDevices') { [bool]$mdmPolicy.AllowNonProvisionableDevices } else { $null }
                PasswordHistory              = if ($mdmPolicy.PSObject.Properties.Name -contains 'PasswordHistory') { $mdmPolicy.PasswordHistory } else { $null }
                MinPasswordLength            = if ($mdmPolicy.PSObject.Properties.Name -contains 'MinPasswordLength') { $mdmPolicy.MinPasswordLength } else { $null }
                MaxPasswordFailedAttempts    = if ($mdmPolicy.PSObject.Properties.Name -contains 'MaxPasswordFailedAttempts') { [string]$mdmPolicy.MaxPasswordFailedAttempts } else { $null }
                PasswordExpiration           = if ($mdmPolicy.PSObject.Properties.Name -contains 'PasswordExpiration') { [string]$mdmPolicy.PasswordExpiration } else { $null }
                DevicePolicyRefreshInterval  = if ($mdmPolicy.PSObject.Properties.Name -contains 'DevicePolicyRefreshInterval') { [string]$mdmPolicy.DevicePolicyRefreshInterval } else { $null }
                AlphanumericPasswordRequired = if ($mdmPolicy.PSObject.Properties.Name -contains 'AlphanumericPasswordRequired') { [bool]$mdmPolicy.AlphanumericPasswordRequired } else { $null }
                RequireDeviceEncryption      = if ($mdmPolicy.PSObject.Properties.Name -contains 'RequireDeviceEncryption') { [bool]$mdmPolicy.RequireDeviceEncryption } else { $null }
                PasswordEnabled              = if ($mdmPolicy.PSObject.Properties.Name -contains 'PasswordEnabled') { [bool]$mdmPolicy.PasswordEnabled } else { $null }
                MaxInactivityTimeLock        = if ($mdmPolicy.PSObject.Properties.Name -contains 'MaxInactivityTimeLock') { [string]$mdmPolicy.MaxInactivityTimeLock } else { $null }
            }
        }
    }
    catch {
        $organization.CollectionWarnings += ('Get-MobileDeviceMailboxPolicy failed: ' + $_.Exception.Message)
    }

    try {
        $irmResult = Invoke-EDCAExchangeEndpointCommand -Server $Server -ScriptBlock {
            Get-IRMConfiguration -ErrorAction Stop | Select-Object -First 1 -Property InternalLicensingEnabled, ExternalLicensingEnabled, AzureRMSLicensingEnabled
        }
        if ($null -ne $irmResult) {
            $internalEnabled = $null
            $externalEnabled = $null
            $azureEnabled = $null
            if ($irmResult.PSObject.Properties.Name -contains 'InternalLicensingEnabled' -and $null -ne $irmResult.InternalLicensingEnabled) {
                $internalEnabled = [bool]$irmResult.InternalLicensingEnabled
            }
            if ($irmResult.PSObject.Properties.Name -contains 'ExternalLicensingEnabled' -and $null -ne $irmResult.ExternalLicensingEnabled) {
                $externalEnabled = [bool]$irmResult.ExternalLicensingEnabled
            }
            if ($irmResult.PSObject.Properties.Name -contains 'AzureRMSLicensingEnabled' -and $null -ne $irmResult.AzureRMSLicensingEnabled) {
                $azureEnabled = [bool]$irmResult.AzureRMSLicensingEnabled
            }
            $organization.IrmConfiguration = [pscustomobject]@{
                InternalLicensingEnabled = $internalEnabled
                ExternalLicensingEnabled = $externalEnabled
                AzureRMSLicensingEnabled = $azureEnabled
            }
        }
    }
    catch {
        $organization.CollectionWarnings += ('Get-IRMConfiguration failed: ' + $_.Exception.Message)
    }

    try {
        # Enumerate all non-Edge Exchange servers with their AD site names via a local
        # DirectorySearcher query against the AD Configuration partition.  msExchExchangeServer
        # objects carry an msExchServerSite attribute (DN of the AD site) so no Exchange PS
        # endpoint call is needed - and the Exchange remote runspace runs in no-language mode
        # which rejects complex scriptblock syntax such as [PSCustomObject]@{}.
        Write-EDCALog -Message 'Collecting Domain Controller system information.'
        $allExSvrs = [System.Collections.Generic.List[object]]::new()
        try {
            $rootDse = [System.DirectoryServices.DirectoryEntry]::new('GC://RootDSE')
            $configDN = [string]$rootDse.Properties['configurationNamingContext'][0]
            $searcher = [System.DirectoryServices.DirectorySearcher]::new()
            $searcher.SearchRoot = [System.DirectoryServices.DirectoryEntry]::new(('GC://{0}' -f $configDN))
            $searcher.Filter = '(&(objectClass=msExchExchangeServer)(msExchServerSite=*))'
            $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $null = $searcher.PropertiesToLoad.Add('name')
            $null = $searcher.PropertiesToLoad.Add('msExchServerSite')
            $null = $searcher.PropertiesToLoad.Add('msExchCurrentServerRoles')
            foreach ($result in @($searcher.FindAll())) {
                # Skip Edge Transport servers (role bit 64)
                $roles = if ($result.Properties['msExchCurrentServerRoles'].Count -gt 0) { [int]$result.Properties['msExchCurrentServerRoles'][0] } else { 0 }
                if ($roles -band 64) { continue }
                $serverName = if ($result.Properties['name'].Count -gt 0) { [string]$result.Properties['name'][0] } else { $null }
                $siteDn = if ($result.Properties['msExchServerSite'].Count -gt 0) { [string]$result.Properties['msExchServerSite'][0] } else { '' }
                $siteName = if ($siteDn -match 'CN=([^,]+)') { $Matches[1] } else { 'Unknown' }
                if (-not [string]::IsNullOrWhiteSpace($serverName)) {
                    $allExSvrs.Add([pscustomobject]@{ Name = $serverName; SiteName = $siteName })
                }
            }
        }
        catch {
            throw ('Exchange server AD enumeration failed: ' + $_.Exception.Message)
        }

        $siteMap = @{}
        foreach ($exSvr in $allExSvrs) {
            $siteName = if (-not [string]::IsNullOrWhiteSpace([string]$exSvr.SiteName)) { [string]$exSvr.SiteName } else { 'Unknown' }
            if (-not $siteMap.ContainsKey($siteName)) { $siteMap[$siteName] = [System.Collections.Generic.List[string]]::new() }
            $siteMap[$siteName].Add([string]$exSvr.Name)
        }

        # Build a site→GC map using native .NET (no ActiveDirectory module required).
        # GlobalCatalog.SiteName and GlobalCatalog.Name provide site and hostname directly.
        $gcsBySite = @{}
        $gcEnumError = $null
        try {
            $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            foreach ($gc in @($forest.GlobalCatalogs)) {
                $gcSite = [string]$gc.SiteName
                if (-not $gcsBySite.ContainsKey($gcSite)) { $gcsBySite[$gcSite] = [System.Collections.Generic.List[object]]::new() }
                $gcsBySite[$gcSite].Add([pscustomobject]@{ Name = [string]$gc.Name })
            }
        }
        catch {
            $gcEnumError = $_.Exception.Message
        }

        $dcRatioResults = [System.Collections.Generic.List[object]]::new()

        foreach ($siteEntry in ($siteMap.GetEnumerator() | Sort-Object Key)) {
            $siteName = $siteEntry.Key

            # Query Exchange server core counts using CIM
            $exCoresTotal = 0
            $exDetails = [System.Collections.Generic.List[object]]::new()
            foreach ($exName in $siteEntry.Value) {
                $exCores = $null
                $exErr = $null
                try { $exCores = [int](@(Get-CimInstance -ClassName Win32_Processor -ComputerName $exName -ErrorAction Stop) | Measure-Object -Property NumberOfCores -Sum).Sum }
                catch { $exErr = $_.Exception.Message }
                if ($null -ne $exCores) { $exCoresTotal += $exCores }
                $exDetails.Add([pscustomobject]@{ Name = $exName; Cores = if ($null -ne $exCores) { $exCores } else { 0 }; Error = $exErr })
            }

            # Find all GCs in this AD site using the pre-built site map
            $gcList = @()
            $dcAccessError = if ($null -ne $gcEnumError) { $gcEnumError } else { $null }
            if ($null -eq $gcEnumError) {
                if ($gcsBySite.ContainsKey($siteName)) {
                    $gcList = @($gcsBySite[$siteName])
                }
                # else: gcsBySite built successfully but no GC in this site - $dcAccessError stays $null
            }

            # Query DC/GC core counts using CIM
            $dcCoresTotal = 0
            $dcDetails = [System.Collections.Generic.List[object]]::new()
            foreach ($gc in $gcList) {
                $dcCores = $null
                $dcErr = $null
                try { $dcCores = [int](@(Get-CimInstance -ClassName Win32_Processor -ComputerName $gc.Name -ErrorAction Stop) | Measure-Object -Property NumberOfCores -Sum).Sum }
                catch { $dcErr = $_.Exception.Message }
                if ($null -ne $dcCores) {
                    $dcCoresTotal += $dcCores
                }
                else {
                    if ($null -eq $dcAccessError) { $dcAccessError = $dcErr }
                }
                $dcDetails.Add([pscustomobject]@{ Name = $gc.Name; Cores = if ($null -ne $dcCores) { $dcCores } else { 0 }; Error = $dcErr })
            }

            $dcRatioValue = if ($null -eq $dcAccessError -and $dcCoresTotal -gt 0) { [math]::Round([double]$exCoresTotal / [double]$dcCoresTotal, 2) } else { $null }

            $dcRatioResults.Add([pscustomobject]@{
                    Available         = $true
                    AdSite            = $siteName
                    ExchangeCores     = $exCoresTotal
                    DcCores           = $dcCoresTotal
                    Ratio             = $dcRatioValue
                    ExchangeServers   = $exDetails.ToArray()
                    DomainControllers = $dcDetails.ToArray()
                    DcAccessError     = $dcAccessError
                })
        }

        $organization.DcCoreRatio = $dcRatioResults.ToArray()
    }
    catch {
        $organization.CollectionWarnings += ('DC/GC core ratio collection failed: ' + $_.Exception.Message)
        $organization.DcCoreRatio = @([pscustomobject]@{
                Available     = $false
                AdSite        = $null
                ExchangeCores = 0
                DcCores       = 0
                Ratio         = $null
                DcAccessError = $_.Exception.Message
            })
    }

    # Collect domain object DACL state for EDCA-IAC-028 (Exchange-AD-Privesc WriteDACL ACE check).
    # Uses pure .NET ADSI - no ActiveDirectory PowerShell module required.
    try {
        $adDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $domainDN = $adDomain.GetDirectoryEntry().distinguishedName
        $domainEntry = [System.DirectoryServices.DirectoryEntry]"LDAP://$domainDN"
        $domainAcl = $domainEntry.get_objectSecurity()

        # GUIDs for inherited object types carrying the vulnerable WriteDACL ACEs
        $userObjTypeGuid = [Guid]'bf967aba-0de6-11d0-a285-00aa003049e2'  # User class
        $inetOrgPersonGuid = [Guid]'4828cc14-1437-45bc-9b07-ad6f015e5f28'  # inetOrgPerson class
        $groupObjTypeGuid = [Guid]'bf967a9c-0de6-11d0-a285-00aa003049e2'  # Group class (AdminSDHolder, Exchange 2016+)
        $writeDaclRight = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
        $inheritOnlyFlag = [System.Security.AccessControl.PropagationFlags]::InheritOnly

        # Resolve EWP SID - translate to SecurityIdentifier for reliable matching regardless of domain name
        $ewpSid = $null
        try {
            $ewpSid = (New-Object System.Security.Principal.NTAccount 'Exchange Windows Permissions').Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {
            # Group may not exist (e.g. split permissions or Exchange not installed in this domain)
        }

        # Resolve Exchange Trusted Subsystem SID for AdminSDHolder check (Exchange 2016+ only)
        $etsSid = $null
        try {
            $etsSid = (New-Object System.Security.Principal.NTAccount 'Exchange Trusted Subsystem').Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
        catch {}

        $domainRules = @($domainAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))

        $ewpUserAceInheritOnly = $null
        $ewpInetOrgPersonAceInheritOnly = $null

        if ($null -ne $ewpSid) {
            foreach ($guid in @($userObjTypeGuid, $inetOrgPersonGuid)) {
                $matchingAce = $domainRules | Where-Object {
                    $_.IdentityReference.Value -eq $ewpSid -and
                    ($_.ActiveDirectoryRights -band $writeDaclRight) -and
                    $_.ObjectType -eq [Guid]::Empty -and
                    $_.InheritedObjectType -eq $guid -and
                    $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow
                } | Select-Object -First 1

                $hasInheritOnly = $null
                if ($null -ne $matchingAce) {
                    $hasInheritOnly = [bool]($matchingAce.PropagationFlags -band $inheritOnlyFlag)
                }
                if ($guid -eq $userObjTypeGuid) {
                    $ewpUserAceInheritOnly = $hasInheritOnly
                }
                else {
                    $ewpInetOrgPersonAceInheritOnly = $hasInheritOnly
                }
            }
        }

        # AdminSDHolder check: ETS WriteDACL Group ACE must be absent (Exchange 2016+)
        $etsGroupAceOnAdminSdHolderAbsent = $null
        if ($null -ne $etsSid) {
            try {
                $adminSdEntry = [System.DirectoryServices.DirectoryEntry]"LDAP://CN=AdminSDHolder,CN=System,$domainDN"
                $adminSdAcl = $adminSdEntry.get_objectSecurity()
                $adminSdRules = @($adminSdAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
                $etsGroupAce = $adminSdRules | Where-Object {
                    $_.IdentityReference.Value -eq $etsSid -and
                    ($_.ActiveDirectoryRights -band $writeDaclRight) -and
                    $_.ObjectType -eq $groupObjTypeGuid -and
                    $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow
                } | Select-Object -First 1
                $etsGroupAceOnAdminSdHolderAbsent = ($null -eq $etsGroupAce)
            }
            catch {
                # AdminSDHolder unreadable - leave $null
            }
        }

        $organization.DomainObjectDacl = [pscustomobject]@{
            EwpUserAceInheritOnly            = $ewpUserAceInheritOnly
            EwpInetOrgPersonAceInheritOnly   = $ewpInetOrgPersonAceInheritOnly
            EtsGroupAceOnAdminSdHolderAbsent = $etsGroupAceOnAdminSdHolderAbsent
            CollectionError                  = $null
        }
    }
    catch {
        $organization.DomainObjectDacl = [pscustomobject]@{
            EwpUserAceInheritOnly            = $null
            EwpInetOrgPersonAceInheritOnly   = $null
            EtsGroupAceOnAdminSdHolderAbsent = $null
            CollectionError                  = $_.Exception.Message
        }
        $organization.CollectionWarnings += ('DomainObjectDacl collection failed: ' + $_.Exception.Message)
    }

    # Collect Client Access Rules for EDCA-IAC-010 (ClientAccessRules sub-check)
    try {
        $carResults = @(Invoke-EDCAExchangeEndpointCommand -Server $Server -ScriptBlock {
                Get-ClientAccessRule -ErrorAction Stop | Select-Object Name, Action, AnyOfProtocols, AnyOfClientIPAddressesOrRanges, ExceptAnyOfClientIPAddressesOrRanges, Priority, Enabled
            })
        $organization.ClientAccessRules = @($carResults | ForEach-Object {
                [pscustomobject]@{
                    Name                                 = [string]$_.Name
                    Action                               = [string]$_.Action
                    AnyOfProtocols                       = @($_.AnyOfProtocols | ForEach-Object { [string]$_ })
                    AnyOfClientIPAddressesOrRanges       = @($_.AnyOfClientIPAddressesOrRanges | ForEach-Object { [string]$_ })
                    ExceptAnyOfClientIPAddressesOrRanges = @($_.ExceptAnyOfClientIPAddressesOrRanges | ForEach-Object { [string]$_ })
                    Priority                             = if ($null -ne $_.Priority) { [int]$_.Priority } else { 0 }
                    Enabled                              = if ($null -ne $_.Enabled) { [bool]$_.Enabled } else { $true }
                }
            })
    }
    catch {
        $organization.CollectionWarnings += ('Get-ClientAccessRule failed: ' + $_.Exception.Message)
    }

    # Collect non-Exchange-admin users with RemotePowerShellEnabled for EDCA-IAC-010 (PS sub-check)
    try {
        # Step 1: collect all Exchange role group names
        $roleGroupNames = @()
        try {
            $rgResults = @(Invoke-EDCAExchangeEndpointCommand -Server $Server -ScriptBlock {
                    Get-RoleGroup -ErrorAction Stop | Select-Object Name
                })
            $roleGroupNames = @($rgResults | ForEach-Object { [string]$_.Name } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }
        catch {
            $organization.CollectionWarnings += ('Get-RoleGroup failed: ' + $_.Exception.Message)
        }

        # Step 2: collect role group members to identify Exchange admins
        $exchangeAdminSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($rgName in $roleGroupNames) {
            try {
                $escapedName = $rgName -replace "'", "''"
                $sbMembers = [scriptblock]::Create("Get-RoleGroupMember -Identity '$escapedName' -ErrorAction SilentlyContinue | Select-Object SamAccountName, DistinguishedName")
                $members = @(Invoke-EDCAExchangeEndpointCommand -Server $Server -ScriptBlock $sbMembers)
                foreach ($m in $members) {
                    $sam = [string]$m.SamAccountName
                    $dn = [string]$m.DistinguishedName
                    if (-not [string]::IsNullOrWhiteSpace($sam)) { $null = $exchangeAdminSet.Add($sam) }
                    if (-not [string]::IsNullOrWhiteSpace($dn)) { $null = $exchangeAdminSet.Add($dn) }
                }
            }
            catch { }
        }

        # Step 3: collect users with RemotePowerShellEnabled = $true (capped at 500 for performance)
        $psEnabledUsers = @(Invoke-EDCAExchangeEndpointCommand -Server $Server -ScriptBlock {
                Get-User -Filter { RemotePowerShellEnabled -eq $true } -ResultSize 500 -ErrorAction Stop |
                Select-Object Name, SamAccountName, DistinguishedName, RecipientType, RecipientTypeDetails
            })

        # Step 4: cross-reference - retain only non-admin users
        $nonAdminPsUsers = [System.Collections.Generic.List[pscustomobject]]::new()
        foreach ($u in $psEnabledUsers) {
            $sam = [string]$u.SamAccountName
            $dn = [string]$u.DistinguishedName
            if (-not ($exchangeAdminSet.Contains($sam) -or $exchangeAdminSet.Contains($dn))) {
                $nonAdminPsUsers.Add([pscustomobject]@{
                        Name                 = [string]$u.Name
                        SamAccountName       = $sam
                        RecipientType        = [string]$u.RecipientType
                        RecipientTypeDetails = [string]$u.RecipientTypeDetails
                    })
            }
        }

        $organization.NonAdminRemotePowerShellUsers = @($nonAdminPsUsers | Select-Object -First 50)
        $organization.NonAdminRemotePowerShellCountTotal = $nonAdminPsUsers.Count
    }
    catch {
        $organization.CollectionWarnings += ('Non-admin RemotePowerShellEnabled collection failed: ' + $_.Exception.Message)
    }

    return $organization
}

function Invoke-EDCACollection {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()]
        [string[]]$Servers = @(),
        [ValidateRange(1, 128)]
        [int]$ThrottleLimit = 4,
        [string]$ToolVersion = 'v0.2 Preview'
    )

    $normalizedServers = @($Servers | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).Trim() } | Sort-Object -Unique)
    if ($normalizedServers.Count -gt 0) {
        Write-Verbose ('Input server list normalized to {0} target(s): {1}' -f $normalizedServers.Count, ($normalizedServers -join ', '))
    }

    if ($normalizedServers.Count -eq 0) {
        # Determine local Exchange role from registry before attempting AD discovery.
        # Exchange setup writes a role-specific subkey for each installed role:
        #   EdgeTransportRole  -> Edge Transport server (not domain-joined; AD lookup will always fail)
        #   MailboxRole        -> Mailbox server (domain-joined; AD discovery is appropriate)
        $localExchangeRole = $null
        if (Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\EdgeTransportRole') {
            $localExchangeRole = 'Edge'
        }
        elseif (Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\MailboxRole') {
            $localExchangeRole = 'Mailbox'
        }
        elseif (Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup') {
            # Setup key present but no recognised role subkey (rare; older or partial installs).
            # Fall back to service presence: MSExchangeADTopology is absent on Edge servers.
            $adTopologySvc = Get-Service -Name 'MSExchangeADTopology' -ErrorAction SilentlyContinue
            $localExchangeRole = if ($null -eq $adTopologySvc) { 'Edge' } else { 'Mailbox' }
        }

        if ($localExchangeRole -eq 'Edge') {
            # Edge Transport servers are never domain-joined; skip AD discovery entirely.
            Write-EDCALog -Message ('Exchange Edge Transport Server detected on this machine ({0}). AD discovery is not applicable for Edge servers; switching to local collection.' -f $env:COMPUTERNAME)
            $normalizedServers = @($env:COMPUTERNAME)
        }
        else {
            Write-EDCALog -Message 'No servers specified. Discovering all Exchange servers in the current environment.'
            try {
                $normalizedServers = Get-EDCAExchangeEnvironmentServers
                Write-EDCALog -Message ('Discovered Exchange servers: {0}' -f ($normalizedServers -join ', '))
            }
            catch {
                # AD is unreachable. If Exchange is installed on this machine fall back to local
                # collection automatically (covers Mailbox servers that lost AD connectivity, or
                # machines where the role registry key was absent but Exchange is still present).
                if ($null -ne $localExchangeRole -or (Test-Path -Path 'HKLM:\SOFTWARE\Microsoft\ExchangeServer\v15\Setup')) {
                    Write-EDCALog -Message ('Active Directory unreachable: {0}' -f $_.Exception.Message)
                    Write-EDCALog -Message ('Exchange detected on local machine ({0}). Falling back to local collection mode.' -f $env:COMPUTERNAME)
                    Write-Warning ('Active Directory is unreachable. Falling back to local collection mode - collecting from {0} only.' -f $env:COMPUTERNAME)
                    $normalizedServers = @($env:COMPUTERNAME)
                }
                else {
                    throw
                }
            }
        }
    }

    $results = Invoke-EDCAParallelServerCollection -Servers $normalizedServers -ThrottleLimit $ThrottleLimit

    $localExchangeServerCmdlet = Get-Command -Name Get-ExchangeServer -ErrorAction SilentlyContinue
    if ($null -eq $localExchangeServerCmdlet) {
        try {
            Add-PSSnapin -Name Microsoft.Exchange.Management.PowerShell.SnapIn -ErrorAction Stop
        }
        catch {
        }
        $localExchangeServerCmdlet = Get-Command -Name Get-ExchangeServer -ErrorAction SilentlyContinue
    }

    $organization = [pscustomobject]@{
        Available                  = $false
        SourceServer               = $null
        ExchangeCmdletsAvailable   = $false
        OAuth2ClientProfileEnabled = $null
        AdSplitPermissionEnabled   = $null
        AcceptedDomains            = @()
        ForestFunctionalLevel      = $null
        DomainFunctionalLevel      = $null
        AdSiteCount                = $null
        TransportConfig            = $null
        RemoteDomains              = @()
        EdgeServers                = @()
        IrmConfiguration           = $null
        CollectionWarnings         = @()
    }

    $organizationSourceServer = $null
    foreach ($result in $results) {
        if ($result.PSObject.Properties.Name -contains 'CollectionError') {
            continue
        }

        $isResultEdge = ($result.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $result.Exchange -and
        ($result.Exchange.PSObject.Properties.Name -contains 'IsEdge') -and [bool]$result.Exchange.IsEdge
        if ($isResultEdge) { continue }

        if (($result.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $result.Exchange -and ($result.Exchange.PSObject.Properties.Name -contains 'IsExchangeServer') -and [bool]$result.Exchange.IsExchangeServer) {
            $organizationSourceServer = [string]$result.Server
            break
        }
    }

    if ([string]::IsNullOrWhiteSpace($organizationSourceServer) -and $normalizedServers.Count -gt 0) {
        # Prefer the first server that is not known to be an Edge server.
        $nonEdgeFallback = $results | Where-Object {
            -not ($_.PSObject.Properties.Name -contains 'CollectionError') -and
            ($_.PSObject.Properties.Name -contains 'Exchange') -and $null -ne $_.Exchange -and
            -not (($_.Exchange.PSObject.Properties.Name -contains 'IsEdge') -and [bool]$_.Exchange.IsEdge)
        } | Select-Object -First 1
        $organizationSourceServer = if ($null -ne $nonEdgeFallback) { [string]$nonEdgeFallback.Server } else { [string]$normalizedServers[0] }
    }

    if (-not [string]::IsNullOrWhiteSpace($organizationSourceServer)) {
        try {
            $organization = Get-EDCAOrganizationInventory -Server $organizationSourceServer
        }
        catch {
            $organization.CollectionWarnings = @('Organization-level collection failed: ' + $_.Exception.Message)
        }
    }

    if ($null -ne $localExchangeServerCmdlet) {
        Write-Verbose 'Attempting local Exchange Management Shell fallback enrichment for incomplete server Exchange data.'

        if (($organization.PSObject.Properties.Name -contains 'Available') -and -not [bool]$organization.Available) {
            Write-Verbose 'Organization-level remote collection unavailable; attempting local Exchange Management Shell fallback for organization settings.'

            try {
                $orgFallbackWarnings = @()
                $orgFallbackAcceptedDomains = @()
                $orgFallbackOAuth2Enabled = $null
                $orgFallbackAdSplitPermissionEnabled = $null

                if (Get-Command -Name Get-OrganizationConfig -ErrorAction SilentlyContinue) {
                    try {
                        $orgConfig = Get-OrganizationConfig -ErrorAction Stop
                        if ($orgConfig.PSObject.Properties.Name -contains 'OAuth2ClientProfileEnabled') {
                            $orgFallbackOAuth2Enabled = [bool]$orgConfig.OAuth2ClientProfileEnabled
                        }
                        if ($orgConfig.PSObject.Properties.Name -contains 'AdSplitPermissionEnabled' -and $null -ne $orgConfig.AdSplitPermissionEnabled) {
                            $orgFallbackAdSplitPermissionEnabled = [bool]$orgConfig.AdSplitPermissionEnabled
                        }
                        elseif ($orgConfig.PSObject.Properties.Name -contains 'ADSplitPermissionEnabled' -and $null -ne $orgConfig.ADSplitPermissionEnabled) {
                            $orgFallbackAdSplitPermissionEnabled = [bool]$orgConfig.ADSplitPermissionEnabled
                        }
                    }
                    catch {
                        $orgFallbackWarnings += ('Local fallback Get-OrganizationConfig failed: ' + $_.Exception.Message)
                    }
                }

                if (Get-Command -Name Get-AcceptedDomain -ErrorAction SilentlyContinue) {
                    try {
                        foreach ($acceptedDomain in @(Get-AcceptedDomain -ErrorAction Stop)) {
                            $domainValue = ''
                            if ($acceptedDomain.PSObject.Properties.Name -contains 'DomainName' -and $null -ne $acceptedDomain.DomainName) {
                                $domainValue = [string]$acceptedDomain.DomainName
                            }
                            elseif ($acceptedDomain.PSObject.Properties.Name -contains 'Name') {
                                $domainValue = [string]$acceptedDomain.Name
                            }

                            if (-not [string]::IsNullOrWhiteSpace($domainValue)) {
                                $orgFallbackAcceptedDomains += $domainValue.Trim().TrimEnd('.').ToLowerInvariant()
                            }
                        }
                    }
                    catch {
                        $orgFallbackWarnings += ('Local fallback Get-AcceptedDomain failed: ' + $_.Exception.Message)
                    }
                }

                $orgFallbackIdentity = $null
                if (Get-Command -Name Get-OrganizationConfig -ErrorAction SilentlyContinue) {
                    try {
                        $orgIdentityResult = Get-OrganizationConfig -ErrorAction Stop
                        if ($orgIdentityResult.PSObject.Properties.Name -contains 'Identity' -and -not [string]::IsNullOrWhiteSpace([string]$orgIdentityResult.Identity)) {
                            $orgFallbackIdentity = [string]$orgIdentityResult.Identity
                        }
                    }
                    catch { }
                }

                $organization = [pscustomobject]@{
                    Available                  = ($null -ne $orgFallbackOAuth2Enabled -or $null -ne $orgFallbackAdSplitPermissionEnabled -or @($orgFallbackAcceptedDomains).Count -gt 0)
                    SourceServer               = $env:COMPUTERNAME
                    ExchangeCmdletsAvailable   = $true
                    OrganizationIdentity       = $orgFallbackIdentity
                    OAuth2ClientProfileEnabled = $orgFallbackOAuth2Enabled
                    AdSplitPermissionEnabled   = $orgFallbackAdSplitPermissionEnabled
                    AcceptedDomains            = @($orgFallbackAcceptedDomains | Sort-Object -Unique)
                    ForestFunctionalLevel      = $null
                    DomainFunctionalLevel      = $null
                    AdSiteCount                = $null
                    CollectionWarnings         = $orgFallbackWarnings
                }
            }
            catch {
                $organization.CollectionWarnings = @('Organization-level local fallback failed: ' + $_.Exception.Message)
            }
        }

        foreach ($result in $results) {
            if ($result.PSObject.Properties.Name -contains 'CollectionError') {
                continue
            }

            if (-not ($result.PSObject.Properties.Name -contains 'Exchange') -or $null -eq $result.Exchange) {
                continue
            }

            $exchangeInfo = $result.Exchange
            $serverName = [string]$result.Server
            $warnings = @()
            if ($exchangeInfo.PSObject.Properties.Name -contains 'CollectionWarnings' -and $null -ne $exchangeInfo.CollectionWarnings) {
                $warnings = @($exchangeInfo.CollectionWarnings)
            }

            $needsServerIdentityData = [string]::IsNullOrWhiteSpace([string]$exchangeInfo.AdminDisplayVersion) -or [string]::IsNullOrWhiteSpace([string]$exchangeInfo.Edition) -or [string]::IsNullOrWhiteSpace([string]$exchangeInfo.ProductLine) -or ([string]$exchangeInfo.ProductLine -eq 'Unknown')
            if ($needsServerIdentityData) {
                try {
                    $exchangeServer = Get-ExchangeServer -Identity $serverName -ErrorAction Stop
                    $exchangeInfo.ExchangeCmdletsAvailable = $true
                    $exchangeInfo.IsExchangeServer = $true

                    if ($exchangeServer.PSObject.Properties.Name -contains 'Name') {
                        $exchangeInfo.Name = [string]$exchangeServer.Name
                    }
                    if ($exchangeServer.PSObject.Properties.Name -contains 'AdminDisplayVersion' -and $null -ne $exchangeServer.AdminDisplayVersion) {
                        $exchangeInfo.AdminDisplayVersion = [string]$exchangeServer.AdminDisplayVersion
                    }
                    if ($exchangeServer.PSObject.Properties.Name -contains 'Edition') {
                        $exchangeInfo.Edition = [string]$exchangeServer.Edition
                    }

                    $versionText = [string]$exchangeInfo.AdminDisplayVersion
                    if ($versionText -match 'Version 15\.1') {
                        $exchangeInfo.ProductLine = 'Exchange2016'
                    }
                    elseif ($versionText -match 'Version 15\.2') {
                        $isSe = $false
                        if ($exchangeServer.PSObject.Properties.Name -contains 'IsExchangeServerSubscriptionEdition') {
                            $isSe = [bool]$exchangeServer.IsExchangeServerSubscriptionEdition
                        }
                        if (-not $isSe -and $versionText -match 'Subscription|SE') {
                            $isSe = $true
                        }
                        if (-not $isSe -and $versionText -match 'Build\s+(\d+)\.') {
                            if ([int]$matches[1] -ge 2562) {
                                $isSe = $true
                            }
                        }
                        $exchangeInfo.ProductLine = if ($isSe) { 'ExchangeSE' } else { 'Exchange2019' }
                    }
                }
                catch {
                    $warnings += ('Local fallback Get-ExchangeServer failed for {0}: {1}' -f $serverName, $_.Exception.Message)
                }
            }

            if (($exchangeInfo.PSObject.Properties.Name -contains 'CollectionWarnings') -and $warnings.Count -gt 0) {
                $exchangeInfo.CollectionWarnings = @($warnings | Select-Object -Unique)
            }
        }
    }
    else {
        Write-Verbose 'Local Exchange Management Shell cmdlets are unavailable; skipping local fallback enrichment.'
    }

    $acceptedDomains = @()
    if (($organization.PSObject.Properties.Name -contains 'AcceptedDomains') -and $null -ne $organization.AcceptedDomains) {
        foreach ($acceptedDomain in @($organization.AcceptedDomains)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$acceptedDomain)) {
                $acceptedDomains += ([string]$acceptedDomain).Trim().TrimEnd('.').ToLowerInvariant()
            }
        }
    }

    $acceptedDomains = @($acceptedDomains | Sort-Object -Unique)
    $eligibleAcceptedDomains = @($acceptedDomains | Where-Object {
            $domainCandidate = [string]$_
            $domainCandidate -ne 'onmicrosoft.com' -and -not $domainCandidate.EndsWith('.onmicrosoft.com')
        })
    $skippedAcceptedDomains = @($acceptedDomains | Where-Object {
            $domainCandidate = [string]$_
            $domainCandidate -eq 'onmicrosoft.com' -or $domainCandidate.EndsWith('.onmicrosoft.com')
        })

    Write-Verbose ('Collected {0} unique accepted domain(s) for email-auth checks.' -f $acceptedDomains.Count)
    if ($skippedAcceptedDomains.Count -gt 0) {
        Write-Verbose ('Excluding {0} onmicrosoft.com domain(s) before email-auth checks: {1}' -f $skippedAcceptedDomains.Count, ($skippedAcceptedDomains -join ', '))
    }

    $emailAuthentication = Invoke-EDCAEmailAuthenticationChecks -AcceptedDomains $eligibleAcceptedDomains
    Write-Verbose 'Email authentication checks completed.'

    return [pscustomobject]@{
        Metadata            = [pscustomobject]@{
            ToolName            = 'EDCA'
            ToolVersion         = $ToolVersion
            CollectionTimestamp = (Get-Date -Format 'o')
            ExecutedBy          = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        }
        Servers             = $results
        Organization        = $organization
        EmailAuthentication = $emailAuthentication
    }
}

