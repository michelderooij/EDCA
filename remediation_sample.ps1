========================================================================
EDCA - Generated Remediation Script [SAMPLE TEMPLATE]
Derived from failed control evaluations in your environmnet, but not
fully validated. Intended as starting point for remediation actions,
not fully automated fix: adapt, review, and test before production runs.
Provided as-is without warranty or support. Use at your own risk.
========================================================================

#requires -version 5.1
param([switch]$WhatIfMode)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Host "Exchange SE remediation script" -ForegroundColor Cyan
Write-Host "Run in an approved change window. Current user context is used." -ForegroundColor Yellow

function Invoke-EDCA-DATA-001 {
    Write-Host "[EDCA-DATA-001] No expired Exchange certificates" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Replace expired certificates and assign them to Exchange services." -ForegroundColor Yellow
}

function Invoke-EDCA-DATA-007 {
    Write-Host "[EDCA-DATA-007] TLS 1.3 is disabled for Exchange compatibility" -ForegroundColor Cyan
    if ($WhatIfMode) {
        Write-Host "[WhatIf] New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Name Enabled -Type DWord -Value 0; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Name DisabledByDefault -Type DWord -Value 1" -ForegroundColor Yellow
        return
    }
    New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Name Enabled -Type DWord -Value 0; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Name DisabledByDefault -Type DWord -Value 1
}

function Invoke-EDCA-GOV-002 {
    Write-Host "[EDCA-GOV-002] Exchange product line lifecycle status" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Ensure Exchange Server SE is running the latest approved update. If running Exchange 2016 or 2019, plan migration to Exchange Server SE first." -ForegroundColor Yellow
}

function Invoke-EDCA-GOV-012 {
    Write-Host "[EDCA-GOV-012] Exchange services are documented and unnecessary services are disabled" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Enumerate all running services on Exchange servers and document required services. Disable any non-essential services. POP3 and IMAP4 are disabled by default in Exchange and should remain disabled unless explicitly required. If not in use, set both the back-end and front-end service instances to Disabled and stop any running instances." -ForegroundColor Yellow
}

function Invoke-EDCA-IAC-010 {
    Write-Host "[EDCA-IAC-010] Administrative access to EAC and remote PowerShell is restricted" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Create Client Access Rules to restrict EAC and remote PowerShell access to authorized source IP ranges, and disable RemotePowerShellEnabled for all users who are not Exchange administrators." -ForegroundColor Yellow
}

function Invoke-EDCA-MON-007 {
    Write-Host "[EDCA-MON-007] Receive connector protocol logging is set to Verbose" -ForegroundColor Cyan
    if ($WhatIfMode) {
        Write-Host "[WhatIf] # Enable verbose protocol logging on all receive connectors of this server.
Get-ReceiveConnector -Server $env:COMPUTERNAME | Set-ReceiveConnector -ProtocolLoggingLevel Verbose" -ForegroundColor Yellow
        return
    }
    # Enable verbose protocol logging on all receive connectors of this server.
Get-ReceiveConnector -Server $env:COMPUTERNAME | Set-ReceiveConnector -ProtocolLoggingLevel Verbose
}

function Invoke-EDCA-MON-008 {
    Write-Host "[EDCA-MON-008] Send connector protocol logging is set to Verbose" -ForegroundColor Cyan
    if ($WhatIfMode) {
        Write-Host "[WhatIf] # Enable verbose protocol logging on all send connectors.
Get-SendConnector | Set-SendConnector -ProtocolLoggingLevel Verbose" -ForegroundColor Yellow
        return
    }
    # Enable verbose protocol logging on all send connectors.
Get-SendConnector | Set-SendConnector -ProtocolLoggingLevel Verbose
}

function Invoke-EDCA-MON-011 {
    Write-Host "[EDCA-MON-011] Exchange audit data resides on a separate partition" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Move Exchange audit log paths to a dedicated volume separate from the OS and Exchange application volumes." -ForegroundColor Yellow
}

function Invoke-EDCA-MON-014 {
    Write-Host "[EDCA-MON-014] PowerShell Module Logging is enabled" -ForegroundColor Cyan
    if ($WhatIfMode) {
        Write-Host "[WhatIf] # Check current Module Logging state
$modLogPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
$val = (Get-ItemProperty $modLogPath -Name EnableModuleLogging -ErrorAction SilentlyContinue).EnableModuleLogging
'EnableModuleLogging: $(if ($null -eq $val) { 'not set (disabled)' } else { $val })'

# Enable Module Logging and log all modules
New-Item -Path $modLogPath -Force | Out-Null
Set-ItemProperty -Path $modLogPath -Name EnableModuleLogging -Type DWord -Value 1

$modNamesPath = '$modLogPath\ModuleNames'
New-Item -Path $modNamesPath -Force | Out-Null
Set-ItemProperty -Path $modNamesPath -Name '*' -Type String -Value '*'

Write-Host 'PowerShell Module Logging enabled for all modules.'" -ForegroundColor Yellow
        return
    }
    # Check current Module Logging state
$modLogPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
$val = (Get-ItemProperty $modLogPath -Name EnableModuleLogging -ErrorAction SilentlyContinue).EnableModuleLogging
"EnableModuleLogging: $(if ($null -eq $val) { 'not set (disabled)' } else { $val })"

# Enable Module Logging and log all modules
New-Item -Path $modLogPath -Force | Out-Null
Set-ItemProperty -Path $modLogPath -Name EnableModuleLogging -Type DWord -Value 1

$modNamesPath = "$modLogPath\ModuleNames"
New-Item -Path $modNamesPath -Force | Out-Null
Set-ItemProperty -Path $modNamesPath -Name '*' -Type String -Value '*'

Write-Host 'PowerShell Module Logging enabled for all modules.'
}

function Invoke-EDCA-PERF-003 {
    Write-Host "[EDCA-PERF-003] Hyper-Threading/SMT not enabled" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Review BIOS/host settings for SMT/Hyper-Threading and disable per performance policy where approved." -ForegroundColor Yellow
}

function Invoke-EDCA-PERF-013 {
    Write-Host "[EDCA-PERF-013] Page file initial and maximum size match Exchange version baseline" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Set the page file to a fixed size equal to the Exchange version target. For Exchange 2016: if total RAM is 32 GB or more, set Initial and Maximum to 32778 MB; otherwise set both to RAM in MB + 10. For Exchange 2019 / Exchange SE: set both to 25% of total RAM rounded up to the nearest MB. After changing the page file size a reboot is required for the new values to take effect." -ForegroundColor Yellow
}

function Invoke-EDCA-PERF-014 {
    Write-Host "[EDCA-PERF-014] Memory meets Exchange version and role requirements" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Add physical or virtual memory until the server meets the minimum for its Exchange version and role. For virtual machines, ensure the hypervisor memory reservation equals the full vRAM allocation and that dynamic memory / memory ballooning is disabled. Use the Exchange Server role requirements calculator (https://aka.ms/Exchange2019Calc) to size Mailbox servers based on actual mailbox count, message profile, and availability requirements before provisioning." -ForegroundColor Yellow
}

function Invoke-EDCA-RES-006 {
    Write-Host "[EDCA-RES-006] Mailbox database is not permanently deleted until it has been backed up" -ForegroundColor Cyan
    if ($WhatIfMode) {
        Write-Host "[WhatIf] # Ensure mailbox database items are not permanently deleted before backup.
# To target a specific database: replace 'DatabaseName' with the actual database name.
Set-MailboxDatabase -Identity 'DatabaseName' -RetainDeletedItemsUntilBackup $true" -ForegroundColor Yellow
        return
    }
    # Ensure mailbox database items are not permanently deleted before backup.
# To target a specific database: replace 'DatabaseName' with the actual database name.
Set-MailboxDatabase -Identity 'DatabaseName' -RetainDeletedItemsUntilBackup $true
}

function Invoke-EDCA-RES-008 {
    Write-Host "[EDCA-RES-008] Exchange mailbox databases reside on a dedicated partition" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Move mailbox database files to a dedicated volume separate from OS, Exchange binaries, and transaction logs." -ForegroundColor Yellow
}

function Invoke-EDCA-RES-010 {
    Write-Host "[EDCA-RES-010] Exchange mailbox databases are in a highly available and redundant configuration" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Configure a Database Availability Group with at least two mailbox database copies across different servers." -ForegroundColor Yellow
}

function Invoke-EDCA-SEC-008 {
    Write-Host "[EDCA-SEC-008] Exchange database/log volume block size is 64KB" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Use 64KB allocation unit size on volumes that host Exchange database/log paths." -ForegroundColor Yellow
}

function Invoke-EDCA-SEC-013 {
    Write-Host "[EDCA-SEC-013] Credential Guard disabled on Exchange servers" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Disable Credential Guard via Windows Defender Credential Guard Group Policy or by setting LsaCfgFlags to 0 under HKLM\SYSTEM\CurrentControlSet\Control\Lsa and EnableVirtualizationBasedSecurity to 0 under HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard. A reboot is required." -ForegroundColor Yellow
}

function Invoke-EDCA-SEC-014 {
    Write-Host "[EDCA-SEC-014] Extended Protection enabled on Exchange virtual directories" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Use the ExchangeExtendedProtectionManagement.ps1 script from the CSS-Exchange toolkit (https://microsoft.github.io/CSS-Exchange/Security/ExchangeExtendedProtectionManagement/) from an elevated Exchange Management Shell (EMS) with Organization Management permissions. Before enabling, disable SSL Offloading for Outlook Anywhere if applicable (Exchange 2019 CU14+ does this automatically). Use -ShowExtendedProtection to view current configuration, -PrerequisitesCheckOnly to validate prerequisites, or run without arguments to enable on all servers." -ForegroundColor Yellow
}

function Invoke-EDCA-SEC-018 {
    Write-Host "[EDCA-SEC-018] LLMNR disabled by policy" -ForegroundColor Cyan
    if ($WhatIfMode) {
        Write-Host "[WhatIf] # Group Policy equivalent:
# Computer Configuration > Administrative Templates > Network > DNS Client
#   Turn off Multicast Name Resolution = Enabled
#
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Type DWord -Value 0" -ForegroundColor Yellow
        return
    }
    # Group Policy equivalent:
# Computer Configuration > Administrative Templates > Network > DNS Client
#   Turn off Multicast Name Resolution = Enabled
#
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Force | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -Type DWord -Value 0
}

function Invoke-EDCA-SEC-020 {
    Write-Host "[EDCA-SEC-020] OWA Download Domains configured" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Configure OWA download domains according to Exchange security best practices. If Hybrid Modern Authentication is active, also apply the OWA HMA Download Domain Support setting override." -ForegroundColor Yellow
}

function Invoke-EDCA-SEC-033 {
    Write-Host "[EDCA-SEC-033] Transport pickup directory path is not configured" -ForegroundColor Cyan
    if ($WhatIfMode) {
        Write-Host "[WhatIf] # Clear the pickup directory path on the local transport service.
Set-TransportService -Identity $env:COMPUTERNAME -PickupDirectoryPath $null" -ForegroundColor Yellow
        return
    }
    # Clear the pickup directory path on the local transport service.
Set-TransportService -Identity $env:COMPUTERNAME -PickupDirectoryPath $null
}

function Invoke-EDCA-SEC-038 {
    Write-Host "[EDCA-SEC-038] Exchange has the most current approved update installed" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Install the latest approved Cumulative Update for the installed Exchange Server version." -ForegroundColor Yellow
}

function Invoke-EDCA-SEC-042 {
    Write-Host "[EDCA-SEC-042] NetBIOS over TCP/IP is disabled on all network interfaces" -ForegroundColor Cyan
    if ($WhatIfMode) {
        Write-Host "[WhatIf] # Group Policy equivalent:
# Computer Configuration > Preferences > Windows Settings > Registry
#   Key: HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{GUID}
#   Value: NetbiosOptions = 2 (DWORD) — Disabled
#
# Check current NetBIOS over TCP/IP setting per interface
$interfacesPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
Get-ChildItem $interfacesPath | ForEach-Object {
    $val = (Get-ItemProperty $_.PSPath -Name NetbiosOptions -ErrorAction SilentlyContinue).NetbiosOptions
    $status = switch ($val) { 0 { 'Default (use DHCP)' } 1 { 'Enabled' } 2 { 'Disabled' } default { 'Unknown ($val)' } }
    [PSCustomObject]@{ Interface = $_.PSChildName; NetbiosOptions = $val; Status = $status }
} | Format-Table -AutoSize

# Disable NetBIOS on all interfaces (set to 2 = disabled)
Get-ChildItem $interfacesPath | ForEach-Object {
    Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Type DWord -Value 2
    Write-Host 'Disabled NetBIOS on interface: $($_.PSChildName)'
}
Write-Host 'Done. Changes take effect immediately (no reboot required).'" -ForegroundColor Yellow
        return
    }
    # Group Policy equivalent:
# Computer Configuration > Preferences > Windows Settings > Registry
#   Key: HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{GUID}
#   Value: NetbiosOptions = 2 (DWORD) — Disabled
#
# Check current NetBIOS over TCP/IP setting per interface
$interfacesPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
Get-ChildItem $interfacesPath | ForEach-Object {
    $val = (Get-ItemProperty $_.PSPath -Name NetbiosOptions -ErrorAction SilentlyContinue).NetbiosOptions
    $status = switch ($val) { 0 { 'Default (use DHCP)' } 1 { 'Enabled' } 2 { 'Disabled' } default { "Unknown ($val)" } }
    [PSCustomObject]@{ Interface = $_.PSChildName; NetbiosOptions = $val; Status = $status }
} | Format-Table -AutoSize

# Disable NetBIOS on all interfaces (set to 2 = disabled)
Get-ChildItem $interfacesPath | ForEach-Object {
    Set-ItemProperty -Path $_.PSPath -Name NetbiosOptions -Type DWord -Value 2
    Write-Host "Disabled NetBIOS on interface: $($_.PSChildName)"
}
Write-Host 'Done. Changes take effect immediately (no reboot required).'
}

function Invoke-EDCA-SEC-043 {
    Write-Host "[EDCA-SEC-043] SMB packet signing is required on server and client" -ForegroundColor Cyan
    if ($WhatIfMode) {
        Write-Host "[WhatIf] # Group Policy equivalent:
# Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options
#   Microsoft network server: Digitally sign communications (always) = Enabled
#   Microsoft network client: Digitally sign communications (always) = Enabled
#
# Check SMB server signing (LanmanServer)
$serverPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$serverReq = (Get-ItemProperty $serverPath -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature
'SMB Server RequireSecuritySignature: $(if ($null -eq $serverReq) { 'not set (default: 0 - not required)' } else { $serverReq })'

# Check SMB client signing (LanmanWorkstation)
$clientPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
$clientReq = (Get-ItemProperty $clientPath -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature
'SMB Client RequireSecuritySignature: $(if ($null -eq $clientReq) { 'not set (default: 0 - not required)' } else { $clientReq })'

# Require SMB signing on server and client (1 = required)
Set-ItemProperty -Path $serverPath -Name RequireSecuritySignature -Type DWord -Value 1
Set-ItemProperty -Path $clientPath -Name RequireSecuritySignature -Type DWord -Value 1
Write-Host 'SMB signing required on server and client. No restart required; applies to new connections.'" -ForegroundColor Yellow
        return
    }
    # Group Policy equivalent:
# Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options
#   Microsoft network server: Digitally sign communications (always) = Enabled
#   Microsoft network client: Digitally sign communications (always) = Enabled
#
# Check SMB server signing (LanmanServer)
$serverPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$serverReq = (Get-ItemProperty $serverPath -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature
"SMB Server RequireSecuritySignature: $(if ($null -eq $serverReq) { 'not set (default: 0 - not required)' } else { $serverReq })"

# Check SMB client signing (LanmanWorkstation)
$clientPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
$clientReq = (Get-ItemProperty $clientPath -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature
"SMB Client RequireSecuritySignature: $(if ($null -eq $clientReq) { 'not set (default: 0 - not required)' } else { $clientReq })"

# Require SMB signing on server and client (1 = required)
Set-ItemProperty -Path $serverPath -Name RequireSecuritySignature -Type DWord -Value 1
Set-ItemProperty -Path $clientPath -Name RequireSecuritySignature -Type DWord -Value 1
Write-Host 'SMB signing required on server and client. No restart required; applies to new connections.'
}

function Invoke-EDCA-SEC-037 {
    Write-Host "[EDCA-SEC-037] LDAP client signing is set to require signing" -ForegroundColor Cyan
    if ($WhatIfMode) {
        Write-Host "[WhatIf] # Group Policy equivalent:
# Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options
#   Network security: LDAP client signing requirements = Require signing
#
# Check current LDAP client signing setting
$ldapPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP'
$val = (Get-ItemProperty $ldapPath -Name LdapClientIntegrity -ErrorAction SilentlyContinue).LdapClientIntegrity
$status = switch ($val) {
    0       { 'None - unsigned LDAP allowed (non-compliant)' }
    1       { 'Negotiate signing' }
    2       { 'Require signing (compliant)' }
    $null   { 'Not set - defaults to Negotiate (1)' }
    default { 'Unknown ($val)' }
}
'LdapClientIntegrity: $(if ($null -eq $val) { 'not set' } else { $val }) - $status'

# Set LDAP client to require signing (2)
Set-ItemProperty -Path $ldapPath -Name LdapClientIntegrity -Type DWord -Value 2
Write-Host 'LDAP client signing set to Require (2). No restart required.'" -ForegroundColor Yellow
        return
    }
    # Group Policy equivalent:
# Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options
#   Network security: LDAP client signing requirements = Require signing
#
# Check current LDAP client signing setting
$ldapPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LDAP'
$val = (Get-ItemProperty $ldapPath -Name LdapClientIntegrity -ErrorAction SilentlyContinue).LdapClientIntegrity
$status = switch ($val) {
    0       { 'None - unsigned LDAP allowed (non-compliant)' }
    1       { 'Negotiate signing' }
    2       { 'Require signing (compliant)' }
    $null   { 'Not set - defaults to Negotiate (1)' }
    default { "Unknown ($val)" }
}
"LdapClientIntegrity: $(if ($null -eq $val) { 'not set' } else { $val }) - $status"

# Set LDAP client to require signing (2)
Set-ItemProperty -Path $ldapPath -Name LdapClientIntegrity -Type DWord -Value 2
Write-Host 'LDAP client signing set to Require (2). No restart required.'
}

function Invoke-EDCA-TLS-012 {
    Write-Host "[EDCA-TLS-012] Send connector maximum message size is 25 MB or less" -ForegroundColor Cyan
    if ($WhatIfMode) {
        Write-Host "[WhatIf] # Set the send size limit on all send connectors.
Get-SendConnector | Set-SendConnector -MaxMessageSize 25MB" -ForegroundColor Yellow
        return
    }
    # Set the send size limit on all send connectors.
Get-SendConnector | Set-SendConnector -MaxMessageSize 25MB
}

function Invoke-EDCA-TLS-013 {
    Write-Host "[EDCA-TLS-013] Receive connector maximum message size is 25 MB or less" -ForegroundColor Cyan
    if ($WhatIfMode) {
        Write-Host "[WhatIf] # Set the receive size limit on all receive connectors on this server.
Get-ReceiveConnector -Server $env:COMPUTERNAME | Set-ReceiveConnector -MaxMessageSize 25MB" -ForegroundColor Yellow
        return
    }
    # Set the receive size limit on all receive connectors on this server.
Get-ReceiveConnector -Server $env:COMPUTERNAME | Set-ReceiveConnector -MaxMessageSize 25MB
}

function Invoke-EDCA-TLS-014 {
    Write-Host "[EDCA-TLS-014] External send connector has domain security enabled" -ForegroundColor Cyan
    if ($WhatIfMode) {
        Write-Host "[WhatIf] # Enable domain security on the internet send connector.
Get-SendConnector | Where-Object { $_.AddressSpaces -like '*' } |
    Set-SendConnector -DomainSecureEnabled $true" -ForegroundColor Yellow
        return
    }
    # Enable domain security on the internet send connector.
Get-SendConnector | Where-Object { $_.AddressSpaces -like '*' } |
    Set-SendConnector -DomainSecureEnabled $true
}

function Invoke-EDCA-TLS-017 {
    Write-Host "[EDCA-TLS-017] Exchange outbound connection limit per domain is controlled" -ForegroundColor Cyan
    if ($WhatIfMode) {
        Write-Host "[WhatIf] Set-TransportService -Identity $env:COMPUTERNAME -MaxPerDomainOutboundConnections 20" -ForegroundColor Yellow
        return
    }
    Set-TransportService -Identity $env:COMPUTERNAME -MaxPerDomainOutboundConnections 20
}

function Invoke-EDCA-TLS-020 {
    Write-Host "[EDCA-TLS-020] Exchange receive connector connection timeout is limited" -ForegroundColor Cyan
    if ($WhatIfMode) {
        Write-Host "[WhatIf] Get-ReceiveConnector | Set-ReceiveConnector -ConnectionTimeout 00:05:00" -ForegroundColor Yellow
        return
    }
    Get-ReceiveConnector | Set-ReceiveConnector -ConnectionTimeout 00:05:00
}

function Invoke-EDCA-TLS-021 {
    Write-Host "[EDCA-TLS-021] Exchange internal receive connectors require encryption" -ForegroundColor Cyan
    if ($WhatIfMode) {
        Write-Host "[WhatIf] # Verify TLS requirements on internal receive connectors
Get-ReceiveConnector | Where-Object { $_.TransportRole -ne 'FrontendTransport' } |
    Select-Object Name, RequireTLS, AuthMechanism

# Apply RequireTLS on internal connectors
# Get-ReceiveConnector | Where-Object { $_.Name -like '*Internal*' } | Set-ReceiveConnector -RequireTLS $true" -ForegroundColor Yellow
        return
    }
    # Verify TLS requirements on internal receive connectors
Get-ReceiveConnector | Where-Object { $_.TransportRole -ne 'FrontendTransport' } |
    Select-Object Name, RequireTLS, AuthMechanism

# Apply RequireTLS on internal connectors
# Get-ReceiveConnector | Where-Object { $_.Name -like '*Internal*' } | Set-ReceiveConnector -RequireTLS $true
}

function Invoke-EDCA-TLS-025 {
    Write-Host "[EDCA-TLS-025] Accepted domains publish valid MTA-STS policies" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Publish _mta-sts TXT with v=STSv1; id=... and host a valid policy at https://mta-sts.<domain>/.well-known/mta-sts.txt." -ForegroundColor Yellow
}

function Invoke-EDCA-TLS-034 {
    Write-Host "[EDCA-TLS-034] Edge outbound send connectors require TLS" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Set RequireTls = $true on all send connectors: Set-SendConnector -Identity <name> -RequireTls $true. Verify that receiving mail servers present a valid certificate before enabling, to avoid mail flow disruption." -ForegroundColor Yellow
}

function Invoke-EDCA-TLS-035 {
    Write-Host "[EDCA-TLS-035] Edge send connector protocol logging is Verbose" -ForegroundColor Cyan
    if ($WhatIfMode) {
        Write-Host "[WhatIf] Get-SendConnector | Where-Object { $_.ProtocolLoggingLevel -ne 'Verbose' } | Set-SendConnector -ProtocolLoggingLevel Verbose" -ForegroundColor Yellow
        return
    }
    Get-SendConnector | Where-Object { $_.ProtocolLoggingLevel -ne 'Verbose' } | Set-SendConnector -ProtocolLoggingLevel Verbose
}

function Invoke-EDCA-TLS-039 {
    Write-Host "[EDCA-TLS-039] Edge internal Receive connectors require TLS encryption" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Ensure AuthMechanism on internal Receive connectors includes Tls. Set-ReceiveConnector -Identity <name> -AuthMechanism Tls -RequireTLS $true." -ForegroundColor Yellow
}

function Invoke-EDCA-TLS-040 {
    Write-Host "[EDCA-TLS-040] Edge internal Receive connectors disallow anonymous connections" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Remove AnonymousUsers from the PermissionGroups on internal Receive connectors." -ForegroundColor Yellow
}

function Invoke-EDCA-TLS-042 {
    Write-Host "[EDCA-TLS-042] Edge internet-facing Send connectors route via a Smart Host" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Configure Send connectors to route via an approved Smart Host: Set-SendConnector -Identity <name> -SmartHosts <FQDN-or-IP> -SmartHostAuthMechanism None." -ForegroundColor Yellow
}

function Invoke-EDCA-TLS-043 {
    Write-Host "[EDCA-TLS-043] Edge internal Send connectors use mutual-TLS domain security" -ForegroundColor Cyan
    Write-Host "Manual remediation required: Set TlsAuthLevel to DomainValidation and DomainSecureEnabled to $true on internal Send connectors." -ForegroundColor Yellow
}

function Invoke-EDCA-TLS-044 {
    Write-Host "[EDCA-TLS-044] Edge Sender Filter blocks messages from unaccepted domains" -ForegroundColor Cyan
    if ($WhatIfMode) {
        Write-Host "[WhatIf] Get-SenderFilterConfig | Select-Object Enabled, BlankSenderBlockingEnabled, BlockedSendersAndDomains" -ForegroundColor Yellow
        return
    }
    Get-SenderFilterConfig | Select-Object Enabled, BlankSenderBlockingEnabled, BlockedSendersAndDomains
}

Write-Host "Applying remediation actions for failed checks..." -ForegroundColor Green
Invoke-EDCA-DATA-001
Invoke-EDCA-DATA-007
Invoke-EDCA-GOV-002
Invoke-EDCA-GOV-012
Invoke-EDCA-IAC-010
Invoke-EDCA-MON-007
Invoke-EDCA-MON-008
Invoke-EDCA-MON-011
Invoke-EDCA-MON-014
Invoke-EDCA-PERF-003
Invoke-EDCA-PERF-013
Invoke-EDCA-PERF-014
Invoke-EDCA-RES-006
Invoke-EDCA-RES-008
Invoke-EDCA-RES-010
Invoke-EDCA-SEC-008
Invoke-EDCA-SEC-013
Invoke-EDCA-SEC-014
Invoke-EDCA-SEC-018
Invoke-EDCA-SEC-020
Invoke-EDCA-SEC-033
Invoke-EDCA-SEC-038
Invoke-EDCA-SEC-042
Invoke-EDCA-SEC-043
Invoke-EDCA-SEC-037
Invoke-EDCA-TLS-012
Invoke-EDCA-TLS-013
Invoke-EDCA-TLS-014
Invoke-EDCA-TLS-017
Invoke-EDCA-TLS-020
Invoke-EDCA-TLS-021
Invoke-EDCA-TLS-025
Invoke-EDCA-TLS-034
Invoke-EDCA-TLS-035
Invoke-EDCA-TLS-039
Invoke-EDCA-TLS-040
Invoke-EDCA-TLS-042
Invoke-EDCA-TLS-043
Invoke-EDCA-TLS-044

