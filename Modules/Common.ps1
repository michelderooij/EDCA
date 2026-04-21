# Script:  Common.ps1
# Synopsis: Part of EDCA (Exchange Deployment & Compliance Assessment)
#           https://github.com/michelderooij/EDCA
# Author:  Michel de Rooij
# Website: https://eightwone.com

Set-StrictMode -Version Latest

function Resolve-EDCAPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$BasePath
    )

    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }

    return [System.IO.Path]::GetFullPath((Join-Path -Path $BasePath -ChildPath $Path))
}

function New-EDCADirectoryIfMissing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -Path $Path)) {
        $null = New-Item -Path $Path -ItemType Directory -Force
    }
}

function Write-EDCALog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host ('[{0}] [{1}] {2}' -f $timestamp, $Level, $Message)
}

function Invoke-EDCAServerCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [object[]]$ArgumentList = @()
    )

    $localAliases = @($env:COMPUTERNAME, $env:COMPUTERNAME.ToLowerInvariant(), 'localhost', '.')

    if ($localAliases -contains $Server -or $Server.Equals($env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Verbose ('Executing script block locally on {0}.' -f $env:COMPUTERNAME)
        return & $ScriptBlock @ArgumentList
    }

    Write-Verbose ('Executing script block remotely on {0} via WinRM.' -f $Server)
    return Invoke-Command -ComputerName $Server -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
}

function Test-EDCAServerRemoteConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    $localAliases = @($env:COMPUTERNAME, $env:COMPUTERNAME.ToLowerInvariant(), 'localhost', '.')
    if ($localAliases -contains $Server -or $Server.Equals($env:COMPUTERNAME, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Verbose ('Connectivity precheck for {0}: local target, remoting check skipped.' -f $Server)
        return [pscustomobject]@{
            Server                = $Server
            IsLocal               = $true
            TcpPort80Reachable    = $true
            CanConnect            = $true
            CanReadRemoteRegistry = $true
            Details               = 'Local execution target.'
        }
    }

    $details = @()
    $canConnect = $true
    $tcpPort80Reachable = $false
    $canReadRemoteRegistry = $false

    # Fast TCP port 80 reachability check — avoids waiting for WinRM timeouts when the
    # server is simply unreachable. A 2-second window is enough for LAN/WAN targets.
    try {
        Write-Verbose ('Connectivity precheck for {0}: TCP port 80 reachability check.' -f $Server)
        $tcpClient = [System.Net.Sockets.TcpClient]::new()
        try {
            $connectTask = $tcpClient.ConnectAsync($Server, 80)
            if (-not $connectTask.Wait(2000)) {
                $canConnect = $false
                $details += 'TCP port 80 reachability check timed out after 2 seconds.'
            }
            elseif ($connectTask.IsFaulted) {
                $canConnect = $false
                $innerMsg = if ($null -ne $connectTask.Exception -and $null -ne $connectTask.Exception.InnerException) {
                    $connectTask.Exception.InnerException.Message
                }
                else { [string]$connectTask.Exception }
                $details += ('TCP port 80 reachability check failed: {0}' -f $innerMsg)
            }
            else {
                $tcpPort80Reachable = $true
                $details += 'TCP port 80 reachability check passed.'
            }
        }
        finally {
            $tcpClient.Dispose()
        }
    }
    catch {
        $canConnect = $false
        $details += ('TCP port 80 reachability check error: {0}' -f $_.Exception.Message)
    }

    if ($canConnect) {
        try {
            Write-Verbose ('Connectivity precheck for {0}: probing WinRM endpoint.' -f $Server)
            Test-WSMan -ComputerName $Server -ErrorAction Stop | Out-Null
        }
        catch {
            $canConnect = $false
            $details += ('WinRM probe failed: {0}' -f $_.Exception.Message)
        }
    }

    if ($canConnect) {
        try {
            Write-Verbose ('Connectivity precheck for {0}: validating remote command and registry access.' -f $Server)
            $probe = Invoke-Command -ComputerName $Server -ScriptBlock {
                [pscustomobject]@{
                    ComputerName    = $env:COMPUTERNAME
                    CanReadRegistry = (Test-Path -Path 'HKLM:\SOFTWARE')
                }
            } -ErrorAction Stop

            $canReadRemoteRegistry = [bool]$probe.CanReadRegistry
            if (-not $canReadRemoteRegistry) {
                $details += 'Remote session succeeded, but registry access test failed.'
            }
            else {
                $details += ('Remote session established to {0} and registry probe succeeded.' -f [string]$probe.ComputerName)
            }
        }
        catch {
            $canConnect = $false
            $details += ('Remote command execution failed: {0}' -f $_.Exception.Message)
        }
    }

    return [pscustomobject]@{
        Server                = $Server
        IsLocal               = $false
        TcpPort80Reachable    = $tcpPort80Reachable
        CanConnect            = $canConnect
        CanReadRemoteRegistry = $canReadRemoteRegistry
        Details               = ($details -join ' ')
    }
}

function ConvertTo-EDCAJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject
    )

    return ($InputObject | ConvertTo-Json -Depth 12)
}

