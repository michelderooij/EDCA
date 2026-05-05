<#
.SYNOPSIS
    EDCA — Exchange Deployment & Compliance Assessment.
    This script is the wrapper for the EDCA module, which performs collection and reporting tasks. 
    It accepts parameters to control which phases to run, target servers, paths for controls, data, and output, and other options.

    Version: 1.0.0.0
    Author:  Michel de Rooij
    Source:  https://github.com/michelderooij/EDCA
    Website: https://eightwone.com

.DESCRIPTION
    EDCA (Exchange Deployment & Compliance Assessment) collects configuration data from Exchange 2016,
    Exchange 2019, and Exchange SE servers, evaluates each server against a library of best-practice
    and security controls, and produces a detailed HTML report with pass/fail findings, severity
    ratings, and remediation guidance.

    Use -Collect to run the collection phase only, -Report to run the report phase only, or both
    switches together to run collection and reporting in a single run. When neither switch is
    specified, both phases run by default (equivalent to specifying -Collect -Report).

.PARAMETER Collect
    Runs the collection phase only. Connects to the target Exchange servers, gathers configuration
    telemetry, and writes per-server and organization JSON files to the Data folder (-DataPath).
    Cannot be combined with -Report; -Servers and -ThrottleLimit are not available in -Report mode.

.PARAMETER Report
    Runs the report phase only. Reads all *.json files from the Data folder (-DataPath), runs the
    analysis engine against the controls library, and generates an HTML report. Cannot be combined
    with -Collect; -Servers and -ThrottleLimit are not available in this mode. When neither -Collect
    nor -Report is specified, both phases run sequentially (equivalent to specifying both switches).

.PARAMETER Servers
    List of Exchange server names to target during the collection phase.

.PARAMETER ThrottleLimit
    Maximum number of parallel collection jobs (default: 4; range 1–128).

.PARAMETER ControlsPath
    Path to the directory containing control files (default: .\Controls).

.PARAMETER OutputPath
    Directory for analysis JSON and remediation script output files (default: .\Output).

.PARAMETER DataPath
    Directory for JSON data files (default: .\Data). During collection, per-server and
    organization JSON files are written here. During reporting, all *.json files in this
    directory are read as input for analysis.

.PARAMETER RemediationScript
    When specified, generates a PowerShell remediation script file in the Output folder alongside
    the HTML report. Without -Collect, this switch behaves like -Report: it reads all *.json
    collection files from the Data folder (-DataPath) as its input data source; no live collection
    is performed. The generated script is a starting-point template containing sample code derived
    from each failed control's scriptTemplate — review and adapt it for your environment before
    running it in production.

.PARAMETER Framework
    One or more framework names to include in the analysis. When specified, only controls tagged
    with at least one of the supplied frameworks are evaluated. Valid values are:
    Best Practice, ANSSI, BSI, CIS, CISA, DISA, ISM, NIS2.
    When omitted, all controls are evaluated regardless of framework.

.PARAMETER Update
    When specified, downloads the latest exchange.builds.json from GitHub and saves it to
    the Config directory, then continues with the requested operation.

.EXAMPLE
    .\EDCA.ps1 -Update

.EXAMPLE
    .\EDCA.ps1 -Servers EX01,EX02

.EXAMPLE
    .\EDCA.ps1 -Collect -Servers EX01,EX02

.EXAMPLE
    .\EDCA.ps1 -Report

.EXAMPLE
    .\EDCA.ps1 -Report -DataPath .\CustomData

.EXAMPLE
    .\EDCA.ps1 -Servers EX01,EX02 -Framework NIS2

.EXAMPLE
    .\EDCA.ps1 -Report -Framework 'Best Practice'
#>
#requires -version 5.1
[CmdletBinding(DefaultParameterSetName = 'Default')]
param(
    [Parameter(ParameterSetName = 'Collect', Mandatory = $true)]
    [switch]$Collect,

    [Parameter(ParameterSetName = 'Report', Mandatory = $true)]
    [switch]$Report,

    [Parameter(ParameterSetName = 'Default')]
    [Parameter(ParameterSetName = 'Collect')]
    [string[]]$Servers = @(),

    [Parameter(ParameterSetName = 'Default')]
    [Parameter(ParameterSetName = 'Collect')]
    [switch]$Local,

    [Parameter(ParameterSetName = 'Default')]
    [Parameter(ParameterSetName = 'Collect')]
    [ValidateRange(1, 128)]
    [int]$ThrottleLimit = 4,

    [string]$ControlsPath = '',

    [Parameter(ParameterSetName = 'Default')]
    [Parameter(ParameterSetName = 'Report')]
    [string]$OutputPath = '.\Output',

    [string]$DataPath = '.\Data',

    [Parameter(ParameterSetName = 'Default')]
    [Parameter(ParameterSetName = 'Report')]
    [switch]$RemediationScript,

    [switch]$Update,

    [ValidateSet('Best Practice', 'ANSSI', 'BSI', 'CIS', 'CISA', 'DISA', 'ISM', 'NIS2')]
    [string[]]$Framework
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module -Name (Join-Path -Path $PSScriptRoot -ChildPath 'EDCA.psd1') -Force
Invoke-EDCA @PSBoundParameters
Remove-Module -Name EDCA -Force
