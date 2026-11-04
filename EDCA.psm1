#
# EDCA — Exchange Deployment & Compliance Assessment
# Root module file: loads all submodules and exports the public cmdlet.
#

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Store the module root so submodule functions can locate asset folders
# (Controls/, Config/) without relying on $PSScriptRoot inside dot-sourced files.
$script:EDCAModuleRoot = $PSScriptRoot

. (Join-Path -Path $PSScriptRoot -ChildPath 'Modules\Common.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Modules\Collection.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Modules\Analysis.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Modules\Reporting.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Modules\Remediation.ps1')
. (Join-Path -Path $PSScriptRoot -ChildPath 'Modules\Invoke-EDCA.ps1')

Export-ModuleMember -Function 'Invoke-EDCA'
