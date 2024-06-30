<# -------- Guidance for code readers --------
The module uses tight import/export control, no internal function is exposed on the console/to the user.
The $PSDefaultParameterValues located in "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1" is imported via dot-sourcing to the current session of each main cmdlet/internal function that calls any (other) internal function or uses any of the cmdlets defined in that file, prior to everything else.
At the beginning of each main cmdlet, 2 custom $Verbose and/or $Debug variables are defined which help to take actions based on Verbose/Debug preferences and also pass the $VerbosePreference and $DebugPreference to the subsequent sub-functions/modules being called from the main cmdlets.

E.g.,

this captures the $Debug preference from the command line:
[System.Boolean]$Debug = $PSBoundParameters.Debug.IsPresent ? $true : $false

Then in the PSDefaultParameterValues.ps1 file, there is 'Do-Something:Debug' = $Debug

So that essentially means any instance of 'Do-Something' cmdlet in the code is actually 'Do-Something -Debug:$Debug'
#>

# Stopping the module process if any error occurs
$global:ErrorActionPreference = 'Stop'

# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadLineKeyHandler -Key 'Tab' -Function 'MenuComplete'

# Enables additional progress indicators for Windows Terminal and Windows
$PSStyle.Progress.UseOSCIndicator = $true

# Import the public global module
Import-Module -FullyQualifiedName "$([WDACConfig.GlobalVars]::ModuleRootPath)\Public\Write-FinalOutput.psm1" -Force -Global
Import-Module -FullyQualifiedName "$([WDACConfig.GlobalVars]::ModuleRootPath)\Public\MockConfigCIBootstrap.psm1" -Force -Global

# Import the classes
Import-Module -FullyQualifiedName "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\Classes.psm1" -Force
