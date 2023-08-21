# Stop operation as soon as there is an error anywhere, unless explicitly specified otherwise
$ErrorActionPreference = 'Stop'
Function Protect-WindowsSecurity {

    # Hiding Invoke-WebRequest progress because it creates lingering visual effect on PowerShell console for some reason
    # https://github.com/PowerShell/PowerShell/issues/14348

    # https://stackoverflow.com/questions/18770723/hide-progress-of-Invoke-WebRequest
    # Create an in-memory module so $ScriptBlock doesn't run in new scope
    $null = New-Module {
        function Invoke-WithoutProgress {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory)][scriptblock]$ScriptBlock
            )
            # Save current progress preference and hide the progress
            $prevProgressPreference = $global:ProgressPreference
            $global:ProgressPreference = 'SilentlyContinue'
            try {
                # Run the script block in the scope of the caller of this module function
                . $ScriptBlock
            }
            finally {
                # Restore the original behavior
                $global:ProgressPreference = $prevProgressPreference
            }
        }
    }

    try {
        Invoke-WithoutProgress {
            Invoke-RestMethod 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security.ps1' -OutFile .\Harden-Windows-Security.ps1
        }  
    }
    catch {
        Write-Error -Message "Couldn't download the required files, please check your Internet connection." -ErrorAction Stop             
    }

    try {    
        .\Harden-Windows-Security.ps1
    }

    finally {            
        Remove-Item -Path .\Harden-Windows-Security.ps1 -Force    
    }

    <#
.SYNOPSIS
Downloads and runs the Harden Windows Security PowerShell script from the official repository

.LINK
https://github.com/HotCakeX/Harden-Windows-Security

.DESCRIPTION
Downloads and runs the Harden Windows Security PowerShell script from the official repository

.COMPONENT
PowerShell

.FUNCTIONALITY
Downloads and runs the Harden Windows Security PowerShell script from the official repository

#> 
}
