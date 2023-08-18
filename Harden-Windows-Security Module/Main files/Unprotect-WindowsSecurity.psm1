# Stop operation as soon as there is an error anywhere, unless explicitly specified otherwise
$ErrorActionPreference = 'Stop'
Function Unprotect-WindowsSecurity {

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

    # Makes sure this cmdlet is invoked with Admin privileges
    if (![bool]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error -Message 'Unprotect-WindowsSecurity cmdlet requires Administrator privileges.' -ErrorAction Stop
    }
    
    try {
        Invoke-WithoutProgress {
            Invoke-RestMethod 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/Resources/Unprotect-WindowsSecurity.ps1' -OutFile .\Unprotect-WindowsSecurity.ps1
        }  
    }
    catch {
        Write-Error -Message "Couldn't download the required files, please check your Internet connection." -ErrorAction Stop            
    }

    try {    
        .\Unprotect-WindowsSecurity.ps1
    }
    # Will delete the script after it's done when Exit is selected or CTRL + C is pressed
    finally {
        Remove-Item -Path .\Unprotect-WindowsSecurity.ps1 -Force   
    }

    <#
.SYNOPSIS
Downloads and runs the Unprotect-WindowsSecurity PowerShell script from the official repository

.LINK
https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden%E2%80%90Windows%E2%80%90Security%E2%80%90Module

.DESCRIPTION
Downloads and runs the Unprotect-WindowsSecurity PowerShell script from the official repository

.COMPONENT
PowerShell

.FUNCTIONALITY
Removes the protections and changes applied by the Harden Windows Security script

#> 
}
