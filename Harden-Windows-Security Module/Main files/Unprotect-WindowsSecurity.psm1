Function Unprotect-WindowsSecurity {

    # Makes sure this cmdlet is invoked with Admin privileges
    if (![bool]([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error -Message 'Unprotect-WindowsSecurity cmdlet requires Administrator privileges.' -ErrorAction Stop
    }
    
    Invoke-RestMethod 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/Resources/Unprotect-WindowsSecurity.ps1' -OutFile .\Unprotect-WindowsSecurity.ps1
    try {    
        .\Unprotect-WindowsSecurity.ps1
    }
    catch {
        Write-Error -Message "Couldn't download the required files, please check your Internet connection."
        [bool]$DontDelete = $true
    }
    finally {
        # Will delete the script after it's done when Exit is selected or CTRL + C is pressed
        if (!$DontDelete) { Remove-Item -Path .\Unprotect-WindowsSecurity.ps1 -Force }
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
