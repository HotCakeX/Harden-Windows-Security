Function Protect-WindowsSecurity {
    Invoke-RestMethod 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security.ps1' -OutFile .\Harden-Windows-Security.ps1
    .\Harden-Windows-Security.ps1

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