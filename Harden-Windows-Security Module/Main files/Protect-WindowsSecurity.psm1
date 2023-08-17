Function Protect-WindowsSecurity {
    
    Invoke-RestMethod 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security.ps1' -OutFile .\Harden-Windows-Security.ps1
    try {    
        .\Harden-Windows-Security.ps1
    }
    catch {
        Write-Error -Message "Couldn't download the required files, please check your Internet connection."
        [bool]$DontDelete = $true  
    }
    finally {
        # Will delete the script after it's done when Exit is selected or CTRL + C is pressed
        if (!$DontDelete) { Remove-Item -Path .\Harden-Windows-Security.ps1 -Force }
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
