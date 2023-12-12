Function New-SnapBackGuarantee {
    <#
    .SYNOPSIS
        A function that arms the system with a snapback guarantee in case of a reboot during the base policy enforcement process.
        This will help prevent the system from being stuck in audit mode in case of a power outage or a reboot during the base policy enforcement process.
    .PARAMETER Location
        The directory location of the base policy file that will be enforced.
    .INPUTS
        System.IO.DirectoryInfo
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $true)]
        [System.IO.DirectoryInfo]$Location
    )

    # Using CMD and Scheduled Task Method

    # Creating the scheduled task action
    [Microsoft.Management.Infrastructure.CimInstance]$TaskAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c C:\EnforcedModeSnapBack.cmd'
    # Creating the scheduled task trigger
    [Microsoft.Management.Infrastructure.CimInstance]$TaskTrigger = New-ScheduledTaskTrigger -AtLogOn
    # Creating the scheduled task principal, will run the task under the system account using its well-known SID
    [Microsoft.Management.Infrastructure.CimInstance]$Principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -RunLevel Highest
    # Setting the task to run with the highest priority
    [Microsoft.Management.Infrastructure.CimInstance]$TaskSettings = New-ScheduledTaskSettingsSet -Hidden -Compatibility Win8 -DontStopIfGoingOnBatteries -Priority 0 -AllowStartIfOnBatteries
    # Register the scheduled task
    Register-ScheduledTask -TaskName 'EnforcedModeSnapBack' -Action $TaskAction -Trigger $TaskTrigger -Principal $Principal -Settings $TaskSettings -Force | Out-Null

    # Saving the EnforcedModeSnapBack.cmd file to the root of C drive
    # It contains the instructions to revert the base policy to enforced mode
    Set-Content -Force 'C:\EnforcedModeSnapBack.cmd' -Value @"
REM Deploying the Enforced Mode SnapBack CI Policy
CiTool --update-policy "$Location\EnforcedMode.cip" -json
REM Deleting the Scheduled task responsible for running this CMD file
schtasks /Delete /TN EnforcedModeSnapBack /F
REM Deleting the CI Policy file
del /f /q "$Location\EnforcedMode.cip"
REM Deleting this CMD file itself
del "%~f0"
"@

}

# Export external facing functions only, prevent internal functions from getting exported
Export-ModuleMember -Function 'New-SnapBackGuarantee'

# An alternative way to do this which is less reliable because RunOnce key can be deleted by 3rd party programs during installation etc.
<#
                # Using PowerShell and RunOnce Method

                # Defining the registry path for RunOnce key
                [System.String]$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
                # Defining the command that will be executed by the RunOnce key in case of a reboot
                [System.String]$Command = @"
CiTool --update-policy "$((Get-Location).Path)\EnforcedMode.cip" -json; Remove-Item -Path "$((Get-Location).Path)\EnforcedMode.cip" -Force
"@
                # Saving the command to a file that will be executed by the RunOnce key in case of a reboot
                $Command | Out-File -FilePath 'C:\EnforcedModeSnapBack.ps1' -Force
                # Saving the command that runs the EnforcedModeSnapBack.ps1 file in the next reboot to the RunOnce key
                New-ItemProperty -Path $RegistryPath -Name '*CIPolicySnapBack' -Value "powershell.exe -WindowStyle `"Hidden`" -ExecutionPolicy `"Bypass`" -Command `"& {&`"C:\EnforcedModeSnapBack.ps1`";Remove-Item -Path 'C:\EnforcedModeSnapBack.ps1' -Force}`"" -PropertyType String -Force | Out-Null
#>  

# If the alternative way is used, this should be added to the Finally block under the:
# Enforced Mode Snapback removal after base policy has already been successfully re-enforced

<#
# For PowerShell Method
# Remove-Item -Path 'C:\EnforcedModeSnapBack.ps1' -Force
# Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -Name '*CIPolicySnapBack' -Force
#>