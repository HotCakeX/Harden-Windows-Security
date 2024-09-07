#nullable enable

namespace HardenWindowsSecurity
{
    public partial class MicrosoftDefender
    {
        public static void MSFTDefender_ScheduledTask()
        {
            HardenWindowsSecurity.Logger.LogMessage("Creating scheduled task for fast weekly Microsoft recommended driver block list update", LogTypeIntel.Information);

            HardenWindowsSecurity.PowerShellExecutor.ExecuteScript("""
Write-Verbose -Message 'Deleting the MSFT Driver Block list update Scheduled task if it exists'
Get-ScheduledTask -TaskName 'MSFT Driver Block list update' -TaskPath '\MSFT Driver Block list update\' -ErrorAction Ignore | Unregister-ScheduledTask -Confirm:$false

Write-Verbose -Message "Creating the MSFT Driver Block list update task"
[System.Security.Principal.SecurityIdentifier]$SYSTEMSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)

[System.String]$TaskArgument = @'
-NoProfile -WindowStyle Hidden -command "& {try {Invoke-WebRequest -Uri 'https://aka.ms/VulnerableDriverBlockList' -OutFile 'VulnerableDriverBlockList.zip' -ErrorAction Stop}catch{exit 1};Expand-Archive -Path '.\VulnerableDriverBlockList.zip' -DestinationPath 'VulnerableDriverBlockList' -Force;$SiPolicy_EnforcedFile = Get-ChildItem -Recurse -File -Path '.\VulnerableDriverBlockList' -Filter 'SiPolicy_Enforced.p7b' | Select-Object -First 1;Move-Item -Path $SiPolicy_EnforcedFile.FullName -Destination ($env:SystemDrive + '\Windows\System32\CodeIntegrity\SiPolicy.p7b') -Force;citool --refresh -json;Remove-Item -Path '.\VulnerableDriverBlockList' -Recurse -Force;Remove-Item -Path '.\VulnerableDriverBlockList.zip' -Force;}"
'@
# Create a scheduled task action, this defines how to download and install the latest Microsoft Recommended Driver Block Rules
[Microsoft.Management.Infrastructure.CimInstance]$Action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument $TaskArgument

# Create a scheduled task principal and assign the SYSTEM account's SID to it so that the task will run under its context
[Microsoft.Management.Infrastructure.CimInstance]$TaskPrincipal = New-ScheduledTaskPrincipal -LogonType S4U -UserId $($SYSTEMSID.Value) -RunLevel Highest

# Create a trigger for the scheduled task. The task will first run one hour after its creation and from then on will run every 7 days, indefinitely
[Microsoft.Management.Infrastructure.CimInstance]$Time = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1) -RepetitionInterval (New-TimeSpan -Days 7)

# Register the scheduled task. If the task's state is disabled, it will be overwritten with a new task that is enabled
Register-ScheduledTask -Action $Action -Trigger $Time -Principal $TaskPrincipal -TaskPath 'MSFT Driver Block list update' -TaskName 'MSFT Driver Block list update' -Description 'Microsoft Recommended Driver Block List update' -Force

# Define advanced settings for the scheduled task
[Microsoft.Management.Infrastructure.CimInstance]$TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility 'Win8' -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -RestartCount 4 -RestartInterval (New-TimeSpan -Hours 6) -RunOnlyIfNetworkAvailable

# Add the advanced settings we defined above to the scheduled task
Set-ScheduledTask -TaskName 'MSFT Driver Block list update' -TaskPath 'MSFT Driver Block list update' -Settings $TaskSettings
""");
        }
    }
}
