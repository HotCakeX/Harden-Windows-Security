using System;
using System.Management;

#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class MicrosoftDefender
    {
        public static void MSFTDefender_ScheduledTask()
        {
            HardenWindowsSecurity.Logger.LogMessage("Creating scheduled task for fast weekly Microsoft recommended driver block list update", LogTypeIntel.Information);

            // Initialize ManagementScope to interact with Task Scheduler's WMI namespace
            var scope = new ManagementScope(@"root\Microsoft\Windows\TaskScheduler");
            // Establish connection to the WMI namespace
            scope.Connect();


            #region Action
            // Create a scheduled task action, this defines how to download and install the latest Microsoft Recommended Driver Block Rules
            using ManagementClass actionClass = new(scope, new ManagementPath("PS_ScheduledTask"), null);

            // Prepare method parameters for creating the task action
            ManagementBaseObject actionInParams = actionClass.GetMethodParameters("NewActionByExec");
            actionInParams["Execute"] = "PowerShell.exe";
            // The PowerShell command to run, downloading and deploying the drivers block list
            actionInParams["Argument"] = """
-NoProfile -WindowStyle Hidden -command "& {try {Invoke-WebRequest -Uri 'https://aka.ms/VulnerableDriverBlockList' -OutFile 'VulnerableDriverBlockList.zip' -ErrorAction Stop}catch{exit 1};Expand-Archive -Path '.\VulnerableDriverBlockList.zip' -DestinationPath 'VulnerableDriverBlockList' -Force;$SiPolicy_EnforcedFile = Get-ChildItem -Recurse -File -Path '.\VulnerableDriverBlockList' -Filter 'SiPolicy_Enforced.p7b' | Select-Object -First 1;Move-Item -Path $SiPolicy_EnforcedFile.FullName -Destination ($env:SystemDrive + '\Windows\System32\CodeIntegrity\SiPolicy.p7b') -Force;citool --refresh -json;Remove-Item -Path '.\VulnerableDriverBlockList' -Recurse -Force;Remove-Item -Path '.\VulnerableDriverBlockList.zip' -Force;}"
""";

            // Execute the WMI method to create the action
            ManagementBaseObject actionResult = actionClass.InvokeMethod("NewActionByExec", actionInParams, null);

            // Check if the action was created successfully
            if ((uint)actionResult["ReturnValue"] != 0)
            {
                throw new InvalidOperationException($"Failed to create task action: {((uint)actionResult["ReturnValue"])}");
            }

            // Extract CIM instance for further use in task registration
            ManagementBaseObject actionCimInstance = (ManagementBaseObject)actionResult["cmdletOutput"];

            #endregion


            #region Principal
            // Create a scheduled task principal and assign the SYSTEM account's SID to it so that the task will run under its context
            using ManagementClass principalClass = new(scope, new ManagementPath("PS_ScheduledTask"), null);

            // Prepare method parameters to set up the principal (user context)
            ManagementBaseObject principalInParams = principalClass.GetMethodParameters("NewPrincipalByUser");
            principalInParams["UserId"] = "S-1-5-18"; // SYSTEM SID (runs with the highest system privileges)
            principalInParams["LogonType"] = 2; // S4U logon type, allows the task to run without storing credentials
            principalInParams["RunLevel"] = 1; // Highest run level, ensuring the task runs with elevated privileges

            // Execute the WMI method to create the principal
            ManagementBaseObject principalResult = principalClass.InvokeMethod("NewPrincipalByUser", principalInParams, null);

            // Check if the principal was created successfully
            if ((uint)principalResult["ReturnValue"] != 0)
            {
                throw new InvalidOperationException($"Failed to create task principal: {((uint)principalResult["ReturnValue"])}");
            }

            // Extract CIM instance for further use in task registration
            ManagementBaseObject principalCimInstance = (ManagementBaseObject)principalResult["cmdletOutput"];
            #endregion


            #region Trigger
            // Create a trigger for the scheduled task. The task will first run one hour after its creation and from then on will run every 7 days, indefinitely
            using ManagementClass triggerClass = new(scope, new ManagementPath("PS_ScheduledTask"), null);

            // Prepare method parameters for setting the task trigger
            // DateTime and TimeSpan are .NET constructs that are not directly compatible with WMI methods, which require the use of DMTF DateTime and TimeInterval formats.
            // The conversion ensures that time-related parameters (e.g., DateTime.Now.AddHours(1) or TimeSpan.FromDays(7)) are formatted in a way that the WMI provider can interpret them correctly.
            // The ManagementDateTimeConverter class provides methods like ToDmtfDateTime and ToDmtfTimeInterval that perform these necessary conversions.

            ManagementBaseObject triggerInParams = triggerClass.GetMethodParameters("NewTriggerByOnce");
            triggerInParams["Once"] = true; // This switch indicates the task should run once
            triggerInParams["At"] = ManagementDateTimeConverter.ToDmtfDateTime(DateTime.Now.AddHours(1)); // Convert the current time +1 hour to DMTF format
            triggerInParams["RepetitionInterval"] = ManagementDateTimeConverter.ToDmtfTimeInterval(TimeSpan.FromDays(7)); // Convert 7-day interval to DMTF format

            // Execute the WMI method to create the trigger
            ManagementBaseObject triggerResult = triggerClass.InvokeMethod("NewTriggerByOnce", triggerInParams, null);

            // Check if the trigger was created successfully
            if ((uint)triggerResult["ReturnValue"] != 0)
            {
                throw new InvalidOperationException($"Failed to create task trigger: {((uint)triggerResult["ReturnValue"])}");
            }

            // Extract CIM instance for further use in task registration
            ManagementBaseObject triggerCimInstance = (ManagementBaseObject)triggerResult["cmdletOutput"];
            #endregion


            #region Settings
            // Define advanced settings for the scheduled task
            using ManagementClass settingsClass = new(scope, new ManagementPath("PS_ScheduledTask"), null);

            // Prepare method parameters to define advanced settings for the task
            ManagementBaseObject settingsInParams = settingsClass.GetMethodParameters("NewSettings");
            settingsInParams["AllowStartIfOnBatteries"] = true; // Allow the task to start if the system is on battery
            settingsInParams["DontStopIfGoingOnBatteries"] = true; // Ensure the task isn't stopped if the system switches to battery power
            settingsInParams["Compatibility"] = 4;
            settingsInParams["StartWhenAvailable"] = true; // Start the task if it missed a scheduled time but becomes available
            settingsInParams["RunOnlyIfNetworkAvailable"] = true; // Run the task only if a network is available
            settingsInParams["ExecutionTimeLimit"] = ManagementDateTimeConverter.ToDmtfTimeInterval(TimeSpan.FromMinutes(3)); // Limit task execution time to 3 minutes (converted to DMTF format)
            settingsInParams["RestartCount"] = 4; // Number of allowed task restarts on failure
            settingsInParams["RestartInterval"] = ManagementDateTimeConverter.ToDmtfTimeInterval(TimeSpan.FromHours(6)); // Wait 6 hours between restarts (converted to DMTF format)

            // Execute the WMI method to set the task's advanced settings
            ManagementBaseObject settingsResult = settingsClass.InvokeMethod("NewSettings", settingsInParams, null);
            if ((uint)settingsResult["ReturnValue"] != 0)
            {
                throw new InvalidOperationException($"Failed to define task settings: {((uint)settingsResult["ReturnValue"])}");
            }

            // Extract CIM instance for further use in task registration
            ManagementBaseObject settingsCimInstance = (ManagementBaseObject)settingsResult["cmdletOutput"];
            #endregion


            #region Register Task
            // Register the scheduled task. If the task's state is disabled, it will be overwritten with a new task that is enabled
            using ManagementClass registerClass = new(scope, new ManagementPath("PS_ScheduledTask"), null);

            // Prepare method parameters to register the task
            ManagementBaseObject registerInParams = registerClass.GetMethodParameters("RegisterByPrincipal");
            registerInParams["Force"] = true; // Overwrite any existing task with the same name
            registerInParams["Principal"] = principalCimInstance;
            registerInParams["Action"] = new ManagementBaseObject[] { actionCimInstance };
            registerInParams["Trigger"] = new ManagementBaseObject[] { triggerCimInstance };
            registerInParams["Settings"] = settingsCimInstance;
            registerInParams["TaskPath"] = @"\MSFT Driver Block list update";
            registerInParams["TaskName"] = "MSFT Driver Block list update";
            registerInParams["Description"] = "Microsoft Recommended Driver Block List update";

            // Execute the WMI method to register the task
            ManagementBaseObject registerResult = registerClass.InvokeMethod("RegisterByPrincipal", registerInParams, null);

            // Check if the task was registered successfully
            if ((uint)registerResult["ReturnValue"] != 0)
            {
                throw new InvalidOperationException($"Failed to register the task: {((uint)registerResult["ReturnValue"])}");
            }
            #endregion

            Logger.LogMessage("Successfully created the Microsoft Recommended Driver Block Rules auto updater scheduled task.", LogTypeIntel.Information);





            /*
            PowerShell implementation of this

           [System.String]$TaskArgument = @'
-NoProfile -WindowStyle Hidden -command "& {try {Invoke-WebRequest -Uri 'https://aka.ms/VulnerableDriverBlockList' -OutFile 'VulnerableDriverBlockList.zip' -ErrorAction Stop}catch{exit 1};Expand-Archive -Path '.\VulnerableDriverBlockList.zip' -DestinationPath 'VulnerableDriverBlockList' -Force;$SiPolicy_EnforcedFile = Get-ChildItem -Recurse -File -Path '.\VulnerableDriverBlockList' -Filter 'SiPolicy_Enforced.p7b' | Select-Object -First 1;Move-Item -Path $SiPolicy_EnforcedFile.FullName -Destination ($env:SystemDrive + '\Windows\System32\CodeIntegrity\SiPolicy.p7b') -Force;citool --refresh -json;Remove-Item -Path '.\VulnerableDriverBlockList' -Recurse -Force;Remove-Item -Path '.\VulnerableDriverBlockList.zip' -Force;}"
'@

$ActionResult = Invoke-CimMethod -Namespace 'Root\Microsoft\Windows\TaskScheduler' -ClassName 'PS_ScheduledTask' -MethodName 'NewActionByExec' -Arguments @{
   Execute  = 'PowerShell.exe'
   Argument = $TaskArgument
}

if ([uint]$ActionResult.ReturnValue -eq 0) {
   [Microsoft.Management.Infrastructure.CimInstance]$Action = $ActionResult.cmdletOutput
}
else {
   throw 'Could not create task action.'
}


[System.Security.Principal.SecurityIdentifier]$SYSTEMSID = [System.Security.Principal.SecurityIdentifier]::new([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
$TaskPrincipalResult = Invoke-CimMethod -Namespace 'Root\Microsoft\Windows\TaskScheduler' -ClassName 'PS_ScheduledTask' -MethodName 'NewPrincipalByUser' -Arguments @{
   UserId    = $SYSTEMSID.Value
   LogonType = [int]2
   RunLevel  = [int]1
}

if ([uint]$TaskPrincipalResult.ReturnValue -eq 0) {
   [Microsoft.Management.Infrastructure.CimInstance]$TaskPrincipal = $TaskPrincipalResult.cmdletOutput
}
else {
   throw 'Could not create task principal.'
}


$TriggerResult = Invoke-CimMethod -Namespace 'Root\Microsoft\Windows\TaskScheduler' -ClassName 'PS_ScheduledTask' -MethodName 'NewTriggerByOnce' -Arguments @{
   Once               = $true
   At                 = [System.DateTime]::Now.AddHours(1)
   RepetitionInterval = [System.TimeSpan]::New(7, 0, 0, 0)
}

if ([uint]$TriggerResult.ReturnValue -eq 0) {
   [Microsoft.Management.Infrastructure.CimInstance]$Trigger = $TriggerResult.cmdletOutput
}
else {
   throw 'Could not create task principal.'
}


$TaskSettingsResult = Invoke-CimMethod -Namespace 'Root\Microsoft\Windows\TaskScheduler' -ClassName 'PS_ScheduledTask' -MethodName 'NewSettings' -Arguments @{
   AllowStartIfOnBatteries    = $true
   DontStopIfGoingOnBatteries = $true
   Compatibility              = [int]4
   StartWhenAvailable         = $true
   RunOnlyIfNetworkAvailable  = $true
   ExecutionTimeLimit         = [System.TimeSpan]::New(0, 0, 3, 0) # 3 Minutes
   RestartCount               = [int]4
   RestartInterval            = [System.TimeSpan]::New(0, 6, 0, 0) # 6 Hours
}

if ([uint]$TaskSettingsResult.ReturnValue -eq 0) {
   [Microsoft.Management.Infrastructure.CimInstance]$TaskSettings = $TaskSettingsResult.cmdletOutput
}
else {
   throw 'Could not create task principal.'
}


$RegisterByPrincipalResult = Invoke-CimMethod -Namespace 'Root\Microsoft\Windows\TaskScheduler' -ClassName 'PS_ScheduledTask' -MethodName 'RegisterByPrincipal' -Arguments @{
   Force       = $true
   Principal   = $TaskPrincipal
   Action      = [Microsoft.Management.Infrastructure.CimInstance[]]$Action
   Trigger     = [Microsoft.Management.Infrastructure.CimInstance[]]$Trigger
   Settings    = $TaskSettings
   TaskPath    = 'MSFT Driver Block list update'
   TaskName    = 'MSFT Driver Block list update'
   Description = 'Microsoft Recommended Driver Block List update'
}

if ([uint]$RegisterByPrincipalResult.ReturnValue -eq 0) {
   Write-Host 'Task Successfully registered.'
}
else {
   throw 'Could not register the task..'
}


            */


        }
    }
}
