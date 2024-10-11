using System;
using System.IO;
using System.Management;

#nullable enable

namespace WDACConfig
{
    public class SnapBackGuarantee
    {

        /// <summary>
        /// A method that arms the system with a snapback guarantee in case of a reboot during the base policy enforcement process.
        /// This will help prevent the system from being stuck in audit mode in case of a power outage or a reboot during the base policy enforcement process.
        /// </summary>
        /// <param name="path">The path to the EnforcedMode.cip file that will be used to revert the base policy to enforced mode in case of a reboot.</param>
        /// <exception cref="InvalidOperationException"></exception>
        public static void Create(string path)
        {

            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "The path to the EnforcedMode.cip file cannot be null or whitespace.");
            }

            Logger.Write("Creating the scheduled task for Snap Back Guarantee");

            // Initialize ManagementScope to interact with Task Scheduler's WMI namespace
            var scope = new ManagementScope(@"root\Microsoft\Windows\TaskScheduler");
            // Establish connection to the WMI namespace
            scope.Connect();

            #region Action
            // Creating a scheduled task action
            using ManagementClass actionClass = new(scope, new ManagementPath("PS_ScheduledTask"), null);

            // Prepare method parameters for creating the task action
            var actionInParams = actionClass.GetMethodParameters("NewActionByExec");
            actionInParams["Execute"] = "cmd.exe";

            // The PowerShell command to run, downloading and deploying the drivers block list
            actionInParams["Argument"] = $"/c \"{GlobalVars.UserConfigDir}\\EnforcedModeSnapBack.cmd\"";

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
            // Create a trigger for the scheduled task
            using ManagementClass triggerClass = new(scope, new ManagementPath("PS_ScheduledTask"), null);

            ManagementBaseObject triggerInParams = triggerClass.GetMethodParameters("NewTriggerByLogon");
            triggerInParams["AtLogOn"] = true;

            // Execute the WMI method to create the trigger
            ManagementBaseObject triggerResult = triggerClass.InvokeMethod("NewTriggerByLogon", triggerInParams, null);

            // Check if the trigger was created successfully
            if ((uint)triggerResult["ReturnValue"] != 0)
            {
                throw new InvalidOperationException($"Failed to create task trigger: {((uint)triggerResult["ReturnValue"])}");
            }

            // Extract CIM instance for further use in task registration
            var triggerCimInstance = (ManagementBaseObject)triggerResult["cmdletOutput"];
            #endregion


            #region Settings
            // Define advanced settings for the scheduled task
            using ManagementClass settingsClass = new(scope, new ManagementPath("PS_ScheduledTask"), null);

            // Prepare method parameters to define advanced settings for the task
            ManagementBaseObject settingsInParams = settingsClass.GetMethodParameters("NewSettings");
            settingsInParams["AllowStartIfOnBatteries"] = true; // Allow the task to start if the system is on battery
            settingsInParams["DontStopIfGoingOnBatteries"] = true; // Ensure the task isn't stopped if the system switches to battery power
            settingsInParams["Compatibility"] = 4;
            // Setting the task to run with the highest priority.This is to ensure that the task runs as soon as possible after the reboot.It runs even on logon screen before user logs on too.
            settingsInParams["Priority"] = 0;
            settingsInParams["Hidden"] = true;
            settingsInParams["RestartCount"] = 2; // Number of allowed task restarts on failure
            settingsInParams["RestartInterval"] = ManagementDateTimeConverter.ToDmtfTimeInterval(TimeSpan.FromMinutes(3)); // Wait 3 minutes between restarts (converted to DMTF format)

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
            registerInParams["TaskName"] = "EnforcedModeSnapBack";

            // Execute the WMI method to register the task
            var registerResult = registerClass.InvokeMethod("RegisterByPrincipal", registerInParams, null);

            // Check if the task was registered successfully
            if ((uint)registerResult["ReturnValue"] != 0)
            {
                throw new InvalidOperationException($"Failed to register the task: {((uint)registerResult["ReturnValue"])}");
            }
            #endregion

            Logger.Write("Successfully created the Microsoft Recommended Driver Block Rules auto updater scheduled task.");



            // Saving the EnforcedModeSnapBack.cmd file to the UserConfig directory in Program Files
            // It contains the instructions to revert the base policy to enforced mode

            string savePath = Path.Combine(GlobalVars.UserConfigDir, "EnforcedModeSnapBack.cmd");

            string contentToBeSaved = $@"
REM Deploying the Enforced Mode SnapBack CI Policy
CiTool --update-policy ""{path}"" -json
REM Deleting the Scheduled task responsible for running this CMD file
schtasks /Delete /TN EnforcedModeSnapBack /F
REM Deleting the CI Policy file
del /f /q ""{path}""
REM Deleting this CMD file itself
del ""%~f0""
";


            // Write to file (overwrite if exists)
            File.WriteAllText(savePath, contentToBeSaved);


            // An alternative way to do this which is less reliable because RunOnce key can be deleted by 3rd party programs during installation etc.

        }
    }
}
