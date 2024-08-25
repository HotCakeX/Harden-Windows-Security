using System;
using System.IO;
using System.Reflection;

#nullable enable

namespace HardenWindowsSecurity
{
    public class OptionalWindowsFeatures
    {
        // Declare the _FeaturesCheckResults as a private static field
        private static HardenWindowsSecurity.WindowsFeatureChecker.FeatureStatus? _FeaturesCheckResults;

        /// <summary>
        /// A Private method that removes the capability if it is present
        /// </summary>
        /// <param name="CapabilityIdentity">the capability's identity, the one that will be used to query its state and to remove it</param>
        /// <param name="CapabilityName">The name of the capability, used to display in the log messages</param>
        private static void RemoveCapability(string CapabilityIdentity, string CapabilityName)
        {

            if (CapabilityIdentity == null)
            {
                throw new ArgumentNullException(nameof(CapabilityIdentity));
            }

            if (CapabilityName == null)
            {
                throw new ArgumentNullException(nameof(CapabilityName));
            }

            // The queried state of the capability
            string CapabilityState = string.Empty;

            CapabilityState = HardenWindowsSecurity.WindowsFeatureChecker.GetCapabilityState(CapabilityIdentity);

            if (string.Equals(CapabilityState, "Not Present", StringComparison.OrdinalIgnoreCase))
            {
                HardenWindowsSecurity.Logger.LogMessage($"The {CapabilityName} is already removed.");
            }
            else if (string.Equals(CapabilityState, "Installed", StringComparison.OrdinalIgnoreCase))
            {
                HardenWindowsSecurity.Logger.LogMessage($"Removing {CapabilityName}");

                // For capabilities, using DISM would do the job but would hang and not exit
                // Running DISM in a different thread wouldn't fix it. DISM has this problem only for capabilities, but for using features DISM works fine.

                // PowerShell script to run to remove the Windows Capability
                string PSScript = $@"
Import-Module -Name 'DISM' -UseWindowsPowerShell -Force -WarningAction SilentlyContinue
$null = Get-WindowsCapability -Online |
Where-Object -FilterScript {{ $_.Name -eq '{CapabilityIdentity}' }} |
Remove-WindowsCapability -Online
";

                // Run the PowerShell script
                HardenWindowsSecurity.PowerShellExecutor.ExecuteScript(PSScript);

            }
            else
            {
                HardenWindowsSecurity.Logger.LogMessage($"The {CapabilityName} is in {CapabilityState} state. Skipping.");
            }
        }

        /// <summary>
        /// A Private method that configures the Windows Optional Feature, enables/disables them by checking for their state first
        /// </summary>
        /// <param name="Action">true means the feature should be enabled, false means the feature should be disabled</param>
        /// <param name="FeatureNameToActOn">The exact name of the feature to use when querying/enabling/disabling it, this is what DISM.exe requires and understands</param>
        /// <param name="FriendlyName">the name to display in the displayed messages</param>
        /// <param name="FeatureNameToCheckWith">
        /// The name of the feature to use when checking its state
        /// Since the method uses the values in HardenWindowsSecurity.WindowsFeatureChecker.FeatureStatus class
        /// and they are stored under different names, we need this parameter to create the correct connections
        /// </param>
        private static void ConfigureWindowsOptionalFeature(bool Action, string FeatureNameToActOn, string FriendlyName, string FeatureNameToCheckWith)
        {
            // If the action is to enable a feature, then check if it's disabled and vise versa
            string ValueToCheckFor = Action ? "Disabled" : "Enabled";
            // Used when performing the action
            string ValueToCheckAgainst = Action ? "Enabled" : "Disabled";
            // Used in the log messages
            string TextToUseForMessages = Action ? "Enabling" : "Disabling";

            // Use reflection to get the property value
            var propertyInfo = _FeaturesCheckResults?.GetType().GetProperty(FeatureNameToCheckWith);

            // To store the value of the property of the _FeaturesCheckResults
            string? propertyValue = string.Empty;

            if (propertyInfo != null)
            {
                propertyValue = propertyInfo.GetValue(_FeaturesCheckResults)?.ToString();
            }

            if (string.IsNullOrWhiteSpace(propertyValue))
            {
                HardenWindowsSecurity.Logger.LogMessage($"couldn't get the state of {FeatureNameToCheckWith}");
            }

            if (string.Equals(propertyValue, ValueToCheckAgainst, StringComparison.OrdinalIgnoreCase))
            {
                HardenWindowsSecurity.Logger.LogMessage($"{FriendlyName} is already {ValueToCheckAgainst}");
            }
            else if (string.Equals(propertyValue, ValueToCheckFor, StringComparison.OrdinalIgnoreCase))
            {
                HardenWindowsSecurity.Logger.LogMessage($"{TextToUseForMessages} {FriendlyName}");
                HardenWindowsSecurity.WindowsFeatureChecker.SetWindowsFeature(FeatureNameToActOn, Action);
            }
            else
            {
                HardenWindowsSecurity.Logger.LogMessage($"The {FriendlyName} is in {propertyValue} state. Skipping.");
            }
        }

        public static void Invoke()
        {
            HardenWindowsSecurity.Logger.LogMessage("Running the Optional Windows Features category");

            // Get the results of all optional features once and store them in the static variable to be reused later
            _FeaturesCheckResults = HardenWindowsSecurity.WindowsFeatureChecker.CheckWindowsFeatures();


            ConfigureWindowsOptionalFeature(false, "MicrosoftWindowsPowerShellV2", "PowerShell v2", "PowerShellv2");
            ConfigureWindowsOptionalFeature(false, "MicrosoftWindowsPowerShellV2Root", "PowerShell v2 root", "PowerShellv2Engine");
            ConfigureWindowsOptionalFeature(false, "WorkFolders-Client", "Work Folders", "WorkFoldersClient");
            ConfigureWindowsOptionalFeature(false, "Printing-Foundation-Features", "Print Foundation Features", "InternetPrintingClient");
            ConfigureWindowsOptionalFeature(false, "Windows-Defender-ApplicationGuard", "Deprecated Microsoft Defender Application Guard (MDAG)", "MDAG");
            ConfigureWindowsOptionalFeature(true, "Containers-DisposableClientVM", "Windows Sandbox", "WindowsSandbox");
            ConfigureWindowsOptionalFeature(true, "Microsoft-Hyper-V", "Hyper-V", "HyperV");

            RemoveCapability("Media.WindowsMediaPlayer~~~~0.0.12.0", "The old Windows Media Player");
            RemoveCapability("Browser.InternetExplorer~~~~0.0.11.0", "Internet Explorer Mode for Edge");
            RemoveCapability("WMIC~~~~", "Deprecated WMIC");
            RemoveCapability("Microsoft.Windows.Notepad.System~~~~0.0.1.0", "Old classic Notepad");
            RemoveCapability("Microsoft.Windows.WordPad~~~~0.0.1.0", "Deprecated WordPad");
            RemoveCapability("Microsoft.Windows.PowerShell.ISE~~~~0.0.1.0", "PowerShell ISE");
            RemoveCapability("App.StepsRecorder~~~~0.0.1.0", "Deprecated Steps Recorder");
            RemoveCapability("VBSCRIPT~~~~", "Deprecated VBScript");
        }
    }
}
