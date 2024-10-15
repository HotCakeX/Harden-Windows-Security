using System;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class OptionalWindowsFeatures
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

            ArgumentNullException.ThrowIfNull(CapabilityIdentity);
            ArgumentNullException.ThrowIfNull(CapabilityName);

            // The queried state of the capability
            string CapabilityState;

            CapabilityState = HardenWindowsSecurity.WindowsFeatureChecker.GetCapabilityState(CapabilityIdentity);

            if (string.Equals(CapabilityState, "Not Present", StringComparison.OrdinalIgnoreCase))
            {
                HardenWindowsSecurity.Logger.LogMessage($"The {CapabilityName} is already removed.", LogTypeIntel.Information);
            }
            else if (string.Equals(CapabilityState, "Installed", StringComparison.OrdinalIgnoreCase))
            {
                HardenWindowsSecurity.Logger.LogMessage($"Removing {CapabilityName}", LogTypeIntel.Information);

                // For capabilities, using DISM would do the job but would hang and not exit
                // Running DISM in a different thread wouldn't fix it. DISM has this problem only for capabilities, but for using features DISM works fine.

                // PowerShell script to run to remove the Windows Capability
                string PSScript = $@"
Import-Module -Name 'DISM' -UseWindowsPowerShell -Force -WarningAction SilentlyContinue
$null = Get-WindowsCapability -Online |
Where-Object -FilterScript {{ $_.Name -like '*{CapabilityIdentity}*' }} |
Remove-WindowsCapability -Online
";

                // Run the PowerShell script
                _ = HardenWindowsSecurity.PowerShellExecutor.ExecuteScript(PSScript);

            }
            else
            {
                HardenWindowsSecurity.Logger.LogMessage($"The {CapabilityName} is in {CapabilityState} state. Skipping.", LogTypeIntel.Information);
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

            if (propertyInfo is not null)
            {
                propertyValue = propertyInfo.GetValue(_FeaturesCheckResults)?.ToString();
            }

            if (string.IsNullOrWhiteSpace(propertyValue))
            {
                HardenWindowsSecurity.Logger.LogMessage($"couldn't get the state of {FeatureNameToCheckWith}", LogTypeIntel.Information);
            }

            if (string.Equals(propertyValue, ValueToCheckAgainst, StringComparison.OrdinalIgnoreCase))
            {
                HardenWindowsSecurity.Logger.LogMessage($"{FriendlyName} is already {ValueToCheckAgainst}", LogTypeIntel.Information);
            }
            else if (string.Equals(propertyValue, ValueToCheckFor, StringComparison.OrdinalIgnoreCase))
            {
                HardenWindowsSecurity.Logger.LogMessage($"{TextToUseForMessages} {FriendlyName}", LogTypeIntel.Information);
                HardenWindowsSecurity.WindowsFeatureChecker.SetWindowsFeature(FeatureNameToActOn, Action);
            }
            else
            {
                HardenWindowsSecurity.Logger.LogMessage($"The {FriendlyName} is in {propertyValue} state. Skipping.", LogTypeIntel.Information);
            }
        }

        public static void Invoke()
        {

            ChangePSConsoleTitle.Set("🏅 Optional Features");

            HardenWindowsSecurity.Logger.LogMessage("Running the Optional Windows Features category", LogTypeIntel.Information);

            // Get the results of all optional features once and store them in the static variable to be reused later
            _FeaturesCheckResults = HardenWindowsSecurity.WindowsFeatureChecker.CheckWindowsFeatures();

            ConfigureWindowsOptionalFeature(false, "MicrosoftWindowsPowerShellV2", "PowerShell v2", "PowerShellv2");
            ConfigureWindowsOptionalFeature(false, "MicrosoftWindowsPowerShellV2Root", "PowerShell v2 root", "PowerShellv2Engine");
            ConfigureWindowsOptionalFeature(false, "WorkFolders-Client", "Work Folders", "WorkFoldersClient");
            ConfigureWindowsOptionalFeature(false, "Printing-Foundation-Features", "Print Foundation Features", "InternetPrintingClient");
            ConfigureWindowsOptionalFeature(false, "Windows-Defender-ApplicationGuard", "Deprecated Microsoft Defender Application Guard (MDAG)", "MDAG");
            ConfigureWindowsOptionalFeature(true, "Containers-DisposableClientVM", "Windows Sandbox", "WindowsSandbox");
            ConfigureWindowsOptionalFeature(true, "Microsoft-Hyper-V", "Hyper-V", "HyperV");

            RemoveCapability("Media.WindowsMediaPlayer", "The old Windows Media Player");
            RemoveCapability("WMIC", "Deprecated WMIC");
            RemoveCapability("Microsoft.Windows.Notepad.System", "Old classic Notepad");
            RemoveCapability("Microsoft.Windows.WordPad", "Deprecated WordPad");
            RemoveCapability("Microsoft.Windows.PowerShell.ISE", "PowerShell ISE");
            RemoveCapability("App.StepsRecorder", "Deprecated Steps Recorder");
            RemoveCapability("VBSCRIPT", "Deprecated VBScript");
            RemoveCapability("Browser.InternetExplorer", "Internet Explorer Mode for Edge");
        }
    }
}
