using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Management;
using System.Globalization;

#nullable enable

namespace HardenWindowsSecurity
{
    internal static class WindowsFeatureChecker
    {
        internal class FeatureStatus
        {
            internal string? PowerShellv2 { get; set; }
            internal string? PowerShellv2Engine { get; set; }
            internal string? WorkFoldersClient { get; set; }
            internal string? InternetPrintingClient { get; set; }
            internal string? WindowsMediaPlayer { get; set; }
            internal string? MDAG { get; set; }
            internal string? WindowsSandbox { get; set; }
            internal string? HyperV { get; set; }
            internal string? WMIC { get; set; }
            internal string? IEMode { get; set; }
            internal string? LegacyNotepad { get; set; }
            internal string? LegacyWordPad { get; set; }
            internal string? PowerShellISE { get; set; }
            internal string? StepsRecorder { get; set; }
        }

        internal static FeatureStatus CheckWindowsFeatures()
        {
            // Get the states of optional features using Cim Instance only once so that we can use it multiple times
            Dictionary<string, string>? optionalFeatureStates = GetOptionalFeatureStates();

            return new FeatureStatus
            {
                PowerShellv2 = optionalFeatureStates.GetValueOrDefault("MicrosoftWindowsPowerShellV2", "Unknown"),
                PowerShellv2Engine = optionalFeatureStates.GetValueOrDefault("MicrosoftWindowsPowerShellV2Root", "Unknown"),
                WorkFoldersClient = optionalFeatureStates.GetValueOrDefault("WorkFolders-Client", "Unknown"),
                InternetPrintingClient = optionalFeatureStates.GetValueOrDefault("Printing-Foundation-Features", "Unknown"),
                WindowsMediaPlayer = GetCapabilityState("Media.WindowsMediaPlayer"),
                MDAG = optionalFeatureStates.GetValueOrDefault("Windows-Defender-ApplicationGuard", "Unknown"),
                WindowsSandbox = optionalFeatureStates.GetValueOrDefault("Containers-DisposableClientVM", "Unknown"),
                HyperV = optionalFeatureStates.GetValueOrDefault("Microsoft-Hyper-V", "Unknown"),
                WMIC = GetCapabilityState("Wmic"),
                IEMode = GetCapabilityState("Browser.InternetExplorer"),
                LegacyNotepad = GetCapabilityState("Microsoft.Windows.Notepad.System"),
                LegacyWordPad = GetCapabilityState("Microsoft.Windows.WordPad"),
                PowerShellISE = GetCapabilityState("Microsoft.Windows.PowerShell.ISE"),
                StepsRecorder = GetCapabilityState("App.StepsRecorder")
            };
        }

        internal static Dictionary<string, string> GetOptionalFeatureStates()
        {
            // Initialize a dictionary to store the states of optional features
            // Ensure case-insensitive key comparison
            var states = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            // Create a ManagementObjectSearcher to query Win32_OptionalFeature
            using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_OptionalFeature"))
            {
                // Iterate through each object returned by the query
                foreach (var obj in searcher.Get())
                {
                    // Retrieve the name of the feature
                    string? name = obj["Name"]?.ToString();

                    // Convert the install state to a string representation
                    string state = ConvertStateToString((UInt32)obj["InstallState"]);

                    // If the name is not null, add it to the dictionary
                    if (name != null)
                    {
                        states[name] = state;
                    }
                }
            }

            // Return the dictionary containing the states of optional features
            return states;
        }

        /// <summary>
        /// DISM.exe output is localized and changes between different language packs
        /// But using Get-WindowsCapability output consistent results.
        /// </summary>
        /// <param name="capabilityName">The name of the capability to check its state</param>
        /// <returns></returns>
        internal static string GetCapabilityState(string capabilityName)
        {
            // Define the PowerShell script template with placeholder
            string scriptTemplate = """
Import-Module -Name 'DISM' -UseWindowsPowerShell -Force -WarningAction SilentlyContinue
$CompatibilityName = '{CompatibilityName}'
return ((Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like "*$CompatibilityName*" }).State)
""";
            // Replace the placeholder with the actual value
            string script = scriptTemplate.Replace("{CompatibilityName}", capabilityName, StringComparison.OrdinalIgnoreCase);

            // Execute the script and return the output - true means the PowerShell script will return string output and won't write the normal output to the console or GUI
            string? output = HardenWindowsSecurity.PowerShellExecutor.ExecuteScript(script, true);

            if (output == null)
            {
                HardenWindowsSecurity.Logger.LogMessage($"The output of the {capabilityName} state check was null", LogTypeIntel.Information);
                return "Unknown";
            }

            if (string.Equals(output, "Installed", StringComparison.OrdinalIgnoreCase))
            {
                return "Installed";
            }

            else if (string.Equals(output, "Not Present", StringComparison.OrdinalIgnoreCase) || string.Equals(output, "NotPresent", StringComparison.OrdinalIgnoreCase))
            {
                return "Not Present";
            }

            else if (string.Equals(output, "Staged", StringComparison.OrdinalIgnoreCase))
            {
                return "Staged";
            }

            HardenWindowsSecurity.Logger.LogMessage($"The output of the {capabilityName} state check is {output}", LogTypeIntel.Information);

            return "Unknown";
        }

        private static string RunDismCommand(string arguments)
        {
            // Create a ProcessStartInfo object to configure the DISM process
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = "dism.exe",           // Set the file name to "dism.exe"
                Arguments = arguments,           // Set the arguments to the specified arguments
                RedirectStandardOutput = true,   // Redirect the standard output
                RedirectStandardError = true,
                UseShellExecute = false,         // Do not use the shell to execute
                CreateNoWindow = true            // Do not create a window
            };

            // Start the DISM process
            using (Process? process = Process.Start(startInfo))
            {
                // Check if the process is not null
                if (process == null)
                {
                    throw new InvalidOperationException("Failed to start the process.");
                }

                using (System.IO.StreamReader outputReader = process.StandardOutput)
                using (System.IO.StreamReader errorReader = process.StandardError)
                {
                    string output = outputReader.ReadToEnd();
                    string error = errorReader.ReadToEnd();

                    process.WaitForExit();

                    // Error code 87 is for when the capability doesn't exist on the system
                    // Typically when a newer OS build has removed a deprecated feature that the older builds still have
                    // The logic to handle such cases exist in other methods that call this method, but the error must not be terminating
                    if (process.ExitCode == 87)
                    {
                        //    HardenWindowsSecurity.Logger.LogMessage($"Error details: {error}");
                        //    HardenWindowsSecurity.Logger.LogMessage($"DISM command output: {output}");
                        return string.Empty;
                    }
                    // https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1700-3999-
                    else if (process.ExitCode == 3010)
                    {
                        HardenWindowsSecurity.Logger.LogMessage($"Reboot required to finish the feature/capability installation/uninstallation.", LogTypeIntel.Information);
                        return string.Empty;
                    }
                    else if (process.ExitCode != 0)
                    {
                        // Print or log error and output details for other error codes
                        HardenWindowsSecurity.Logger.LogMessage($"DISM command failed with exit code {process.ExitCode}. Error details: {error}", LogTypeIntel.Error);
                        HardenWindowsSecurity.Logger.LogMessage($"DISM command output: {output}", LogTypeIntel.Error);

                        throw new InvalidOperationException($"DISM command failed with exit code {process.ExitCode}. Error details: {error}");
                    }
                    else
                    {
                        // Return the output of the DISM command if successful
                        return output;
                    }
                }
            }
        }


        private static string ConvertStateToString(uint state)
        {
            // Convert the state code to a string representation
            return state switch
            {
                1 => "Enabled",        // State code 1 corresponds to "Enabled"
                2 => "Disabled",       // State code 2 corresponds to "Disabled"
                3 => "Abnormal",       // State code 3 corresponds to "Abnormal"
                _ => "Unknown"         // Any other state code corresponds to "Unknown"
            };
        }

        /// <summary>
        /// Enables or disables a Windows feature using DISM
        /// </summary>
        /// <param name="featureName">feature name to enable/disable</param>
        /// <param name="enable">true means enable, false means disable</param>
        internal static void SetWindowsFeature(string featureName, bool enable)
        {

            string arguments = string.Empty;

            // Determine the command based on whether we are enabling or disabling the feature
            if (enable == true)
            {
                // Construct the arguments for the DISM command
                arguments = $"/Online /Enable-Feature /FeatureName:{featureName} /All /NoRestart";
            }
            else
            {
                // Construct the arguments for the DISM command
                arguments = $"/Online /Disable-Feature /FeatureName:{featureName} /NoRestart";
            }

            // Run the DISM command using the helper method
            string output = RunDismCommand(arguments);
        }
    }
}
