using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class MicrosoftDefender
    {
        /// <summary>
        /// Runs the Microsoft Defender category
        /// </summary>
        public static void Invoke()
        {

            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            ChangePSConsoleTitle.Set("🍁 MSFT Defender");

            HardenWindowsSecurity.Logger.LogMessage("Running the Microsoft Defender category", LogTypeIntel.Information);

            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Microsoft Defender Policies", "registry.pol"), LGPORunner.FileType.POL);

            HardenWindowsSecurity.Logger.LogMessage("Enabling Restore point scan", LogTypeIntel.Information);
            HardenWindowsSecurity.ConfigDefenderHelper.ManageMpPreference<bool>("DisableRestorePoint", false, true);

            HardenWindowsSecurity.Logger.LogMessage("Optimizing Network Protection Performance of the Microsoft Defender", LogTypeIntel.Information);
            HardenWindowsSecurity.ConfigDefenderHelper.ManageMpPreference<bool>("AllowSwitchToAsyncInspection", true, true);

            HardenWindowsSecurity.Logger.LogMessage("Setting the Network Protection to block network traffic instead of displaying a warning", LogTypeIntel.Information);
            HardenWindowsSecurity.ConfigDefenderHelper.ManageMpPreference<bool>("EnableConvertWarnToBlock", true, true);

            HardenWindowsSecurity.Logger.LogMessage("Extending brute-force protection coverage to block local network addresses.", LogTypeIntel.Information);
            HardenWindowsSecurity.ConfigDefenderHelper.ManageMpPreference<bool>("BruteForceProtectionLocalNetworkBlocking", true, true);

            HardenWindowsSecurity.Logger.LogMessage("Enabling ECS in Microsoft Defender for better product health and security.", LogTypeIntel.Information);
            HardenWindowsSecurity.ConfigDefenderHelper.ManageMpPreference<bool>("EnableEcsConfiguration", true, true);

            HardenWindowsSecurity.Logger.LogMessage("Adding OneDrive folders of all the user accounts (personal and work accounts) to the Controlled Folder Access for Ransomware Protection", LogTypeIntel.Information);
            string[] OneDrivePaths = [.. HardenWindowsSecurity.GetOneDriveDirectories.Get()];
            HardenWindowsSecurity.ConfigDefenderHelper.ManageMpPreference<string[]>("ControlledFolderAccessProtectedFolders", OneDrivePaths, true);

            HardenWindowsSecurity.Logger.LogMessage("Enabling Mandatory ASLR Exploit Protection system-wide", LogTypeIntel.Information);

            // Define the PowerShell command to execute
            string command = "Set-ProcessMitigation -System -Enable ForceRelocateImages";
            _ = HardenWindowsSecurity.PowerShellExecutor.ExecuteScript(command);


            HardenWindowsSecurity.Logger.LogMessage("Excluding GitHub Desktop Git executables from mandatory ASLR if they are found", LogTypeIntel.Information);

            List<FileInfo>? gitHubDesktopFiles = HardenWindowsSecurity.GitHubDesktopFinder.Find();

            if (gitHubDesktopFiles is not null)
            {
                IEnumerable<string> gitHubDesktopExes = gitHubDesktopFiles.Select(x => x.Name);
                HardenWindowsSecurity.ForceRelocateImagesForFiles.SetProcessMitigationForFiles(gitHubDesktopExes.ToArray());
            }


            HardenWindowsSecurity.Logger.LogMessage("Excluding Git executables from mandatory ASLR if they are found", LogTypeIntel.Information);

            List<FileInfo>? gitExesFiles = HardenWindowsSecurity.GitExesFinder.Find();

            if (gitExesFiles is not null)
            {
                IEnumerable<string> gitExes = gitExesFiles.Select(x => x.Name);
                HardenWindowsSecurity.ForceRelocateImagesForFiles.SetProcessMitigationForFiles(gitExes.ToArray());
            }

            // Skip applying process mitigations when ARM hardware detected
            if (string.Equals(Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE"), "ARM64", StringComparison.OrdinalIgnoreCase))
            {
                HardenWindowsSecurity.Logger.LogMessage("ARM64 hardware detected, skipping process mitigations due to potential incompatibilities.", LogTypeIntel.Information);
            }
            else
            {
                HardenWindowsSecurity.Logger.LogMessage("Applying the Process Mitigations", LogTypeIntel.Information);
                HardenWindowsSecurity.ProcessMitigationsApplication.Apply();
            }

            HardenWindowsSecurity.Logger.LogMessage("Turning on Data Execution Prevention (DEP) for all applications, including 32-bit programs", LogTypeIntel.Information);
            // Old method: bcdedit.exe /set '{current}' nx AlwaysOn
            // New method using PowerShell cmdlets added in Windows 11
            _ = HardenWindowsSecurity.PowerShellExecutor.ExecuteScript(@"Set-BcdElement -Element 'nx' -Type 'Integer' -Value '3'");
        }
    }
}
