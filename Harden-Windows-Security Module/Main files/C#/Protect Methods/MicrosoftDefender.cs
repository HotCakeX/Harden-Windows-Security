using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class MicrosoftDefender
    {
        /// <summary>
        /// Runs the Microsoft Defender category
        /// </summary>
        public static void Invoke()
        {

            if (HardenWindowsSecurity.GlobalVars.path == null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            HardenWindowsSecurity.Logger.LogMessage("Running the Microsoft Defender category", LogTypeIntel.Information);

            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Microsoft Defender Policies", "registry.pol"), LGPORunner.FileType.POL);

            HardenWindowsSecurity.Logger.LogMessage("Optimizing Network Protection Performance of the Microsoft Defender", LogTypeIntel.Information);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("AllowSwitchToAsyncInspection", true);

            HardenWindowsSecurity.Logger.LogMessage("Enabling Real-time protection and Security Intelligence Updates during OOBE", LogTypeIntel.Information);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("OobeEnableRtpAndSigUpdate", true);

            HardenWindowsSecurity.Logger.LogMessage("Enabling Intel Threat Detection Technology", LogTypeIntel.Information);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("IntelTDTEnabled", true);

            HardenWindowsSecurity.Logger.LogMessage("Enabling Restore point scan", LogTypeIntel.Information);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("DisableRestorePoint", false);

            HardenWindowsSecurity.Logger.LogMessage("Disabling Performance mode of Defender that only applies to Dev drives by lowering security", LogTypeIntel.Information);
            // Due to a possible bug or something, 0 means 1 and 1 means 0
            // Invoke-CimMethod -Namespace "ROOT\Microsoft\Windows\Defender" -ClassName "MSFT_MpPreference" -MethodName Set -Arguments @{PerformanceModeStatus = [byte]1}
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<byte>("PerformanceModeStatus", 1);

            HardenWindowsSecurity.Logger.LogMessage("Setting the Network Protection to block network traffic instead of displaying a warning", LogTypeIntel.Information);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("EnableConvertWarnToBlock", true);

            //2nd level aggression will come after further testing
            HardenWindowsSecurity.Logger.LogMessage("Setting the Brute-Force Protection to use cloud aggregation to block IP addresses that are over 99% likely malicious", LogTypeIntel.Information);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<byte>("BruteForceProtectionAggressiveness", 1);

            HardenWindowsSecurity.Logger.LogMessage("Setting the Brute-Force Protection to prevent suspicious and malicious behaviors", LogTypeIntel.Information);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<byte>("BruteForceProtectionConfiguredState", 1);

            HardenWindowsSecurity.Logger.LogMessage("Setting the internal feature logic to determine blocking time for the Brute-Force Protections", LogTypeIntel.Information);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<uint>("BruteForceProtectionMaxBlockTime", 0);

            HardenWindowsSecurity.Logger.LogMessage("Setting the Remote Encryption Protection to use cloud intel and context, and block when confidence level is above 90%", LogTypeIntel.Information);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<byte>("RemoteEncryptionProtectionAggressiveness", 2);

            HardenWindowsSecurity.Logger.LogMessage("Setting the Remote Encryption Protection to prevent suspicious and malicious behaviors", LogTypeIntel.Information);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<byte>("RemoteEncryptionProtectionConfiguredState", 1);

            HardenWindowsSecurity.Logger.LogMessage("Setting the internal feature logic to determine blocking time for the Remote Encryption Protection", LogTypeIntel.Information);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<uint>("RemoteEncryptionProtectionMaxBlockTime", 0);

            HardenWindowsSecurity.Logger.LogMessage("Extending brute-force protection coverage to block local network addresses.", LogTypeIntel.Information);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("BruteForceProtectionLocalNetworkBlocking", true);

            HardenWindowsSecurity.Logger.LogMessage("Enabling ECS in Microsoft Defender for better product health and security.", LogTypeIntel.Information);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("EnableEcsConfiguration", true);

            HardenWindowsSecurity.Logger.LogMessage("Adding OneDrive folders of all the user accounts (personal and work accounts) to the Controlled Folder Access for Ransomware Protection", LogTypeIntel.Information);
            string[] OneDrivePaths = HardenWindowsSecurity.GetOneDriveDirectories.Get().ToArray();
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<string[]>("ControlledFolderAccessProtectedFolders", OneDrivePaths);

            HardenWindowsSecurity.Logger.LogMessage("Enabling Mandatory ASLR Exploit Protection system-wide", LogTypeIntel.Information);

            // Define the PowerShell command to execute
            string command = "Set-ProcessMitigation -System -Enable ForceRelocateImages";
            HardenWindowsSecurity.PowerShellExecutor.ExecuteScript(command);


            HardenWindowsSecurity.Logger.LogMessage("Excluding GitHub Desktop Git executables from mandatory ASLR if they are found", LogTypeIntel.Information);

            List<FileInfo>? gitHubDesktopFiles = HardenWindowsSecurity.GitHubDesktopFinder.Find();

            if (gitHubDesktopFiles != null)
            {
                IEnumerable<string> gitHubDesktopExes = gitHubDesktopFiles.Select(x => x.Name);
                HardenWindowsSecurity.ForceRelocateImagesForFiles.SetProcessMitigationForFiles(gitHubDesktopExes.ToArray());
            }


            HardenWindowsSecurity.Logger.LogMessage("Excluding Git executables from mandatory ASLR if they are found", LogTypeIntel.Information);

            List<FileInfo>? gitExesFiles = HardenWindowsSecurity.GitExesFinder.Find();

            if (gitExesFiles != null)
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
            HardenWindowsSecurity.PowerShellExecutor.ExecuteScript(@"Set-BcdElement -Element 'nx' -Type 'Integer' -Value '3'");
        }
    }
}
