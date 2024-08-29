using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;

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

            HardenWindowsSecurity.Logger.LogMessage("Running the Microsoft Defender category");

            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Microsoft Defender Policies", "registry.pol"), LGPORunner.FileType.POL);

            HardenWindowsSecurity.Logger.LogMessage("Optimizing Network Protection Performance of the Microsoft Defender");
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("AllowSwitchToAsyncInspection", true);

            HardenWindowsSecurity.Logger.LogMessage("Enabling Real-time protection and Security Intelligence Updates during OOBE");
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("OobeEnableRtpAndSigUpdate", true);

            HardenWindowsSecurity.Logger.LogMessage("Enabling Intel Threat Detection Technology");
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("IntelTDTEnabled", true);

            HardenWindowsSecurity.Logger.LogMessage("Enabling Restore point scan");
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("DisableRestorePoint", false);

            HardenWindowsSecurity.Logger.LogMessage("Disabling Performance mode of Defender that only applies to Dev drives by lowering security");
            // Due to a possible bug or something, 0 means 1 and 1 means 0
            // Invoke-CimMethod -Namespace "ROOT\Microsoft\Windows\Defender" -ClassName "MSFT_MpPreference" -MethodName Set -Arguments @{PerformanceModeStatus = [byte]1}
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<byte>("PerformanceModeStatus", 1);

            HardenWindowsSecurity.Logger.LogMessage("Setting the Network Protection to block network traffic instead of displaying a warning");
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("EnableConvertWarnToBlock", true);

            //2nd level aggression will come after further testing
            HardenWindowsSecurity.Logger.LogMessage("Setting the Brute-Force Protection to use cloud aggregation to block IP addresses that are over 99% likely malicious");
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<byte>("BruteForceProtectionAggressiveness", 1);

            HardenWindowsSecurity.Logger.LogMessage("Setting the Brute-Force Protection to prevent suspicious and malicious behaviors");
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<byte>("BruteForceProtectionConfiguredState", 1);

            HardenWindowsSecurity.Logger.LogMessage("Setting the internal feature logic to determine blocking time for the Brute-Force Protections");
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<uint>("BruteForceProtectionMaxBlockTime", 0);

            HardenWindowsSecurity.Logger.LogMessage("Setting the Remote Encryption Protection to use cloud intel and context, and block when confidence level is above 90%");
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<byte>("RemoteEncryptionProtectionAggressiveness", 2);

            HardenWindowsSecurity.Logger.LogMessage("Setting the Remote Encryption Protection to prevent suspicious and malicious behaviors");
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<byte>("RemoteEncryptionProtectionConfiguredState", 1);

            HardenWindowsSecurity.Logger.LogMessage("Setting the internal feature logic to determine blocking time for the Remote Encryption Protection");
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<uint>("RemoteEncryptionProtectionMaxBlockTime", 0);

            HardenWindowsSecurity.Logger.LogMessage("Extending brute-force protection coverage to block local network addresses.");
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("BruteForceProtectionLocalNetworkBlocking", true);

            HardenWindowsSecurity.Logger.LogMessage("Enabling ECS in Microsoft Defender for better product health and security.");
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("EnableEcsConfiguration", true);

            HardenWindowsSecurity.Logger.LogMessage("Adding OneDrive folders of all the user accounts (personal and work accounts) to the Controlled Folder Access for Ransomware Protection");
            string[] OneDrivePaths = HardenWindowsSecurity.GetOneDriveDirectories.Get().ToArray();
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<string[]>("ControlledFolderAccessProtectedFolders", OneDrivePaths);

            HardenWindowsSecurity.Logger.LogMessage("Enabling Mandatory ASLR Exploit Protection system-wide");

            #region ASLR System-Wide
            try
            {
                // Define the PowerShell command to execute
                string command = "Set-ProcessMitigation -System -Enable ForceRelocateImages";

                // Set up the process start info
                ProcessStartInfo processStartInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-Command \"{command}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                // Start the process
                using (Process? process = Process.Start(processStartInfo))
                {
                    // Capture the output and error
                    string output = process!.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();

                    // Wait for the process to exit
                    process.WaitForExit();

                    // Check if there were any errors
                    if (process.ExitCode != 0)
                    {
                        throw new Exception($"Error executing PowerShell command: {error}");
                    }

                    // Output the result
                    HardenWindowsSecurity.Logger.LogMessage("Command executed successfully:");
                    HardenWindowsSecurity.Logger.LogMessage(output);
                }
            }
            catch (Exception ex)
            {
                HardenWindowsSecurity.Logger.LogMessage($"Exception: {ex.Message}");
            }
            #endregion

            HardenWindowsSecurity.Logger.LogMessage("Excluding GitHub Desktop Git executables from mandatory ASLR if they are found");

            List<FileInfo>? gitHubDesktopFiles = HardenWindowsSecurity.GitHubDesktopFinder.Find();

            if (gitHubDesktopFiles != null)
            {
                IEnumerable<string> gitHubDesktopExes = gitHubDesktopFiles.Select(x => x.Name);
                HardenWindowsSecurity.ForceRelocateImagesForFiles.SetProcessMitigationForFiles(gitHubDesktopExes.ToArray());
            }


            HardenWindowsSecurity.Logger.LogMessage("Excluding Git executables from mandatory ASLR if they are found");

            List<FileInfo>? gitExesFiles = HardenWindowsSecurity.GitExesFinder.Find();

            if (gitExesFiles != null)
            {
                IEnumerable<string> gitExes = gitExesFiles.Select(x => x.Name);
                HardenWindowsSecurity.ForceRelocateImagesForFiles.SetProcessMitigationForFiles(gitExes.ToArray());
            }

            // Skip applying process mitigations when ARM hardware detected
            if (string.Equals(Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE"), "ARM64", StringComparison.OrdinalIgnoreCase))
            {
                HardenWindowsSecurity.Logger.LogMessage("ARM64 hardware detected, skipping process mitigations due to potential incompatibilities.");
            }
            else
            {
                HardenWindowsSecurity.Logger.LogMessage("Applying the Process Mitigations");
                HardenWindowsSecurity.ProcessMitigationsApplication.Apply();
            }

            HardenWindowsSecurity.Logger.LogMessage("Turning on Data Execution Prevention (DEP) for all applications, including 32-bit programs");
            // Old method: bcdedit.exe /set '{current}' nx AlwaysOn
            // New method using PowerShell cmdlets added in Windows 11
            MicrosoftDefender.SetNXBit();
        }

        private static void SetNXBit()
        {
            // Create a PowerShell instance
            using (PowerShell ps = PowerShell.Create())
            {
                // Add the command to the PowerShell instance
                ps.AddCommand("Set-BcdElement")
                  .AddParameter("Element", "nx")
                  .AddParameter("Type", "Integer")
                  .AddParameter("Value", 3)
                  .AddParameter("Force");

                // Execute the command and handle any results or exceptions
                try
                {
                    var results = ps.Invoke();

                    // Check for errors
                    if (ps.HadErrors)
                    {
                        foreach (var error in ps.Streams.Error)
                        {
                            HardenWindowsSecurity.Logger.LogMessage("Error: " + error.ToString());
                        }
                    }
                    else
                    {
                        HardenWindowsSecurity.Logger.LogMessage("Command executed successfully.");
                    }
                }
                catch (Exception ex)
                {
                    HardenWindowsSecurity.Logger.LogMessage("An error occurred: " + ex.Message);
                }
            }
        }
    }
}
