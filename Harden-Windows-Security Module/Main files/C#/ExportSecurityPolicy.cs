using System;
using System.Collections.Generic;
using Microsoft.Win32;
using System.Linq;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Management.Automation;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;

namespace HardenWindowsSecurity
{
    public partial class ConfirmSystemComplianceMethods
    {
        /// <summary>
        /// Get the security group policies by utilizing the Secedit.exe
        /// </summary>
        public static void ExportSecurityPolicy()
        {
            // Assuming securityPolicyInfPath is defined in your environment
            string securityPolicyInfPath = HardenWindowsSecurity.GlobalVars.securityPolicyInfPath;
            string systemDrive = Environment.GetEnvironmentVariable("SystemDrive");

            // Create the process start info
            ProcessStartInfo processStartInfo = new ProcessStartInfo
            {
                FileName = $"{systemDrive}\\Windows\\System32\\Secedit.exe",
                Arguments = $"/export /cfg \"{securityPolicyInfPath}\"",
                // RedirectStandardOutput = false,
                RedirectStandardError = true, // Redirect the StandardError stream
                UseShellExecute = false,
                CreateNoWindow = true
            };

            // Start the process
            using (Process process = Process.Start(processStartInfo))
            {
                // Read the output
                // string output = process.StandardOutput.ReadToEnd();

                string error = process.StandardError.ReadToEnd();

                process.WaitForExit();

                if (!string.IsNullOrEmpty(error))
                {
                    HardenWindowsSecurity.VerboseLogger.Write("Error: " + error);
                }
            }
        }
    }
}
