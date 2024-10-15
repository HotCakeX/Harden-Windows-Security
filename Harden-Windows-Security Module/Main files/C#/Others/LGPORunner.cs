using System;
using System.Diagnostics;

#nullable enable

namespace HardenWindowsSecurity
{
    public class LGPORunner
    {
        // Enum to specify the file type
        public enum FileType
        {
            POL,
            INF
        }

        /// <summary>
        /// Method to run LGPO.exe with the appropriate parameters
        /// </summary>
        /// <param name="filePath">Path of the .Pol or .Inf file to apply using LGPO.exe</param>
        /// <param name="fileType">Whether it's Policy file or Inf file for security group policies</param>
        /// <param name="LGPOExePath">Optional: provide the path to the LGPO.exe that will be used</param>
        /// <exception cref="ArgumentException"></exception>
        public static void RunLGPOCommand(string filePath, FileType fileType, string? LGPOExePath = null)
        {
            // Construct the command based on the file type
            string commandArgs = fileType switch
            {
                FileType.POL => $"/q /m \"{filePath}\"",
                FileType.INF => $"/q /s \"{filePath}\"",
                _ => throw new ArgumentException("Invalid file type"),
            };

            // Start the process with LGPO.exe
            ProcessStartInfo processInfo = new()
            {
                // If the path to LGPO.exe was provided then use it, otherwise use the global variable
                FileName = LGPOExePath ?? GlobalVars.LGPOExe,
                Arguments = commandArgs,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            try
            {
                using Process? process = Process.Start(processInfo);

                // Capture and output the process result
                string output = process!.StandardOutput.ReadToEnd();
                process.WaitForExit();
                Logger.LogMessage(output, LogTypeIntel.Information);

            }
            catch (Exception ex)
            {
                Logger.LogMessage($"An error occurred: {ex.Message}", LogTypeIntel.Error);
            }
        }
    }
}
