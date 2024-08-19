using System;
using System.Diagnostics;
using System.Globalization;

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
        /// <exception cref="ArgumentException"></exception>
        public static void RunLGPOCommand(string filePath, FileType fileType)
        {
            // Construct the command based on the file type
            string commandArgs;
            switch (fileType)
            {
                case FileType.POL:
                    commandArgs = $"/q /m \"{filePath}\"";
                    break;
                case FileType.INF:
                    commandArgs = $"/q /s \"{filePath}\"";
                    break;
                default:
                    throw new ArgumentException("Invalid file type");
            }

            // Start the process with LGPO.exe
            ProcessStartInfo processInfo = new ProcessStartInfo
            {
                FileName = GlobalVars.LGPOExe,
                Arguments = commandArgs,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            try
            {
                using (Process? process = Process.Start(processInfo))
                {
                    // Capture and output the process result
                    string output = process!.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    HardenWindowsSecurity.Logger.LogMessage(output);
                }
            }
            catch (Exception ex)
            {
                HardenWindowsSecurity.Logger.LogMessage($"An error occurred: {ex.Message}");
            }
        }
    }
}
