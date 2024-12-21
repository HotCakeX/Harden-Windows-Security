using System;

namespace HardenWindowsSecurity;

    internal static class LGPORunner
    {
        // Enum to specify the file type
        internal enum FileType
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
        internal static void RunLGPOCommand(string filePath, FileType fileType, string? LGPOExePath = null)
        {
            // Construct the command based on the file type
            string commandArgs = fileType switch
            {
                FileType.POL => $"/q /m \"{filePath}\"",
                FileType.INF => $"/q /s \"{filePath}\"",
                _ => throw new ArgumentException("Invalid file type"),
            };

            ProcessStarter.RunCommand(LGPOExePath ?? GlobalVars.LGPOExe!, commandArgs);
        }
    }
