using System;
using System.Diagnostics;
using System.IO;

namespace WDACConfig
{
    public static class CodeIntegritySigner
    {
        public static void InvokeCiSigning(FileInfo ciPath, FileInfo signToolPathFinal, string certCN)
        {
            // Validate inputs
            if (ciPath == null) throw new ArgumentNullException(nameof(ciPath));
            if (signToolPathFinal == null) throw new ArgumentNullException(nameof(signToolPathFinal));
            if (string.IsNullOrEmpty(certCN)) throw new ArgumentException("Certificate Common Name cannot be null or empty.", nameof(certCN));

            // Build the arguments for the process
            string arguments = $"sign /v /n \"{certCN}\" /p7 . /p7co 1.3.6.1.4.1.311.79.1 /fd certHash \"{ciPath.Name}\"";

            // Set up the process start info
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = signToolPathFinal.FullName,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = ciPath.DirectoryName // Set the working directory so that SignTool.exe will know where the .cip file is and where to save the output
            };

            // Start the process
            using (Process process = new Process { StartInfo = startInfo })
            {
                process.Start();

                // Wait for the process to exit
                process.WaitForExit();

                // Read the output and error streams
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                // Log the output and error
                WDACConfig.VerboseLogger.Write(output);

                // Check if there is any error and throw an exception if there is
                if (!string.IsNullOrEmpty(error))
                {
                    throw new InvalidOperationException($"SignTool failed with exit code {process.ExitCode}. Error: {error}");
                }

                // Check the exit code
                if (process.ExitCode != 0)
                {
                    throw new InvalidOperationException($"SignTool failed with exit code {process.ExitCode}. Error: {error}");
                }
            }
        }
    }
}
