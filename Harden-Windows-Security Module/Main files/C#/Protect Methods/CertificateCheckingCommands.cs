using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class CertificateCheckingCommands
    {
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.WorkingDir is null || !Directory.Exists(HardenWindowsSecurity.GlobalVars.WorkingDir))
            {
                throw new ArgumentNullException(nameof(HardenWindowsSecurity.GlobalVars.WorkingDir), "The working directory variable is either null or the directory doesn't exist.");
            }

            ChangePSConsoleTitle.Set("🎟️ Certificates");

            HardenWindowsSecurity.Logger.LogMessage("Running the Certificate Checking category", LogTypeIntel.Information);

            string sigcheck64Path = Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "sigcheck64.exe");
            string fileUrl = "https://live.sysinternals.com/sigcheck64.exe";

            try
            {
                using (HttpClient client = new())
                {
                    HardenWindowsSecurity.Logger.LogMessage("Downloading file...", LogTypeIntel.Information);

                    // Download the file synchronously
                    byte[] fileBytes = client.GetByteArrayAsync(fileUrl).GetAwaiter().GetResult();
                    File.WriteAllBytes(sigcheck64Path, fileBytes);

                    HardenWindowsSecurity.Logger.LogMessage($"File saved to {sigcheck64Path}", LogTypeIntel.Information);
                }

                // Make sure the file exists after download
                if (File.Exists(sigcheck64Path))
                {
                    // Run the downloaded executable with the specified arguments
                    HardenWindowsSecurity.Logger.LogMessage("Listing valid certificates not rooted to the Microsoft Certificate Trust List in the Local Machine Store", LogTypeIntel.Information);
                    RunSigcheck(sigcheck64Path, "-tv -accepteula -nobanner");

                    HardenWindowsSecurity.Logger.LogMessage("Listing valid certificates not rooted to the Microsoft Certificate Trust List in the Current User store", LogTypeIntel.Information);
                    RunSigcheck(sigcheck64Path, "-tuv -accepteula -nobanner");
                }
                else
                {
                    HardenWindowsSecurity.Logger.LogMessage($"File {sigcheck64Path} does not exist after download.", LogTypeIntel.Error);
                }
            }
            catch (Exception ex)
            {
                HardenWindowsSecurity.Logger.LogMessage($"An error occurred: {ex.Message}", LogTypeIntel.Error);
            }
        }

        private static void RunSigcheck(string exePath, string arguments)
        {
            try
            {
                using Process process = new();

                process.StartInfo.FileName = exePath;
                process.StartInfo.Arguments = arguments;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;

                HardenWindowsSecurity.Logger.LogMessage($"Running: {exePath} {arguments}", LogTypeIntel.Information);

                _ = process.Start();

                // Read the output (standard and error)
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                process.WaitForExit();

                HardenWindowsSecurity.Logger.LogMessage("Output:", LogTypeIntel.Information);
                HardenWindowsSecurity.Logger.LogMessage(output, LogTypeIntel.Information);

                if (!string.IsNullOrEmpty(error))
                {
                    HardenWindowsSecurity.Logger.LogMessage("Error:", LogTypeIntel.Error);
                    HardenWindowsSecurity.Logger.LogMessage(error, LogTypeIntel.Error);
                }
            }
            catch (Exception ex)
            {
                HardenWindowsSecurity.Logger.LogMessage($"An error occurred while running the process: {ex.Message}", LogTypeIntel.Error);
            }
        }
    }
}
