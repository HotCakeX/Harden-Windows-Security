using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

#nullable enable

namespace HardenWindowsSecurity
{
    public class AsyncDownloader
    {
        // HttpClient instance to be used and re-used for downloading files
        private static readonly HttpClient _httpClient = new HttpClient();

        // Dictionary to map URLs to their local file paths
        private static readonly Dictionary<string, string> fileDictionary = new Dictionary<string, string>
        {
            {
                "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/Windows%2011%20v23H2%20Security%20Baseline.zip",
                "MicrosoftSecurityBaseline.zip"
            },
            {
                "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/Microsoft%20365%20Apps%20for%20Enterprise%202306.zip",
                "Microsoft365SecurityBaseline.zip"
            },
            {
                "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip",
                "LGPO.zip"
            }
        };

        /// <summary>
        /// Asynchronously starts the file download process for multiple files.
        /// outputs proper errors and data to verify success/failure.
        /// </summary>
        /// <param name="workingDir">The directory where files will be downloaded.</param>
        /// <param name="OnlyLGPO">If used, only LGPO will be downloaded</param>
        /// <exception cref="DirectoryNotFoundException">Thrown if the specified directory does not exist.</exception>
        private static async Task StartFileDownloadAsync(bool OnlyLGPO)
        {
            // Check if the working directory exists; throw an exception if it does not
            if (!Directory.Exists(HardenWindowsSecurity.GlobalVars.WorkingDir))
            {
                throw new DirectoryNotFoundException($"The directory '{HardenWindowsSecurity.GlobalVars.WorkingDir}' does not exist.");
            }

            List<Task> tasks = new List<Task>();

            // Start asynchronous download for each file
            foreach (var kvp in fileDictionary)
            {

                // if OnlyLGPO was used/is true then skip files that are not LGPO.zip in order to only download the LGPO.zip
                if (OnlyLGPO == true && !string.Equals(kvp.Value, "LGPO.zip", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                Logger.LogMessage($"Downloading {kvp.Value}", LogTypeIntel.Information);

                string url = kvp.Key;
                string fileName = kvp.Value;
                string filePath = Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, fileName);
                tasks.Add(DownloadFileAsync(url, filePath));
            }

            try
            {
                // Wait for all download tasks to complete
                await Task.WhenAll(tasks);
            }
            catch (Exception)
            {
                // Re-throw the exception to propagate it further if needed
                throw;
            }
        }

        /// <summary>
        /// Asynchronously downloads a file from the specified URL to the specified file path.
        /// </summary>
        /// <param name="url">The URL of the file to download.</param>
        /// <param name="filePath">The local file path where the downloaded file will be saved.</param>
        /// <exception cref="Exception">Thrown if downloading or saving the file fails.</exception>
        private static async Task DownloadFileAsync(string url, string filePath)
        {
            try
            {
                // Send GET request to download the file
                using (var response = await _httpClient.GetAsync(url))
                {
                    // Ensure the response indicates success
                    response.EnsureSuccessStatusCode();

                    // Open file stream to save the downloaded content
                    using (FileStream fs = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
                    {
                        // Copy the content from the HTTP response to the file stream
                        await response.Content.CopyToAsync(fs);
                    }
                }
            }
            catch (Exception ex)
            {
                // Throw a new exception with a meaningful message indicating the failure
                throw new Exception($"Failed to download {url}: {ex.Message}", ex);
            }
        }

        // To get the Security baselines directories that have dynamic names by getting the first directory after the base path
        // e.g., inputting this in Get-ChildItem "C:\Users\HotCakeX\AppData\Local\Temp\HardeningXStuff\MicrosoftSecurityBaseline\*\"
        // would show these "C:\Users\HotCakeX\AppData\Local\Temp\HardeningXStuff\MicrosoftSecurityBaseline\Windows 11 v23H2 Security Baseline"
        // This method does the same thing but in C#
        private static string GetSubDirectoryName(string basePath)
        {
            if (Directory.Exists(basePath))
            {
                string[] subDirectories = Directory.GetDirectories(basePath);
                if (subDirectories.Length > 0)
                {
                    // Assuming you want the first subdirectory found
                    string fullPath = subDirectories[0];
                    return fullPath;
                }
            }
            return string.Empty;
        }


        /// <summary>
        /// The main method of this class
        /// First checks if the module is running in offline mode, if not, it starts the download process asynchronously
        /// Then extracts the downloaded files to the working directory
        /// If the module is running in offline mode, it copies the files from the user provided paths to the working directory
        /// Finally, it extracts the downloaded zip files to the working directory
        /// It also copies the LGPO.exe to the Microsoft Security Baseline and Microsoft 365 Security Baseline folders
        /// so that it can be used by the PowerShell script
        /// Whether online or offline mode is used, it assigns the paths to the downloaded or copied files to the same variables
        /// Which allows seamless usage of the files regardless of whether they were downloaded or provided by the user
        /// </summary>
        /// <param name="LGPOPath"></param>
        /// <param name="MSFTSecurityBaselinesPath"></param>
        /// <param name="MSFT365AppsSecurityBaselinesPath"></param>
        /// <param name="OnlyLGPO">if true, only LGPO will be downloaded and processed</param>
        /// <exception cref="Exception"></exception>
        public static void PrepDownloadedFiles(string? LGPOPath, string? MSFTSecurityBaselinesPath, string? MSFT365AppsSecurityBaselinesPath, bool OnlyLGPO)
        {
            // Only download if offline is not used or OnlyLGPO is true meaning LGPO must be downloaded from the MSFT servers
            if (!HardenWindowsSecurity.GlobalVars.Offline || OnlyLGPO)
            {
                if (OnlyLGPO)
                {
                    Logger.LogMessage("Will only download LGPO.zip file", LogTypeIntel.Information);
                }

                // Start the download process asynchronously
                Task DownloadsTask = HardenWindowsSecurity.AsyncDownloader.StartFileDownloadAsync(OnlyLGPO);

                while (!DownloadsTask.IsCompleted)
                {
                    // Wait for 500 milliseconds before checking again
                    System.Threading.Thread.Sleep(500);
                }

                if (DownloadsTask.IsFaulted)
                {
                    // throw the exceptions
                    throw DownloadsTask.Exception;
                }
                else if (DownloadsTask.IsCompletedSuccessfully)
                {
                    Logger.LogMessage("Download completed successfully", LogTypeIntel.Information);
                }

            }

            if (OnlyLGPO == false)
            {

                if (HardenWindowsSecurity.GlobalVars.Offline)
                {
                    Logger.LogMessage("Offline Mode; Copying the Microsoft Security Baselines, Microsoft 365 Apps for Enterprise Security Baselines and LGPO files from the user provided paths to the working directory", LogTypeIntel.Information);

                    if (LGPOPath != null)
                    {
                        System.IO.File.Copy(LGPOPath, Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "LGPO.zip"), true);
                    }
                    else
                    {
                        throw new Exception("LGPOPath was empty for the offline mode.");
                    }

                    if (MSFTSecurityBaselinesPath != null)
                    {
                        System.IO.File.Copy(MSFTSecurityBaselinesPath, Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "MicrosoftSecurityBaseline.zip"), true);
                    }
                    else
                    {
                        throw new Exception("MSFTSecurityBaselinesPath was empty for the offline mode.");
                    }

                    if (MSFT365AppsSecurityBaselinesPath != null)
                    {
                        System.IO.File.Copy(MSFT365AppsSecurityBaselinesPath, Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "Microsoft365SecurityBaseline.zip"), true);
                    }
                    else
                    {
                        throw new Exception("MSFT365AppsSecurityBaselinesPath was empty for the offline mode.");
                    }

                }

                Logger.LogMessage("Extracting the downloaded zip files", LogTypeIntel.Information);

                // Extract MicrosoftSecurityBaseline.zip
                System.IO.Compression.ZipFile.ExtractToDirectory(Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "MicrosoftSecurityBaseline.zip"), Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "MicrosoftSecurityBaseline"));

                // Extract Microsoft365SecurityBaseline.zip
                System.IO.Compression.ZipFile.ExtractToDirectory(Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "Microsoft365SecurityBaseline.zip"), Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "Microsoft365SecurityBaseline"));

            }


            // Extract LGPO.zip
            System.IO.Compression.ZipFile.ExtractToDirectory(Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "LGPO.zip"), HardenWindowsSecurity.GlobalVars.WorkingDir);

            if (OnlyLGPO == false)
            {

                // capturing the Microsoft Security Baselines extracted path in a variable using GetSubDirectoryName method and storing it in a variable so that we won't need to change anything in the code other than the download link when they are updated
                HardenWindowsSecurity.GlobalVars.MicrosoftSecurityBaselinePath = GetSubDirectoryName(basePath: Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "MicrosoftSecurityBaseline"));

                // capturing the Microsoft 365 Security Baselines extracted path in a variable using GetSubDirectoryName method and storing it in a variable so that we won't need to change anything in the code other than the download link when they are updated
                HardenWindowsSecurity.GlobalVars.Microsoft365SecurityBaselinePath = GetSubDirectoryName(basePath: Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "Microsoft365SecurityBaseline"));

            }

            // Storing the LGPO.exe path in a variable
            HardenWindowsSecurity.GlobalVars.LGPOExe = Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "LGPO_30", "LGPO.exe");

            if (OnlyLGPO == false)
            {

                if (GlobalVars.MicrosoftSecurityBaselinePath == null || GlobalVars.Microsoft365SecurityBaselinePath == null)
                {
                    throw new Exception("One or more of the paths were null after extracting the zip files.");
                }

                // Copying LGPO.exe from its folder to Microsoft Security Baseline folder in order to get it ready to be used by PowerShell script
                System.IO.File.Copy(HardenWindowsSecurity.GlobalVars.LGPOExe, Path.Combine(HardenWindowsSecurity.GlobalVars.MicrosoftSecurityBaselinePath, "Scripts", "Tools", "LGPO.exe"), true);

                // Copying LGPO.exe from its folder to Microsoft Office 365 Apps for Enterprise Security Baseline folder in order to get it ready to be used by PowerShell script
                System.IO.File.Copy(HardenWindowsSecurity.GlobalVars.LGPOExe, Path.Combine(HardenWindowsSecurity.GlobalVars.Microsoft365SecurityBaselinePath, "Scripts", "Tools", "LGPO.exe"), true);

            }
        }
    }
}
