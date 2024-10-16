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
        private static readonly HttpClient _httpClient = new();

        // Directory paths
        private static readonly string LGPODirPath = Path.Combine(GlobalVars.WorkingDir, "LGPO_30");
        private static readonly string MicrosoftSecurityBaselineDirPath = Path.Combine(GlobalVars.WorkingDir, "MicrosoftSecurityBaseline");
        private static readonly string Microsoft365SecurityBaselineDirPath = Path.Combine(GlobalVars.WorkingDir, "Microsoft365SecurityBaseline");

        // Zip File Paths
        private static readonly string LGPOZipFilePath = Path.Combine(GlobalVars.WorkingDir, "LGPO.zip");
        private static readonly string MicrosoftSecurityBaselineZipFilePath = Path.Combine(GlobalVars.WorkingDir, "MicrosoftSecurityBaseline.zip");
        private static readonly string Microsoft365SecurityBaselineZipFilePath = Path.Combine(GlobalVars.WorkingDir, "Microsoft365SecurityBaseline.zip");

        // Dictionary to map URLs to their local file paths
        private static readonly Dictionary<string, string> fileDictionary = new()
        {
            {
                "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/Windows%2011%20v24H2%20Security%20Baseline.zip",
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
            if (!Directory.Exists(GlobalVars.WorkingDir))
            {
                throw new DirectoryNotFoundException($"The directory '{GlobalVars.WorkingDir}' does not exist.");
            }

            List<Task> tasks = [];

            // Start asynchronous download for each file
            foreach (var kvp in fileDictionary)
            {

                // if OnlyLGPO was used/is true then skip files that are not LGPO.zip in order to only download the LGPO.zip
                if (OnlyLGPO && !string.Equals(kvp.Value, "LGPO.zip", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                Logger.LogMessage($"Downloading {kvp.Value}", LogTypeIntel.Information);

                string url = kvp.Key;
                string fileName = kvp.Value;
                string filePath = Path.Combine(GlobalVars.WorkingDir, fileName);
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
                using var response = await _httpClient.GetAsync(url);

                // Ensure the response indicates success
                _ = response.EnsureSuccessStatusCode();

                // Open file stream to save the downloaded content
                using FileStream fs = new(filePath, FileMode.Create, FileAccess.Write, FileShare.None);

                // Copy the content from the HTTP response to the file stream
                await response.Content.CopyToAsync(fs);
            }
            catch (Exception ex)
            {
                // Throw a new exception with a meaningful message indicating the failure
                throw new InvalidOperationException($"Failed to download {url}: {ex.Message}", ex);
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
        /// 1) Checks if the files and directories that will be created by the method exist and if they do, attempts to remove them.
        /// 2) Checks if the program is running in offline mode, if not, it starts the download process asynchronously.
        /// 3) If the program is running in offline mode, it copies the files from the user provided paths to the working directory.
        /// 4) Extracts the downloaded zip files to the working directory.
        /// 5) Copies the LGPO.exe to the Microsoft Security Baseline and Microsoft 365 Security Baseline directories so that it can be used by the Microsoft-provided PowerShell scripts in the baselines.
        /// Whether online or offline mode is used, the method assigns the paths to the downloaded or copied files to the same variables.
        /// Which allows seamless usage of the files regardless of whether they were downloaded or provided by the user.
        /// </summary>
        /// <param name="LGPOPath"></param>
        /// <param name="MSFTSecurityBaselinesPath"></param>
        /// <param name="MSFT365AppsSecurityBaselinesPath"></param>
        /// <param name="OnlyLGPO">if true, only LGPO will be downloaded and processed</param>
        /// <exception cref="Exception"></exception>
        public static void PrepDownloadedFiles(string? LGPOPath, string? MSFTSecurityBaselinesPath, string? MSFT365AppsSecurityBaselinesPath, bool OnlyLGPO)
        {

            #region These steps ensure no error is thrown when the files are later extracted and so on

            // Check and delete files if they exist
            if (File.Exists(LGPOZipFilePath)) File.Delete(LGPOZipFilePath);
            if (File.Exists(MicrosoftSecurityBaselineZipFilePath)) File.Delete(MicrosoftSecurityBaselineZipFilePath);
            if (File.Exists(Microsoft365SecurityBaselineZipFilePath)) File.Delete(Microsoft365SecurityBaselineZipFilePath);

            // Check and delete folders if they exist
            if (Directory.Exists(LGPODirPath)) Directory.Delete(LGPODirPath, true);
            if (Directory.Exists(MicrosoftSecurityBaselineDirPath)) Directory.Delete(MicrosoftSecurityBaselineDirPath, true);
            if (Directory.Exists(Microsoft365SecurityBaselineDirPath)) Directory.Delete(Microsoft365SecurityBaselineDirPath, true);

            #endregion


            // Only download if offline is not used or OnlyLGPO is true meaning LGPO must be downloaded from the MSFT servers
            if (!GlobalVars.Offline || OnlyLGPO)
            {
                if (OnlyLGPO)
                {
                    Logger.LogMessage("Will only download LGPO.zip file", LogTypeIntel.Information);
                }

                // Start the download process asynchronously
                Task DownloadsTask = AsyncDownloader.StartFileDownloadAsync(OnlyLGPO);

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

            if (!OnlyLGPO)
            {

                if (GlobalVars.Offline)
                {
                    Logger.LogMessage("Offline Mode; Copying the Microsoft Security Baselines, Microsoft 365 Apps for Enterprise Security Baselines and LGPO files from the user provided paths to the working directory", LogTypeIntel.Information);

                    if (LGPOPath is not null)
                    {
                        System.IO.File.Copy(LGPOPath, LGPOZipFilePath, true);
                    }
                    else
                    {
                        throw new InvalidOperationException("LGPOPath was empty for the offline mode.");
                    }

                    if (MSFTSecurityBaselinesPath is not null)
                    {
                        System.IO.File.Copy(MSFTSecurityBaselinesPath, MicrosoftSecurityBaselineZipFilePath, true);
                    }
                    else
                    {
                        throw new InvalidOperationException("MSFTSecurityBaselinesPath was empty for the offline mode.");
                    }

                    if (MSFT365AppsSecurityBaselinesPath is not null)
                    {
                        System.IO.File.Copy(MSFT365AppsSecurityBaselinesPath, Microsoft365SecurityBaselineZipFilePath, true);
                    }
                    else
                    {
                        throw new InvalidOperationException("MSFT365AppsSecurityBaselinesPath was empty for the offline mode.");
                    }

                }

                Logger.LogMessage("Extracting the downloaded zip files", LogTypeIntel.Information);

                // Extract MicrosoftSecurityBaseline.zip
                System.IO.Compression.ZipFile.ExtractToDirectory(MicrosoftSecurityBaselineZipFilePath, MicrosoftSecurityBaselineDirPath);

                // Extract Microsoft365SecurityBaseline.zip
                System.IO.Compression.ZipFile.ExtractToDirectory(Microsoft365SecurityBaselineZipFilePath, Microsoft365SecurityBaselineDirPath);

            }


            // Extract LGPO.zip
            System.IO.Compression.ZipFile.ExtractToDirectory(LGPOZipFilePath, GlobalVars.WorkingDir);

            if (!OnlyLGPO)
            {

                // capturing the Microsoft Security Baselines extracted path in a variable using GetSubDirectoryName method and storing it in a variable so that we won't need to change anything in the code other than the download link when they are updated
                GlobalVars.MicrosoftSecurityBaselinePath = GetSubDirectoryName(basePath: MicrosoftSecurityBaselineDirPath);

                // capturing the Microsoft 365 Security Baselines extracted path in a variable using GetSubDirectoryName method and storing it in a variable so that we won't need to change anything in the code other than the download link when they are updated
                GlobalVars.Microsoft365SecurityBaselinePath = GetSubDirectoryName(basePath: Microsoft365SecurityBaselineDirPath);

            }

            // Storing the LGPO.exe path in a variable
            GlobalVars.LGPOExe = Path.Combine(LGPODirPath, "LGPO.exe");

            if (!OnlyLGPO)
            {

                if (GlobalVars.MicrosoftSecurityBaselinePath is null || GlobalVars.Microsoft365SecurityBaselinePath is null)
                {
                    throw new InvalidOperationException("One or more of the paths were null after extracting the zip files.");
                }

                // Copying LGPO.exe from its folder to Microsoft Security Baseline folder in order to get it ready to be used by PowerShell script
                System.IO.File.Copy(GlobalVars.LGPOExe, Path.Combine(GlobalVars.MicrosoftSecurityBaselinePath, "Scripts", "Tools", "LGPO.exe"), true);

                // Copying LGPO.exe from its folder to Microsoft Office 365 Apps for Enterprise Security Baseline folder in order to get it ready to be used by PowerShell script
                System.IO.File.Copy(GlobalVars.LGPOExe, Path.Combine(GlobalVars.Microsoft365SecurityBaselinePath, "Scripts", "Tools", "LGPO.exe"), true);

            }
        }
    }
}
