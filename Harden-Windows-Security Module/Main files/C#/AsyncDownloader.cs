using System;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Collections;
using System.Collections.Generic;
using System.IO.Compression;

namespace HardeningModule
{
    public class FileDownloader
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
        /// Synchronously checks if all URLs are valid and accessible.
        /// </summary>
        /// <exception cref="Exception">Thrown if any URL is invalid or inaccessible.</exception>
        private static void CheckUrls()
        {
            foreach (var url in fileDictionary.Keys)
            {
                try
                {
                    var response = _httpClient.GetAsync(url).Result;
                    if (!response.IsSuccessStatusCode)
                    {
                        throw new Exception($"URL check failed for {url} with status code {response.StatusCode}");
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception($"Failed to access {url}: {ex.Message}", ex);
                }
            }
        }

        /// <summary>
        /// Asynchronously starts the file download process for multiple files.
        /// </summary>
        /// <param name="workingDir">The directory where files will be downloaded.</param>
        /// <exception cref="DirectoryNotFoundException">Thrown if the specified directory does not exist.</exception>
        private static async Task StartFileDownloadAsync(string workingDir)
        {
            // Check if the working directory exists; throw an exception if it does not
            if (!Directory.Exists(workingDir))
            {
                throw new DirectoryNotFoundException($"The directory '{workingDir}' does not exist.");
            }

            // Check if all URLs are valid and accessible
            // Not necessary as the async method outputs proper errors and data to verify success/failure
            // CheckUrls();

            List<Task> tasks = new List<Task>();

            // Start asynchronous download for each file
            foreach (var kvp in fileDictionary)
            {
                string url = kvp.Key;
                string fileName = kvp.Value;
                string filePath = Path.Combine(workingDir, fileName);
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

        // The main method of this class, called from the Protected-WindowsSecurity cmdlet
        // First checks if the module is running in offline mode, if not, it starts the download process asynchronously
        // Then extracts the downloaded files to the working directory
        // If the module is running in offline mode, it copies the files from the user provided paths to the working directory
        // Finally, it extracts the downloaded zip files to the working directory
        // It also copies the LGPO.exe to the Microsoft Security Baseline and Microsoft 365 Security Baseline folders
        // so that it can be used by the PowerShell script
        public static void PrepDownloadedFiles(bool GUI = false, string LGPOPath = null, string MSFTSecurityBaselinesPath = null, string MSFT365AppsSecurityBaselinesPath = null)
        {
            // Only download if offline is not used
            if (!HardeningModule.GlobalVars.Offline)
            {

                // Start the download process asynchronously
                Task DownloadsTask = HardeningModule.FileDownloader.StartFileDownloadAsync(workingDir: HardeningModule.GlobalVars.WorkingDir);

                while (!DownloadsTask.IsCompleted)
                {
                    // Wait for 500 milliseconds before checking again
                    System.Threading.Thread.Sleep(50);
                }

                if (DownloadsTask.IsFaulted)
                {
                    throw new Exception(DownloadsTask.Exception.Message);
                }
                else if (DownloadsTask.IsCompletedSuccessfully)
                {
                    //   Console.WriteLine("Download completed successfully");
                }

            }


            if (HardeningModule.GlobalVars.Offline)
            {
                // 'Offline Mode; Copying the Microsoft Security Baselines, Microsoft 365 Apps for Enterprise Security Baselines and LGPO files from the user provided paths to the working directory'

                System.IO.File.Copy(LGPOPath, Path.Combine(HardeningModule.GlobalVars.WorkingDir, "LGPO.zip"), true);

                System.IO.File.Copy(MSFTSecurityBaselinesPath, Path.Combine(HardeningModule.GlobalVars.WorkingDir, "MicrosoftSecurityBaseline.zip"), true);

                System.IO.File.Copy(MSFT365AppsSecurityBaselinesPath, Path.Combine(HardeningModule.GlobalVars.WorkingDir, "Microsoft365SecurityBaseline.zip"), true);
            }


            // Extract MicrosoftSecurityBaseline.zip
            System.IO.Compression.ZipFile.ExtractToDirectory(Path.Combine(HardeningModule.GlobalVars.WorkingDir, "MicrosoftSecurityBaseline.zip"), Path.Combine(HardeningModule.GlobalVars.WorkingDir, "MicrosoftSecurityBaseline"));

            // Extract Microsoft365SecurityBaseline.zip
            System.IO.Compression.ZipFile.ExtractToDirectory(Path.Combine(HardeningModule.GlobalVars.WorkingDir, "Microsoft365SecurityBaseline.zip"), Path.Combine(HardeningModule.GlobalVars.WorkingDir, "Microsoft365SecurityBaseline"));

            // Extract LGPO.zip
            System.IO.Compression.ZipFile.ExtractToDirectory(Path.Combine(HardeningModule.GlobalVars.WorkingDir, "LGPO.zip"), HardeningModule.GlobalVars.WorkingDir);


            // capturing the Microsoft Security Baselines extracted path in a variable using GetSubDirectoryName method and storing it in a variable so that we won't need to change anything in the code other than the download link when they are updated
            HardeningModule.GlobalVars.MicrosoftSecurityBaselinePath = GetSubDirectoryName(basePath: Path.Combine(HardeningModule.GlobalVars.WorkingDir, "MicrosoftSecurityBaseline"));

            // capturing the Microsoft 365 Security Baselines extracted path in a variable using GetSubDirectoryName method and storing it in a variable so that we won't need to change anything in the code other than the download link when they are updated
            HardeningModule.GlobalVars.Microsoft365SecurityBaselinePath = GetSubDirectoryName(basePath: Path.Combine(HardeningModule.GlobalVars.WorkingDir, "Microsoft365SecurityBaseline"));

            // Storing the LGPO.exe path in a variable
            HardeningModule.GlobalVars.LGPOExe = (Path.Combine(HardeningModule.GlobalVars.WorkingDir, "LGPO_30", "LGPO.exe"));

            // Copying LGPO.exe from its folder to Microsoft Security Baseline folder in order to get it ready to be used by PowerShell script
            System.IO.File.Copy(HardeningModule.GlobalVars.LGPOExe, Path.Combine(HardeningModule.GlobalVars.MicrosoftSecurityBaselinePath, "Scripts", "Tools", "LGPO.exe"), true);

            // Copying LGPO.exe from its folder to Microsoft Office 365 Apps for Enterprise Security Baseline folder in order to get it ready to be used by PowerShell script
            System.IO.File.Copy(HardeningModule.GlobalVars.LGPOExe, Path.Combine(HardeningModule.GlobalVars.Microsoft365SecurityBaselinePath, "Scripts", "Tools", "LGPO.exe"), true);

        }
    }
}
