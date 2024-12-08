using AppControlManager.Logging;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace AppControlManager
{
    public static class SignToolHelper
    {
        /// <summary>
        /// Invokes SignTool.exe to sign a Code Integrity Policy file.
        /// </summary>
        /// <param name="ciPath"></param>
        /// <param name="signToolPathFinal"></param>
        /// <param name="certCN"></param>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="InvalidOperationException"></exception>
        public static void Sign(FileInfo ciPath, FileInfo signToolPathFinal, string certCN)
        {
            // Validate inputs
            ArgumentNullException.ThrowIfNull(ciPath);
            ArgumentNullException.ThrowIfNull(signToolPathFinal);
            if (string.IsNullOrEmpty(certCN)) throw new ArgumentException("Certificate Common Name cannot be null or empty.", nameof(certCN));

            // Build the arguments for the process
            string arguments = $"sign /v /n \"{certCN}\" /p7 . /p7co 1.3.6.1.4.1.311.79.1 /fd certHash \"{ciPath.Name}\"";

            // Set up the process start info
            ProcessStartInfo startInfo = new()
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
            using Process process = new() { StartInfo = startInfo };
            _ = process.Start();

            // Wait for the process to exit
            process.WaitForExit();

            // Read the output and error streams
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();

            // Log the output and error
            Logger.Write(output);

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


        /// <summary>
        /// Downloads the latest version of the microsoft.windows.sdk.buildtools NuGet package.
        /// Extracts the SignTool.exe from it and returns the path to it.
        /// Copies it to the User Configurations directory.
        /// </summary>
        private static string Download()
        {
            DirectoryInfo stagingArea = StagingArea.NewStagingArea("GetSignTool");

            using HttpClient client = new();

            string packageName = "microsoft.windows.sdk.buildtools"; // Important that this stays all lower case

            Logger.Write("Finding the latest version of the microsoft.windows.sdk.buildtools package from NuGet");

            // Get the list of versions
            Uri versionsUrl = new($"https://api.nuget.org/v3-flatcontainer/{packageName}/index.json");
            string versionsResponse = client.GetStringAsync(versionsUrl).GetAwaiter().GetResult();

            // Parse the JSON to get the latest version
            JsonDocument versionsJson = JsonDocument.Parse(versionsResponse);
            JsonElement versions = versionsJson.RootElement.GetProperty("versions");
            string? latestVersion = versions[versions.GetArrayLength() - 1].GetString() ?? throw new InvalidOperationException("Failed to get the latest version of the package.");

            // Construct the download link for the latest version's .nupkg
            Uri downloadUrl = new($"https://api.nuget.org/v3-flatcontainer/{packageName}/{latestVersion}/{packageName}.{latestVersion}.nupkg");

            Logger.Write($"Downloading the latest .nupkg package file version '{latestVersion}' from the following URL: {downloadUrl}");

            // Download the .nupkg file
            string filePath = Path.Combine(stagingArea.FullName, $"{packageName}.{latestVersion}.nupkg");
            using (Stream downloadStream = client.GetStreamAsync(downloadUrl).GetAwaiter().GetResult())
            using (FileStream fileStream = new(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                downloadStream.CopyTo(fileStream);
            }

            Logger.Write($"Downloaded package to {filePath}");

            // Extract the .nupkg file
            string extractPath = Path.Combine(stagingArea.FullName, "extracted");
            ZipFile.ExtractToDirectory(filePath, extractPath);

            Logger.Write($"Extracted package to {extractPath}");


            string binDirectoryPath = Path.Combine(extractPath, "bin");
            // Get the directory that has the version, since it varies we need to get it implicitly
            string[] versionDirectories = Directory.GetDirectories(binDirectoryPath);

            if (versionDirectories.Length == 0)
            {
                throw new DirectoryNotFoundException("No version directories found in 'bin'.");
            }

            // There should be only one
            string versionDirectory = versionDirectories.First();
            string signtoolPath = Path.Combine(versionDirectory, "x64", "signtool.exe");

            if (!File.Exists(signtoolPath))
            {
                throw new FileNotFoundException("signtool.exe not found in the expected path.");
            }

            // The final path that is in the User configurations directory and will be returned and saved in User configs
            string finalSignToolPath = Path.Combine(GlobalVars.UserConfigDir, "SignTool.exe");

            File.Copy(signtoolPath, finalSignToolPath, true);

            Directory.Delete(stagingArea.ToString(), true);

            Logger.Write($"Path to signtool.exe: {finalSignToolPath}");

            return finalSignToolPath;

        }


        /// <summary>
        /// Verifies if the SignTool.exe is of a version greater than one specified in the method
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        private static bool Verify(string filePath)
        {
            try
            {
                FileVersionInfo fileInfo = FileVersionInfo.GetVersionInfo(filePath);
                return (new Version(fileInfo.ProductVersion!) > new Version("10.0.22621.2428"));
            }
            catch
            {
                return false;
            }
        }



        /// <summary>
        /// Returns the architecture of the current OS
        /// </summary>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        private static string GetArchitecture()
        {
            if (RuntimeInformation.OSArchitecture is Architecture.X64)
            {
                return "x64";
            }
            else if (RuntimeInformation.OSArchitecture is Architecture.Arm64)
            {
                return "arm64";
            }
            else
            {
                throw new InvalidOperationException("Only X64 and ARM64 platforms are supported.");
            }
        }



        /// <summary>
        /// Gets the path to SignTool.exe and verifies it to make sure it's valid
        /// If the SignTool.exe path is not provided by parameter, it will try to detect it automatically by checking if Windows SDK is installed
        /// If the SignTool.exe path is not provided by parameter and it could not be detected automatically, it will try to download it from NuGet
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public static string GetSignToolPath(string? filePath = null)
        {
            // The path to return at the end
            string? signToolPath = null;

            // If Sign tool path wasn't provided by parameter or it doesn't exist on the file system, try to detect it automatically
            if (string.IsNullOrWhiteSpace(filePath) && !Path.Exists(filePath))
            {

                try
                {

                    Logger.Write("SignTool.exe path was not provided by parameter, trying to detect it automatically");

                    string baseDir = @"C:\Program Files (x86)\Windows Kits\10\bin";
                    string targetArchitecture = GetArchitecture();

                    // Get the directory with the highest version in its name
                    string? latestSigntoolPath = Directory.GetDirectories(baseDir)
                        .Select(dir => new DirectoryInfo(dir))
                        .Where(dir => Version.TryParse(Path.GetFileName(dir.Name), out _)) // Ensure directory is a version
                        .OrderByDescending(dir => new Version(dir.Name)) // Order by version
                        .First().ToString(); // Get the highest version

                    if (latestSigntoolPath is not null)
                    {
                        // Construct the full SignTool.exe path
                        string constructedFinalPath = Path.Combine(latestSigntoolPath, targetArchitecture, "signtool.exe");

                        // If it checks out, assign it to the output variable
                        if (Verify(constructedFinalPath))
                        {
                            signToolPath = constructedFinalPath;
                            Logger.Write($"Successfully detected the SignTool.exe on the system: {constructedFinalPath}");
                        }
                    }

                }
                catch (Exception ex)
                {
                    Logger.Write($"Failed to detect SignTool.exe path automatically: {ex.Message}");
                }

            }

            // If Sign tool path was provided by parameter, use it
            else
            {
                Logger.Write("SignTool.exe path was provided by parameter");

                if (Verify(filePath))
                {
                    Logger.Write("The provided SignTool.exe is valid");
                    signToolPath = filePath;
                }
                else
                {
                    Logger.Write("The provided SignTool.exe is not valid");
                }
            }

            // Download the SignTool.exe if it's still null
            signToolPath ??= Download();

            Logger.Write($"Setting the SignTool path in the common user configurations to: {signToolPath}");
            _ = UserConfiguration.Set(SignToolCustomPath: signToolPath);

            return signToolPath;
        }
    }
}
