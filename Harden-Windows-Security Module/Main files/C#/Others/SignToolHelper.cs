using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace HardenWindowsSecurity;

internal static class SignToolHelper
{
	/// <summary>
	/// Invokes SignTool.exe to sign a Code Integrity Policy file.
	/// </summary>
	/// <param name="ciPath"></param>
	/// <param name="signToolPathFinal"></param>
	/// <param name="certCN"></param>
	/// <exception cref="ArgumentException"></exception>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void Sign(FileInfo ciPath, FileInfo signToolPathFinal, string certCN)
	{
		// Build the arguments for the process
		string arguments = $"sign /v /n \"{certCN}\" /p7 . /p7co 1.3.6.1.4.1.311.79.1 /fd certHash \"{ciPath.Name}\"";

		Logger.LogMessage($"Signing {ciPath.FullName}", LogTypeIntel.Information);

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
		Logger.LogMessage(output, LogTypeIntel.Information);

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
		using HttpClient client = new();

		string packageName = "microsoft.windows.sdk.buildtools"; // Important that this stays all lower case

		Logger.LogMessage("Finding the latest version of the microsoft.windows.sdk.buildtools package from NuGet", LogTypeIntel.Information);

		// Get the list of versions
		Uri versionsUrl = new($"https://api.nuget.org/v3-flatcontainer/{packageName}/index.json");
		string versionsResponse = client.GetStringAsync(versionsUrl).GetAwaiter().GetResult();

		// Parse the JSON to get the latest version
		JsonDocument versionsJson = JsonDocument.Parse(versionsResponse);
		JsonElement versions = versionsJson.RootElement.GetProperty("versions");
		string? latestVersion = versions[versions.GetArrayLength() - 1].GetString() ?? throw new InvalidOperationException("Failed to get the latest version of the package.");

		// Construct the download link for the latest version's .nupkg
		Uri downloadUrl = new($"https://api.nuget.org/v3-flatcontainer/{packageName}/{latestVersion}/{packageName}.{latestVersion}.nupkg");

		Logger.LogMessage($"Downloading the latest .nupkg package file version '{latestVersion}' from the following URL: {downloadUrl}", LogTypeIntel.Information);

		// Download the .nupkg file
		string filePath = Path.Combine(GlobalVars.WorkingDir, $"{packageName}.{latestVersion}.nupkg");
		using (Stream downloadStream = client.GetStreamAsync(downloadUrl).GetAwaiter().GetResult())
		using (FileStream fileStream = new(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
		{
			downloadStream.CopyTo(fileStream);
		}

		Logger.LogMessage($"Downloaded package to {filePath}", LogTypeIntel.Information);

		// Extract the .nupkg file
		string extractPath = Path.Combine(GlobalVars.WorkingDir, "extracted");

		if (Directory.Exists(extractPath))
		{
			Directory.Delete(extractPath, true);
		}

		ZipFile.ExtractToDirectory(filePath, extractPath, true);

		Logger.LogMessage($"Extracted package to {extractPath}", LogTypeIntel.Information);

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

		string finalSignToolPath = Path.Combine(GlobalVars.WorkingDir, "SignTool.exe");

		File.Copy(signtoolPath, finalSignToolPath, true);

		Logger.LogMessage($"Path to signtool.exe: {finalSignToolPath}", LogTypeIntel.Information);

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
	internal static string GetSignToolPath(string? filePath = null)
	{
		// The path to return at the end
		string? signToolPath = null;

		// If Sign tool path wasn't provided by parameter or it doesn't exist on the file system, try to detect it automatically
		if (string.IsNullOrWhiteSpace(filePath) && !Path.Exists(filePath))
		{

			try
			{

				Logger.LogMessage("SignTool.exe path was not provided by parameter, trying to detect it automatically", LogTypeIntel.Information);

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
						Logger.LogMessage($"Successfully detected the SignTool.exe on the system: {constructedFinalPath}", LogTypeIntel.Information);
					}
				}

			}
			catch (Exception ex)
			{
				Logger.LogMessage($"Failed to detect SignTool.exe path automatically: {ex.Message}", LogTypeIntel.Error);
			}

		}

		// If Sign tool path was provided by parameter, use it
		else
		{
			Logger.LogMessage("SignTool.exe path was provided by parameter", LogTypeIntel.Information);

			if (Verify(filePath))
			{
				Logger.LogMessage("The provided SignTool.exe is valid", LogTypeIntel.Information);
				signToolPath = filePath;
			}
			else
			{
				Logger.LogMessage("The provided SignTool.exe is not valid", LogTypeIntel.Information);
			}
		}

		// Download the SignTool.exe if it's still null
		signToolPath ??= Download();

		Logger.LogMessage($"Setting the SignTool path in the common user configurations to: {signToolPath}", LogTypeIntel.Information);

		return signToolPath;
	}
}
