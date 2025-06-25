// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text.Json;
using AppControlManager.Main;

namespace AppControlManager.Others;

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

		Logger.Write(
			string.Format(
				GlobalVars.GetStr("SigningCodeIntegrityPolicyFileMessage"),
				ciPath.FullName
			)
		);

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

		// Log the output
		Logger.Write(output);

		// Check if there is any error and throw an exception if there is
		if (!string.IsNullOrEmpty(error))
		{
			throw new InvalidOperationException(
				string.Format(
					GlobalVars.GetStr("SignToolFailedWithExitCodeErrorMessage"),
					process.ExitCode,
					error
				)
			);
		}

		// Check the exit code
		if (process.ExitCode != 0)
		{
			throw new InvalidOperationException(
				string.Format(
					GlobalVars.GetStr("SignToolFailedWithExitCodeErrorMessage"),
					process.ExitCode,
					error
				)
			);
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

		const string packageName = "microsoft.windows.sdk.buildtools"; // Important that this stays all lower case

		Logger.Write(
			GlobalVars.GetStr("FindingLatestVersionOfBuildToolsPackageMessage")
		);

		// Get the list of versions
		Uri versionsUrl = new($"https://api.nuget.org/v3-flatcontainer/{packageName}/index.json");
		string versionsResponse = client.GetStringAsync(versionsUrl).GetAwaiter().GetResult();

		// Parse the JSON to get the latest version
		JsonDocument versionsJson = JsonDocument.Parse(versionsResponse);
		JsonElement versions = versionsJson.RootElement.GetProperty("versions");
		string? latestVersion = versions[versions.GetArrayLength() - 1].GetString() ?? throw new InvalidOperationException("Failed to get the latest version of the package.");

		// Construct the download link for the latest version's .nupkg
		Uri downloadUrl = new($"https://api.nuget.org/v3-flatcontainer/{packageName}/{latestVersion}/{packageName}.{latestVersion}.nupkg");

		Logger.Write(
			string.Format(
				GlobalVars.GetStr("DownloadingLatestNuPkgVersionMessage"),
				latestVersion,
				downloadUrl
			)
		);

		// Download the .nupkg file
		string filePath = Path.Combine(stagingArea.FullName, $"{packageName}.{latestVersion}.nupkg");
		using (Stream downloadStream = client.GetStreamAsync(downloadUrl).GetAwaiter().GetResult())
		using (FileStream fileStream = new(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
		{
			downloadStream.CopyTo(fileStream);
		}

		Logger.Write(
			string.Format(
				GlobalVars.GetStr("DownloadedNuPkgToMessage"),
				filePath
			)
		);

		// Extract the .nupkg file
		string extractPath = Path.Combine(stagingArea.FullName, "extracted");
		ZipFile.ExtractToDirectory(filePath, extractPath, true);

		Logger.Write(
			string.Format(
				GlobalVars.GetStr("ExtractedPackageToMessage"),
				extractPath
			)
		);


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

		Logger.Write(
			string.Format(
				GlobalVars.GetStr("PathToSignToolMessage"),
				finalSignToolPath
			)
		);

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
				Logger.Write(
					GlobalVars.GetStr("SignToolPathNotProvidedByParameterMessage")
				);

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
						Logger.Write(
							string.Format(
								GlobalVars.GetStr("SuccessfullyDetectedSignToolOnSystemMessage"),
								constructedFinalPath
							)
						);
					}
				}
			}
			catch (Exception ex)
			{
				Logger.Write(
					string.Format(
						GlobalVars.GetStr("FailedToDetectSignToolPathAutomaticallyMessage"),
						ex.Message
					)
				);
			}
		}
		// If Sign tool path was provided by parameter, use it
		else
		{
			Logger.Write(
				GlobalVars.GetStr("SignToolPathProvidedByParameterMessage")
			);

			if (Verify(filePath))
			{
				Logger.Write(
					GlobalVars.GetStr("ProvidedSignToolIsValidMessage")
				);
				signToolPath = filePath;
			}
			else
			{
				Logger.Write(
					GlobalVars.GetStr("ProvidedSignToolIsNotValidMessage")
				);
			}
		}

		// Download the SignTool.exe if it's still null
		signToolPath ??= Download();

		Logger.Write(
			string.Format(
				GlobalVars.GetStr("SettingSignToolPathInUserConfigMessage"),
				signToolPath
			)
		);
		_ = UserConfiguration.Set(SignToolCustomPath: signToolPath);

		return signToolPath;
	}
}
