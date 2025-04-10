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
using System.Net.Http;

namespace HardenWindowsSecurity;

public static class CertificateCheckingCommands
{
	/// <summary>
	/// Checks the certificates of the system and displays ones that don't come by default in Windows
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void Invoke()
	{
		if (GlobalVars.WorkingDir is null || !Directory.Exists(GlobalVars.WorkingDir))
		{
			throw new ArgumentNullException(nameof(GlobalVars.WorkingDir), "The working directory variable is either null or the directory doesn't exist.");
		}

		ChangePSConsoleTitle.Set("🎟️ Certificates");

		Logger.LogMessage("Running the Certificate Checking category", LogTypeIntel.Information);

		string sigcheck64Path = Path.Combine(GlobalVars.WorkingDir, "sigcheck64.exe");
		Uri fileUrl = new("https://live.sysinternals.com/sigcheck64.exe");

		try
		{
			using (HttpClient client = new())
			{
				Logger.LogMessage("Downloading file...", LogTypeIntel.Information);

				// Download the file synchronously
				byte[] fileBytes = client.GetByteArrayAsync(fileUrl).GetAwaiter().GetResult();
				File.WriteAllBytes(sigcheck64Path, fileBytes);

				Logger.LogMessage($"File saved to {sigcheck64Path}", LogTypeIntel.Information);
			}

			// Make sure the file exists after download
			if (File.Exists(sigcheck64Path))
			{
				// Run the downloaded executable with the specified arguments
				Logger.LogMessage("Listing valid certificates not rooted to the Microsoft Certificate Trust List in the Local Machine Store", LogTypeIntel.Information);
				RunSigcheck(sigcheck64Path, "-tv -accepteula -nobanner");

				Logger.LogMessage("Listing valid certificates not rooted to the Microsoft Certificate Trust List in the Current User store", LogTypeIntel.Information);
				RunSigcheck(sigcheck64Path, "-tuv -accepteula -nobanner");
			}
			else
			{
				Logger.LogMessage($"File {sigcheck64Path} does not exist after download.", LogTypeIntel.Error);
			}
		}
		catch (Exception ex)
		{
			Logger.LogMessage($"An error occurred: {ex.Message}", LogTypeIntel.Error);
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

			Logger.LogMessage($"Running: {exePath} {arguments}", LogTypeIntel.Information);

			_ = process.Start();

			// Read the output (standard and error)
			string output = process.StandardOutput.ReadToEnd();
			string error = process.StandardError.ReadToEnd();

			process.WaitForExit();

			Logger.LogMessage("Output:", LogTypeIntel.Information);
			Logger.LogMessage(output, LogTypeIntel.Information);

			if (!string.IsNullOrEmpty(error))
			{
				Logger.LogMessage("Error:", LogTypeIntel.Error);
				Logger.LogMessage(error, LogTypeIntel.Error);
			}
		}
		catch (Exception ex)
		{
			Logger.LogMessage($"An error occurred while running the process: {ex.Message}", LogTypeIntel.Error);
		}
	}
}
