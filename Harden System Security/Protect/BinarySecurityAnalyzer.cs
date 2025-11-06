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

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace HardenSystemSecurity.Protect;

internal enum SecurityFeatureStatus
{
	Disabled = 0,
	Enabled = 1,
	Unavailable = 2
}

[StructLayout(LayoutKind.Sequential)]
internal struct SecurityAnalysisResult
{
	internal IntPtr BinaryPath;
	internal SecurityFeatureStatus AddressRandomization;
	internal SecurityFeatureStatus EntropyRandomization;
	internal SecurityFeatureStatus FlowProtection;
	internal int ErrorCode;
	internal IntPtr ErrorMessage;
}

[StructLayout(LayoutKind.Sequential)]
internal struct SecurityAnalysisCollection
{
	internal IntPtr AnalysisResults;
	internal int TotalCount;
}

internal sealed class BinarySecurityProfile(
	string binaryPath,
	SecurityFeatureStatus addressRandomization,
	SecurityFeatureStatus entropyRandomization,
	SecurityFeatureStatus flowProtection,
	int errorCode,
	string errorMessage
	)
{
	internal string BinaryPath => binaryPath;
	internal SecurityFeatureStatus AddressRandomization => addressRandomization;
	internal SecurityFeatureStatus EntropyRandomization => entropyRandomization;
	internal SecurityFeatureStatus FlowProtection => flowProtection;
	internal int ErrorCode => errorCode;
	internal string ErrorMessage => errorMessage;

	internal bool IsSuccess => ErrorCode == 0;
}

internal static class BinarySecurityAnalyzer
{

	private unsafe static BinarySecurityProfile[] ScanDirectory(string directoryPath)
	{
		IntPtr resultsPtr = NativeMethods.scan_directory_via_interop(directoryPath);

		if (resultsPtr == IntPtr.Zero)
		{
			return [];
		}

		try
		{
			SecurityAnalysisCollection results = *(SecurityAnalysisCollection*)resultsPtr;
			BinarySecurityProfile[] profileArray = new BinarySecurityProfile[results.TotalCount];

			for (int i = 0; i < results.TotalCount; i++)
			{
				IntPtr resultPtr = IntPtr.Add(results.AnalysisResults, i * sizeof(SecurityAnalysisResult));
				SecurityAnalysisResult result = *(SecurityAnalysisResult*)resultPtr;

				profileArray[i] = new BinarySecurityProfile
				(
					binaryPath: Marshal.PtrToStringAnsi(result.BinaryPath) ?? string.Empty,
					addressRandomization: result.AddressRandomization,
					entropyRandomization: result.EntropyRandomization,
					flowProtection: result.FlowProtection,
					errorCode: result.ErrorCode,
					errorMessage: Marshal.PtrToStringAnsi(result.ErrorMessage) ?? string.Empty
				);
			}

			return profileArray;
		}
		finally
		{
			NativeMethods.release_analysis_results(resultsPtr);
		}
	}

	/// <summary>
	/// Searches for executables in GitHub desktop and returns paths of files not compatible with the ASLR Exploit Protection.
	/// </summary>
	/// <returns></returns>
	private static List<string> FindIncompatibleGitHubDesktopExes()
	{
		string basePath = Path.Combine(GlobalVars.SystemDrive, "Users", Environment.UserName, "AppData", "Local", "GitHubDesktop");

		if (!Directory.Exists(basePath))
		{
			return [];
		}

		// Get all directories under the base path that contain "resources\app\git"
		IEnumerable<string> directories = Directory.GetDirectories(basePath, "*", SearchOption.AllDirectories)
								   .Where(d => d.Contains(@"resources\app\git", StringComparison.OrdinalIgnoreCase));

		// To store the found FileInfo objects
		List<string> fileList = [];

		foreach (string dir in directories)
		{
			BinarySecurityProfile[] scanResult = ScanDirectory(dir);

			foreach (BinarySecurityProfile item in scanResult)
			{
				// Find PEs that are not compatible with ASLR
				if (item.AddressRandomization is SecurityFeatureStatus.Disabled or SecurityFeatureStatus.Unavailable)
				{
					fileList.Add(item.BinaryPath);
				}
			}
		}

		// Return if no files were found
		if (fileList.Count is 0)
		{
			return [];
		}

		return fileList;
	}

	/// <summary>
	/// This method searches for .exe files in the specified path for Standalone Git program and returns a list file paths incompatible with the ASLR Exploit Protection.
	/// </summary>
	/// <returns></returns>
	private static List<string> FindIncompatibleGitExes()
	{
		string basePath = Path.Combine(GlobalVars.SystemDrive, "Program Files", "Git");

		if (!Directory.Exists(basePath))
		{
			return [];
		}

		// Get all directories under the base path
		string[] directories = Directory.GetDirectories(basePath, "*", SearchOption.AllDirectories);

		List<string> fileList = [];

		foreach (string dir in directories)
		{
			BinarySecurityProfile[] scanResult = ScanDirectory(dir);

			foreach (BinarySecurityProfile item in scanResult)
			{
				// Find PEs that are not compatible with ASLR
				if (item.AddressRandomization is SecurityFeatureStatus.Disabled or SecurityFeatureStatus.Unavailable)
				{
					fileList.Add(item.BinaryPath);
				}
			}
		}

		// Return if no files were found
		if (fileList.Count is 0)
		{
			return [];
		}

		return fileList;
	}

	internal static HashSet<string> GetASLRIncompatibleGitHubExes()
	{
		List<string> results = FindIncompatibleGitHubDesktopExes();
		results.AddRange(FindIncompatibleGitExes());

		Logger.Write($"Found {results.Count} Git related files incompatible with ASLR Exploit Mitigation feature:");

		foreach (string item in results)
			Logger.Write(item);

		return results.ToHashSet();
	}
}
