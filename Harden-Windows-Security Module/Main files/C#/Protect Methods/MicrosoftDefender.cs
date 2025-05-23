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
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace HardenWindowsSecurity;

public static partial class MicrosoftDefender
{
	/// <summary>
	/// Runs the Microsoft Defender category
	/// </summary>
	public static void Invoke()
	{

		ChangePSConsoleTitle.Set("🍁 MSFT Defender");

		Logger.LogMessage("Running the Microsoft Defender category", LogTypeIntel.Information);

		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Microsoft Defender Policies", "registry.pol"), LGPORunner.FileType.POL);

		Logger.LogMessage("Enabling Restore point scan", LogTypeIntel.Information);
		ConfigDefenderHelper.ManageMpPreference("DisableRestorePoint", false, true);

		Logger.LogMessage("Optimizing Network Protection Performance of the Microsoft Defender", LogTypeIntel.Information);
		ConfigDefenderHelper.ManageMpPreference("AllowSwitchToAsyncInspection", true, true);

		Logger.LogMessage("Setting the Network Protection to block network traffic instead of displaying a warning", LogTypeIntel.Information);
		ConfigDefenderHelper.ManageMpPreference("EnableConvertWarnToBlock", true, true);

		Logger.LogMessage("Extending brute-force protection coverage to block local network addresses.", LogTypeIntel.Information);
		ConfigDefenderHelper.ManageMpPreference("BruteForceProtectionLocalNetworkBlocking", true, true);

		Logger.LogMessage("Enabling ECS in Microsoft Defender for better product health and security.", LogTypeIntel.Information);
		ConfigDefenderHelper.ManageMpPreference("EnableEcsConfiguration", true, true);

		Logger.LogMessage("Adding OneDrive folders of all the user accounts (personal and work accounts) to the Controlled Folder Access for Ransomware Protection", LogTypeIntel.Information);
		string[] OneDrivePaths = [.. GetOneDriveDirectories.Get()];
		ConfigDefenderHelper.ManageMpPreference("ControlledFolderAccessProtectedFolders", OneDrivePaths, true);

		Logger.LogMessage("Enabling Mandatory ASLR Exploit Protection system-wide", LogTypeIntel.Information);

		_ = PowerShellExecutor.ExecuteScript("Set-ProcessMitigation -System -Enable ForceRelocateImages");


		Logger.LogMessage("Excluding GitHub Desktop Git executables from mandatory ASLR if they are found", LogTypeIntel.Information);

		List<FileInfo>? gitHubDesktopFiles = GitHubDesktopFinder.Find();

		if (gitHubDesktopFiles is not null)
		{
			IEnumerable<string> gitHubDesktopExes = gitHubDesktopFiles.Select(x => x.Name);
			ForceRelocateImagesForFiles.SetProcessMitigationForFiles([.. gitHubDesktopExes]);
		}


		Logger.LogMessage("Excluding Git executables from mandatory ASLR if they are found", LogTypeIntel.Information);

		List<FileInfo>? gitExesFiles = GitExesFinder.Find();

		if (gitExesFiles is not null)
		{
			IEnumerable<string> gitExes = gitExesFiles.Select(x => x.Name);
			ForceRelocateImagesForFiles.SetProcessMitigationForFiles([.. gitExes]);
		}

		// Skip applying process mitigations when ARM hardware detected
		if (string.Equals(Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE"), "ARM64", StringComparison.OrdinalIgnoreCase))
		{
			Logger.LogMessage("ARM64 hardware detected, skipping process mitigations due to potential incompatibilities.", LogTypeIntel.Information);
		}
		else
		{
			Logger.LogMessage("Applying the Process Mitigations", LogTypeIntel.Information);
			ProcessMitigationsApplication.Apply();
		}

		Logger.LogMessage("Turning on Data Execution Prevention (DEP) for all applications, including 32-bit programs", LogTypeIntel.Information);
		// Old method: bcdedit.exe /set '{current}' nx AlwaysOn
		// New method using PowerShell cmdlets added in Windows 11
		_ = PowerShellExecutor.ExecuteScript(@"Set-BcdElement -Element 'nx' -Type 'Integer' -Value '3'");
	}
}
