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

using System.IO;

namespace AppControlManager.Others;

internal static class SnapBackGuarantee
{
	private static readonly string savePath = Path.Combine(GlobalVars.UserConfigDir, "EnforcedModeSnapBack.cmd");

	/// <summary>
	/// A method that arms the system with a snapback guarantee in case of a reboot during the base policy enforcement process.
	/// This will help prevent the system from being stuck in audit mode in case of a power outage or a reboot during the base policy enforcement process.
	/// </summary>
	/// <param name="path">The path to the EnforcedMode.cip file that will be used to revert the base policy to enforced mode in case of a reboot.</param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void Create(string path)
	{

		if (string.IsNullOrWhiteSpace(path))
		{
			throw new ArgumentNullException(nameof(path));
		}

		Logger.Write(
			   GlobalVars.GetStr("CreatingScheduledTaskForSnapBackGuaranteeMessage")
		   );

		const string command = """
/c ""C:\Program Files\AppControl Manager\EnforcedModeSnapBack.cmd""
""";


		string args = $"""
scheduledtasks --name "EnforcedModeSnapBack" --exe "cmd.exe" --arg "{command}" --description "Created by AppControl Manager - Allow New Apps page - Ensures that the enforced mode policy will be deployed in case of a sudden power loss or system restart" --author "AppControl Manager" --logon 2 --runlevel 1 --sid "S-1-5-18" --allowstartifonbatteries --dontstopifgoingonbatteries --startwhenavailable --restartcount 2 --restartinterval PT3M --priority 0 --trigger "type=logon;" --useunifiedschedulingengine true --executiontimelimit PT4M --multipleinstancespolicy 2 --allowhardterminate 1 --hidden
""";

		_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, args);


		// Saving the EnforcedModeSnapBack.cmd file to the UserConfig directory in Program Files
		// It contains the instructions to revert the base policy to enforced mode

		string contentToBeSaved = $@"
REM Deploying the Enforced Mode SnapBack CI Policy
CiTool --update-policy ""{path}"" -json
REM Deleting the Scheduled task responsible for running this CMD file
schtasks /Delete /TN EnforcedModeSnapBack /F
REM Deleting the CI Policy file
del /f /q ""{path}""
REM Deleting this CMD file itself
del ""%~f0""
";

		// Write to file (overwrite if exists)
		File.WriteAllText(savePath, contentToBeSaved);

		// An alternative way to do this which is less reliable because RunOnce key can be deleted by 3rd party programs during installation etc.
	}

	/// <summary>
	/// Removes the SnapBack guarantee scheduled task and the related .bat file
	/// </summary>
	internal static void Remove()
	{
		const string arg = """
scheduledtasks --delete --name EnforcedModeSnapBack
""";

		_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, arg);

		if (Path.Exists(savePath))
		{
			File.Delete(savePath);
		}
	}
}
