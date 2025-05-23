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

namespace HardenWindowsSecurity;

public static partial class MiscellaneousConfigurations
{
	/// <summary>
	/// Applies the Miscellaneous category security measures
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void Invoke()
	{
		ChangePSConsoleTitle.Set("🥌 Miscellaneous");

		Logger.LogMessage("Running the Miscellaneous Configurations category", LogTypeIntel.Information);

		Logger.LogMessage("Applying the Miscellaneous Configurations registry settings", LogTypeIntel.Information);

		foreach (HardeningRegistryKeys.CsvRecord Item in GlobalVars.RegistryCSVItems)
		{
			if (string.Equals(Item.Category, "Miscellaneous", StringComparison.OrdinalIgnoreCase))
			{
				RegistryEditor.EditRegistry(Item.Path, Item.Key, Item.Value, Item.Type, Item.Action);
			}
		}

		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Miscellaneous Policies", "registry.pol"), LGPORunner.FileType.POL);
		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Miscellaneous Policies", "GptTmpl.inf"), LGPORunner.FileType.INF);

		Logger.LogMessage("""Adding all Windows users to the "Hyper-V Administrators" security group to be able to use Hyper-V and Windows Sandbox""", LogTypeIntel.Information);
		List<LocalUser> AllLocalUsers = LocalUserRetriever.Get();

		foreach (LocalUser user in AllLocalUsers)
		{
			// If the user has SID and the user is enabled
			if (user.SID is not null && user.Enabled)
			{
				LocalGroupMember.Add(user.SID, "S-1-5-32-578");
			}
		}

		// Makes sure auditing for the "Other Logon/Logoff Events" subcategory under the Logon/Logoff category is enabled, doesn't touch affect any other sub-category
		// For tracking Lock screen unlocks and locks
		// auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
		// Using GUID

		Logger.LogMessage("""Enabling auditing for the "Other Logon/Logoff Events" subcategory under the Logon/Logoff category""", LogTypeIntel.Information);

		ProcessStarter.RunCommand("auditpol", "/set /subcategory:\"{0CCE921C-69AE-11D9-BED3-505054503030}\" /success:enable /failure:enable");

		// Query all Audits status
		// auditpol /get /category:*
		// Get the list of SubCategories and their associated GUIDs
		// auditpol /list /subcategory:* /r

		// Event Viewer custom views are saved in "$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views". files in there can be backed up and restored on new Windows installations.

		// Create the directory if it doesn't exist
		if (!Directory.Exists(Path.Combine(GlobalVars.SystemDrive, "ProgramData", "Microsoft", "Event Viewer", "Views", "Hardening Script")))
		{
			_ = Directory.CreateDirectory(Path.Combine(GlobalVars.SystemDrive, "ProgramData", "Microsoft", "Event Viewer", "Views", "Hardening Script"));
		}

		foreach (string file in Directory.GetFiles(Path.Combine(GlobalVars.path, "Resources", "EventViewerCustomViews")))
		{
			File.Copy(file, Path.Combine(GlobalVars.SystemDrive, "ProgramData", "Microsoft", "Event Viewer", "Views", "Hardening Script", Path.GetFileName(file)), true);
		}

		SSHConfigurations.SecureMACs();
	}
}
