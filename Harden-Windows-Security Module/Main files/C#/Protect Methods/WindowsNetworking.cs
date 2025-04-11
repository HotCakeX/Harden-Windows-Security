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
using System.IO;

namespace HardenWindowsSecurity;

public static partial class WindowsNetworking
{
	/// <summary>
	/// Runs the Windows Networking Hardening category
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void Invoke()
	{

		ChangePSConsoleTitle.Set("📶 Networking");

		Logger.LogMessage("Running the Windows Networking category", LogTypeIntel.Information);

		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Windows Networking Policies", "registry.pol"), LGPORunner.FileType.POL);
		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Windows Networking Policies", "GptTmpl.inf"), LGPORunner.FileType.INF);

		Logger.LogMessage("Disabling LMHOSTS lookup protocol on all network adapters", LogTypeIntel.Information);
		RegistryEditor.EditRegistry(@"Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "EnableLMHOSTS", "0", "DWORD", "AddOrModify");

		Logger.LogMessage("Applying the Windows Networking registry settings", LogTypeIntel.Information);

		foreach (HardeningRegistryKeys.CsvRecord Item in GlobalVars.RegistryCSVItems)
		{
			if (string.Equals(Item.Category, "WindowsNetworking", StringComparison.OrdinalIgnoreCase))
			{
				RegistryEditor.EditRegistry(Item.Path, Item.Key, Item.Value, Item.Type, Item.Action);
			}
		}

	}
}
