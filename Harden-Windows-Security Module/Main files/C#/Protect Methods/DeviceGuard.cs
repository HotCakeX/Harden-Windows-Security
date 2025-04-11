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

public static partial class DeviceGuard
{

	/// <summary>
	/// Applies the Device Guard category policies
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void Invoke()
	{

		ChangePSConsoleTitle.Set("🖥️ Device Guard");

		Logger.LogMessage("Running the Device Guard category", LogTypeIntel.Information);

		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Device Guard Policies", "registry.pol"), LGPORunner.FileType.POL);

		Logger.LogMessage("Applying the Device Guard registry settings", LogTypeIntel.Information);

		foreach (HardeningRegistryKeys.CsvRecord Item in GlobalVars.RegistryCSVItems)
		{
			if (string.Equals(Item.Category, "DeviceGuard", StringComparison.OrdinalIgnoreCase))
			{
				RegistryEditor.EditRegistry(Item.Path, Item.Key, Item.Value, Item.Type, Item.Action);
			}
		}

	}
}
