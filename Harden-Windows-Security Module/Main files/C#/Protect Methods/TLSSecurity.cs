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
using Microsoft.Win32;

namespace HardenWindowsSecurity;

public static partial class TLSSecurity
{
	public static void Invoke()
	{

		ChangePSConsoleTitle.Set("🛡️ TLS");

		Logger.LogMessage("Running the TLS Security category", LogTypeIntel.Information);

		// Creating these registry keys that have forward slashes in them
		// Values are added to them in the next step using registry.csv file
		string[] cipherKeys =
		[
		"DES 56/56",       // DES 56-bit
            "RC2 40/128",      // RC2 40-bit
            "RC2 56/128",      // RC2 56-bit
            "RC2 128/128",     // RC2 128-bit
            "RC4 40/128",      // RC4 40-bit
            "RC4 56/128",      // RC4 56-bit
            "RC4 64/128",      // RC4 64-bit
            "RC4 128/128",     // RC4 128-bit
            "Triple DES 168"   // 3DES 168-bit (Triple DES 168)
		];

		foreach (string cipherKey in cipherKeys)
		{
			using RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);

			string keyPath = $@"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\{cipherKey}";

			using RegistryKey subKey = baseKey.CreateSubKey(keyPath);
			// Key is created, but no values are set
		}


		Logger.LogMessage("Applying the TLS Security registry settings", LogTypeIntel.Information);

		foreach (HardeningRegistryKeys.CsvRecord Item in GlobalVars.RegistryCSVItems)
		{
			if (string.Equals(Item.Category, "TLS", StringComparison.OrdinalIgnoreCase))
			{
				RegistryEditor.EditRegistry(Item.Path, Item.Key, Item.Value, Item.Type, Item.Action);
			}
		}

		Logger.LogMessage("Applying the TLS Security Group Policies", LogTypeIntel.Information);

		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "TLS Security", "registry.pol"), LGPORunner.FileType.POL);

	}
}
