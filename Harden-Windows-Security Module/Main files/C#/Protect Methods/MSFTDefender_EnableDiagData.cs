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

public static partial class MicrosoftDefender
{
	/// <summary>
	/// Enables diagnostic data to ensure security components of the OS will be able to work as expected and communicate with the services
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void MSFTDefender_EnableDiagData()
	{
		Logger.LogMessage("Enabling Optional Diagnostic Data", LogTypeIntel.Information);

		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Microsoft Defender Policies", "Optional Diagnostic Data", "registry.pol"), LGPORunner.FileType.POL);
	}
}
