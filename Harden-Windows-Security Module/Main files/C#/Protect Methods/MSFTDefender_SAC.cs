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

namespace HardenWindowsSecurity;

public static partial class MicrosoftDefender
{
	/// <summary>
	/// Turns on Smart App Control
	/// </summary>
	public static void MSFTDefender_SAC()
	{
		Logger.LogMessage("Turning on Smart App Control", LogTypeIntel.Information);

		RegistryEditor.EditRegistry(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Policy", "VerifiedAndReputablePolicyState", "1", "DWORD", "AddOrModify");

		// Let the optional diagnostic data be enabled automatically
		GlobalVars.ShouldEnableOptionalDiagnosticData = true;
	}
}
