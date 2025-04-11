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

internal static class PolicyToCIPConverter
{
	/// <summary>
	/// Converts a XML policy file to CIP binary file using the ConvertFrom-CIPolicy cmdlet of the ConfigCI module
	/// </summary>
	/// <param name="XmlFilePath"></param>
	/// <param name="BinaryFilePath"></param>
	internal static void Convert(string XmlFilePath, string BinaryFilePath)
	{

		// Escape the output policy path for PowerShell
		string escapedXMLFile = $"\\\"{XmlFilePath}\\\"";

		// Escape the output policy path for PowerShell
		string escapedOutputCIP = $"\\\"{BinaryFilePath}\\\"";

		// Construct the PowerShell script
		string script = $"ConvertFrom-CIPolicy -XmlFilePath {escapedXMLFile} -BinaryFilePath {escapedOutputCIP}";

		Logger.LogMessage($"PowerShell code that will be executed: {script}", LogTypeIntel.Information);

		// Execute the command
		ProcessStarter.RunCommand("powershell.exe", $"-NoProfile -Command \"{script}\"");
	}

}
