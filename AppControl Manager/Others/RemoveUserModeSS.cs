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

namespace AppControlManager.Others;

internal static class RemoveUserModeSS
{
	/// <summary>
	/// Removes the User-mode signing scenario block completely
	/// </summary>
	/// <param name="filePath">The path to the XML file</param>
	/// <exception cref="Exception"></exception>
	internal static void Remove(string filePath)
	{
		// Instantiate the policy
		SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(filePath, null);

		// Convert the array to a list for easy manipulation
		List<SiPolicy.SigningScenario> signingScenarios = [.. policyObj.SigningScenarios];

		// Remove any signing scenario with the value 12 representing User-Mode
		_ = signingScenarios.RemoveAll(scenario => string.Equals(scenario.Value.ToString(), "12", StringComparison.OrdinalIgnoreCase));

		// Convert the list back to array in order to save it in the policyObj
		policyObj.SigningScenarios = [.. signingScenarios];

		// Save the changes back to the file
		SiPolicy.Management.SavePolicyToFile(policyObj, filePath);
	}
}
