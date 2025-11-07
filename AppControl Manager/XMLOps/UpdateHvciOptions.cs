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

namespace AppControlManager.XMLOps;

internal static class UpdateHvciOptions
{
	/// <summary>
	/// Sets the HVCI option to Strict or (2) in a policy XML file
	/// </summary>
	/// <param name="filePath"></param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void Update(string filePath)
	{
		// Instantiate the policy
		SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(filePath, null);

		policyObj.HvciOptionsSpecified = true;
		policyObj.HvciOptions = 2;

		// Save the modified XML document
		SiPolicy.Management.SavePolicyToFile(policyObj, filePath);

		Logger.Write(string.Format(GlobalVars.GetStr("HVCISetToStrictSuccessMessage"), filePath));
	}
}
