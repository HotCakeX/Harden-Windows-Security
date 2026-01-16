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

using System.Linq;
using AppControlManager.SiPolicy;

namespace AppControlManager.XMLOps;

internal static partial class CheckForAllowAll
{
	/// <summary>
	/// Takes an <see cref="SiPolicy.SiPolicy"/> and checks whether it has an allow all rule.
	/// </summary>
	/// <param name="xmlFilePath"></param>
	/// <returns></returns>
	internal static bool Check(SiPolicy.SiPolicy policyObj)
	{
		// Check if the policy contains any FileRules
		if (policyObj.FileRules is { Count: > 0 })
		{
			// Check for any Allow rule that has FileName="*"
			return policyObj.FileRules
				.OfType<Allow>()
				.Any(rule => string.Equals(rule.FileName, "*", StringComparison.OrdinalIgnoreCase));
		}

		return false;
	}
}
