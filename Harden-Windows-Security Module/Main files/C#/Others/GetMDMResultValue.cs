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
using System.Linq;

namespace HardenWindowsSecurity;

internal static class GetMDMResultValue
{
	/// <summary>
	/// Get the value of a specific MDM result in a resilient way so if the property or value don't exist then return false instead of throwing errors
	/// </summary>
	/// <param name="propertyName">The Name of the MDM object to use the filter the results by</param>
	/// <param name="comparisonValue">This value will be used in comparison with the value property of the MDM object we find after filtering</param>
	/// <returns></returns>
	internal static bool Get(string propertyName, string comparisonValue)
	{
		try
		{
			// Ensure the list is not null
			if (GlobalVars.MDMResults is null)
			{
				return false;
			}

			// Query the list
			string? result = GlobalVars.MDMResults
				.Where(element => element is not null && element.Name == propertyName)
				.Select(element => element.Value)
				.FirstOrDefault();

			// Perform the comparison
			if (result is not null && result.Equals(comparisonValue, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}

			return false;
		}
		catch
		{
			return false;
		}
	}
}
