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
using System.Collections.Generic;
using System.Linq;

namespace HardenWindowsSecurity;

internal static class PropertyHelper
{
	/// <summary>
	/// Get the value of a property from a dynamic object
	/// All of the queries made to the dynamic objects GlobalVars.MDAVConfigCurrent or GlobalVars.MDAVPreferencesCurrent
	/// Must go through this method so that their value is acquired properly and in case of nonexistence, null is returned, otherwise direct access to the nonexistent property would lead to error.
	/// If the code that calls this method tries to compare its value using string.Equals, Convert.ToInt or something similar, a default value must be supplied to it via ?? string.Empty or ?? ushort.MaxValue or ?? false/true when this method returns null.
	/// </summary>
	/// <param name="obj"></param>
	/// <param name="propertyName"></param>
	/// <returns></returns>
	internal static object? GetPropertyValue(dynamic obj, string propertyName)
	{
		// Convert dynamic object to IDictionary<string, object> to access properties and check for nulls
		if (obj is IDictionary<string, object> dictionary)
		{
			// Find the key in a case-insensitive manner
			string? key = dictionary.Keys.FirstOrDefault(k => string.Equals(k, propertyName, StringComparison.OrdinalIgnoreCase));
			if (key is not null)
			{
				var value = dictionary[key];

				// Check if the value is null, empty, or whitespace
				if (value is not null && !(value is string str && string.IsNullOrWhiteSpace(str)))
				{
					return value;
				}
			}
		}

		// Return null if the property does not exist or is null, empty, or whitespace
		return null;
	}
}
