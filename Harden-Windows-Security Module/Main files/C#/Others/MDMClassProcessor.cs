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

namespace HardenWindowsSecurity;

internal partial class MDMClassProcessor
{
	/// <summary>
	/// It gets the results of all of the MDM related CimInstances and processes them into a list of MDMClassProcessor objects
	/// </summary>
	/// <returns></returns>
	internal static List<MDMClassProcessor> Process()
	{
		// Get the results of all of the Intune policies from the system
		Dictionary<string, List<Dictionary<string, object>>> output = MDM.Get();

		// Create a list to store the processed results and return at the end
		List<MDMClassProcessor> resultsList = [];

		// Loop over each data
		foreach (KeyValuePair<string, List<Dictionary<string, object>>> cimInstanceResult in output)
		{
			try
			{
				foreach (Dictionary<string, object> dictionary in cimInstanceResult.Value)
				{
					foreach (KeyValuePair<string, object> keyValuePair in dictionary)
					{
						// Filter out the items we don't need using ordinal, case-insensitive comparison
						if (String.Equals(keyValuePair.Key, "Class", StringComparison.OrdinalIgnoreCase) ||
							String.Equals(keyValuePair.Key, "InstanceID", StringComparison.OrdinalIgnoreCase) ||
							String.Equals(keyValuePair.Key, "ParentID", StringComparison.OrdinalIgnoreCase))
						{
							continue;
						}

						// Add the data to the list
						resultsList.Add(new MDMClassProcessor(
							keyValuePair.Key,
							keyValuePair.Value?.ToString() ?? string.Empty,
							cimInstanceResult.Key
						));
					}
				}
			}
			catch (Exception ex)
			{
				Logger.LogMessage(ex.Message, LogTypeIntel.Error);
			}
		}

		return resultsList;
	}
}
