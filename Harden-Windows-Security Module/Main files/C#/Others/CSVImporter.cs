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
using System.IO;

namespace HardenWindowsSecurity;

public static class HardeningRegistryKeys
{
	// Define a public class to store the structure of the new CSV data
	public sealed class CsvRecord
	{
		public required string Category { get; set; }       // Column for category
		public required string Path { get; set; }           // Column for registry path
		public required string Key { get; set; }            // Column for registry key
		public required string Value { get; set; }          // Column for the expected value
		public required string Type { get; set; }           // Column for the type of the registry value
		public required string Action { get; set; }         // Column for the action to be taken
		public string? Comment { get; set; }                // Column for comments
	}

	// Define a public method to parse the CSV file and save the records to RegistryCSVItems
	internal static void ReadCsv()
	{
		// Ensure RegistryCSVItems is initialized
		List<CsvRecord> registryCSVItems = GlobalVars.RegistryCSVItems;

		// Define the path to the CSV file
		string path = Path.Combine(GlobalVars.path, "Resources", "Registry.csv");

		// Open the file and read the contents
		using StreamReader reader = new(path);

		// Read the header line
		string? header = reader.ReadLine();

		// Return if the header is null
		if (header is null)
		{
			return;
		}

		// Read the rest of the file line by line
		while (!reader.EndOfStream)
		{
			string? line = reader.ReadLine();

			// Skip if the line is null
			if (line is null)
			{
				continue;
			}

			// Split the line by commas to get the values, that's the CSV's delimiter
			string[] values = line.Split(',');

			// Check if the number of values is 7
			if (values.Length == 7)
			{
				// Add a new CsvRecord to the list
				registryCSVItems.Add(new CsvRecord
				{
					Category = values[0],
					Path = values[1],
					Key = values[2],
					Value = values[3],
					Type = values[4],
					Action = values[5],
					Comment = values[6]
				});
			}
		}
	}
}
