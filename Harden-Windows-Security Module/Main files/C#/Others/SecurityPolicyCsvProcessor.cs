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
using System.IO;
using System.Text;

namespace HardenWindowsSecurity;

// Represents a record in the security policy
internal sealed class SecurityPolicyRecord
{
	internal required ComplianceCategories Category { get; set; }
	internal string? Section { get; set; }
	internal string? Path { get; set; }
	internal string? Value { get; set; }
	internal string? Name { get; set; }
}

// Processes the CSV file "SecurityPoliciesVerification.csv" containing security policy records
internal static class SecurityPolicyCsvProcessor
{
	// Reads and processes the CSV file, returning a list of SecurityPolicyRecord objects
	internal static List<SecurityPolicyRecord> ProcessSecurityPolicyCsvFile(string csvFilePath)
	{
		List<SecurityPolicyRecord> securityPolicyRecordsOutput = [];

		// Open the CSV file for reading
		using StreamReader reader = new(csvFilePath);

		// Read the header line
		string? header = reader.ReadLine();

		// Return if the header is null
		if (header is null) return securityPolicyRecordsOutput;

		// Read the rest of the file line by line
		while (!reader.EndOfStream)
		{
			string? line = reader.ReadLine();

			// Skip null lines
			if (line is null) continue;

			// Parse the CSV line into fields
			string[] fields = ParseCsvLine(line);

			// Ensure the line has exactly 5 fields
			if (fields.Length == 5)
			{

				if (!Enum.TryParse(fields[0].Trim(), true, out ComplianceCategories categoryName))
				{
					throw new InvalidDataException($"Invalid category name in the 'SecurityPoliciesVerification.csv' file: {categoryName}");
				}

				// Add a new SecurityPolicyRecord to the output list
				securityPolicyRecordsOutput.Add(new SecurityPolicyRecord
				{
					Category = categoryName,
					Section = fields[1].Trim(),
					Path = fields[2].Trim(),
					Value = fields[3].Trim(),
					Name = fields[4].Trim()
				});
			}
			else
			{
				// Throw an exception if the line does not have 5 fields
				throw new ArgumentException("The CSV file is not formatted correctly. There should be 5 fields in each line.");
			}
		}

		return securityPolicyRecordsOutput;
	}

	// Parses a single line of CSV, taking into account quoted fields
	private static string[] ParseCsvLine(string line)
	{
		List<string> fields = [];
		StringBuilder currentField = new();
		bool inQuotes = false;

		// Iterate through each character in the line
		foreach (char c in line)
		{
			if (c == '"')
			{
				// Toggle the inQuotes flag if a quote is encountered
				inQuotes = !inQuotes;
			}
			else if (c == ',' && !inQuotes)
			{
				// Add the current field to the list if a comma is encountered outside quotes
				fields.Add(currentField.ToString().Trim('"'));
				_ = currentField.Clear();
			}
			else
			{
				// Append the character to the current field
				_ = currentField.Append(c);
			}
		}

		// Add the last field to the list
		fields.Add(currentField.ToString().Trim('"'));
		return [.. fields];
	}
}
