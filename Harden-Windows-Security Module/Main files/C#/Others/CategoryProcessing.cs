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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.Win32;

namespace HardenWindowsSecurity;

// Registry keys are case-insensitive
// https://learn.microsoft.com/en-us/windows/win32/sysinfo/structure-of-the-registry
internal static class CategoryProcessing
{
	// to store the structure of the Registry resources CSV data
	private sealed class CsvRecord
	{
		internal required string Origin { get; set; }
		internal required ComplianceCategories Category { get; set; }
		internal required string Hive { get; set; }
		internal required string Key { get; set; }
		internal required string Name { get; set; }
		internal required string FriendlyName { get; set; }
		internal required string Type { get; set; }
		internal required List<string> Value { get; set; }
		internal required bool ValueIsList { get; set; }
		internal required bool Exists { get; set; }
		internal string? CSPLink { get; set; }
	}

	// method to parse the CSV file and return a list of CsvRecord objects
	private static List<CsvRecord> ReadCsv()
	{
		// Create a list to store the records
		List<CsvRecord> records = [];

		// Define the path to the CSV file - hardcoded because it doesn't need to change
		string path = Path.Combine(GlobalVars.path, "Resources", "Registry resources.csv");

		// Open the file and read the contents
		using (StreamReader reader = new(path))
		{
			// Read the header line
			string? header = reader.ReadLine();

			// Return an empty list if the header is null
			if (header is null) return records;

			// Read the rest of the file line by line
			while (!reader.EndOfStream)
			{
				string? line = reader.ReadLine();

				if (line is null) continue;

				string[] fields = ParseCsvLine(line);

				if (fields.Length is not 11)
				{
					throw new ArgumentException("The 'Registry resources.csv' file is not formatted correctly. There should be 11 fields in each line.");
				}

				// Determine if the ValueIsList field is true
				bool valueIsList = bool.Parse(fields[8]);

				// Split the value field by commas only if ValueIsList is true
				List<string> values = valueIsList
					? [.. fields[7].Trim('"').Split(',').Select(v => v.Trim())]
					: [fields[7].Trim('"')];


				records.Add(new CsvRecord
				{
					Origin = fields[0],
					Category = Enum.Parse<ComplianceCategories>(fields[1], true),
					Hive = fields[2],
					Key = fields[3],
					Name = fields[4],
					FriendlyName = fields[5],
					Type = fields[6],
					Value = values,
					ValueIsList = valueIsList,
					Exists = bool.Parse(fields[9]),
					CSPLink = fields[10]
				});
			}
		}

		return records;
	}


	/// <summary>
	/// Parses a single line of CSV data into an array of fields.
	/// Handles fields enclosed in double quotes and commas within quoted fields.
	/// </summary>
	/// <param name="line">The line of CSV data to parse</param>
	/// <returns>An array of fields extracted from the CSV line</returns>
	private static string[] ParseCsvLine(string line)
	{
		// List to store parsed fields
		List<string> fields = [];

		// StringBuilder to build the current field
		StringBuilder currentField = new();

		// Flag to track if currently inside quoted segment
		bool inQuotes = false;

		// Iterate through each character in the line
		foreach (char c in line)
		{
			// Check if the character is a double quote
			if (c == '"')
			{
				// Toggle the inQuotes flag to handle quoted segments
				inQuotes = !inQuotes;
			}
			// Check if the character is a comma and not inside quotes
			else if (c == ',' && !inQuotes)
			{
				// Add the current field to the fields list (trimming surrounding quotes)
				fields.Add(currentField.ToString().Trim('"'));

				// Clear StringBuilder for next field
				_ = currentField.Clear();
			}
			else
			{
				// Append the character to the current field
				_ = currentField.Append(c);
			}
		}

		// Add the last field (trimming surrounding quotes)
		fields.Add(currentField.ToString().Trim('"'));

		// Convert list of fields to array and return
		return [.. fields];
	}


	// method to process a category based on the CSV data
	// The method used to verify the hardening category, which can be 'Group Policy' or 'Registry Keys'
	internal static List<IndividualResult> ProcessCategory(ComplianceCategories catName, string method)
	{
		// Create a list to store the results
		List<IndividualResult> output = [];

		// Read the CSV data
		List<CsvRecord> csvData = ReadCsv();

		// Filter the items based on category and origin/method
		IEnumerable<CsvRecord> filteredItems = csvData.Where(item =>
			item.Category == catName &&
			item.Origin.Equals(method, StringComparison.OrdinalIgnoreCase)
		);

		// Process each filtered item
		foreach (CsvRecord item in filteredItems)
		{
			// If the registry key should not exist
			if (!item.Exists)
			{
				bool keyExists = false;

				// Check in HKEY_CLASSES_ROOT
				if (item.Hive.Equals("HKEY_CLASSES_ROOT", StringComparison.OrdinalIgnoreCase))
				{
					if (item.Key is not null)
					{
						// Try to open the key in HKEY_CLASSES_ROOT
						using RegistryKey? key = Registry.ClassesRoot.OpenSubKey(item.Key);

						// Determine if the key exists
						keyExists = key is not null;
					}
				}

				// Will implement more if needed


				// Add the result to the output
				output.Add(new IndividualResult
				{
					FriendlyName = item.FriendlyName,
					Compliant = !keyExists, // Compliance is true if the key does NOT exist
					Value = keyExists ? "Exists" : "Does not exist", // Report existence status
					Name = item.Name,
					Category = catName,
					Method = Enum.Parse<ConfirmSystemComplianceMethods.Method>(method, true)
				});

			}

			// If the registry key should exist
			else
			{

				// Initialize variables
				bool valueMatches = false;
				string? regValueStr = null;

				// If the type defined in the CSV is HKLM
				if (item.Hive.Equals("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase))
				{
					// Open the registry key in HKEY_LOCAL_MACHINE
					if (item.Key is not null)
					{
						// Open the registry key in HKEY_LOCAL_MACHINE
						using RegistryKey? key = Registry.LocalMachine.OpenSubKey(item.Key);

						if (key is not null)
						{
							// Get the registry value
							var regValue = key.GetValue(item.Name);

							// Check if the registry value is an integer
							if (regValue is int v)
							{
								// Handle the case where the DWORD value is returned as an int
								// because DWORD is an UInt32
								// Then convert it to a string
								regValueStr = unchecked((uint)v).ToString(CultureInfo.InvariantCulture);
							}
							else if (regValue is uint)
							{
								// Handle the case where the DWORD value is returned as a uint
								regValueStr = regValue.ToString();
							}
							else if (regValue is string[] v1)
							{
								// Convert MULTI_STRING (string[]) to a comma-separated string for display
								regValueStr = string.Join(",", v1);
							}
							else
							{
								// Convert the registry value to a string otherwise
								regValueStr = regValue?.ToString();
							}

							// Parse the expected values based on their type in the CSV file
							List<object> parsedValues = item.Value?.Select(v => ParseRegistryValue(type: item.Type, value: v)).ToList() ?? [];


							// Check if the registry value matches any of the expected values
							if (regValue is not null)
							{
								// Convert regValueStr to uint if applicable
								uint? regValueUInt = null;
								if (uint.TryParse(regValueStr, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint parsedRegValue))
								{
									regValueUInt = parsedRegValue;
								}

								// Handle -1 case (which is equivalent to 4294967295 for DWORD)
								// Because CompareRegistryValues doesn't do the comparison properly
								if (regValueUInt == 4294967295 && item.Value is not null && item.Value.Contains("4294967295"))
								{
									valueMatches = true;
								}
								else if (regValueUInt == 2147483647 && item.Value is not null && item.Value.Contains("2147483647"))
								{
									valueMatches = true;
								}
								// Used for any other value that is not DWORD max int32 or maxUint32
								else if (parsedValues.Any(parsedValue => CompareRegistryValues(type: item.Type, regValue: regValue, expectedValue: parsedValue)))
								{
									valueMatches = true;
								}
							}
						}
					}
				}

				// If the type defined in the CSV is HKCU
				else if (item.Hive.Equals("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase))
				{
					if (item.Key is not null)
					{
						// Open the registry key in HKEY_CURRENT_USER
						using RegistryKey? key = Registry.CurrentUser.OpenSubKey(item.Key);

						if (key is not null)
						{
							// Get the registry value
							var regValue = key.GetValue(item.Name);

							if (regValue is int v1)
							{
								// Handle the case where the DWORD value is returned as an int
								regValueStr = unchecked((uint)v1).ToString(CultureInfo.InvariantCulture);
							}
							else if (regValue is uint)
							{
								// Handle the case where the DWORD value is returned as a uint
								regValueStr = regValue.ToString();
							}
							else if (regValue is string[] v)
							{
								// Convert MULTI_STRING (string[]) to a comma-separated string for display
								regValueStr = string.Join(",", v);
							}
							else
							{
								regValueStr = regValue?.ToString();
							}

							// Parse the expected values based on their type in the CSV file
							var parsedValues = item.Value?.Select(v => ParseRegistryValue(type: item.Type, value: v)).ToList() ?? [];

							// Check if the registry value matches any of the expected values
							if (regValue is not null)
							{
								// Convert regValueStr to uint if applicable
								uint? regValueUInt = null;
								if (uint.TryParse(regValueStr, NumberStyles.Integer, CultureInfo.InvariantCulture, out uint parsedRegValue))
								{
									regValueUInt = parsedRegValue;
								}

								// Handle special DWORD cases manually
								if (regValueUInt == 4294967295 && item.Value is not null && item.Value.Contains("4294967295"))
								{
									// DWORD -1 case, equivalent to max Uint32
									valueMatches = true;
								}
								else if (regValueUInt == 2147483647 && item.Value is not null && item.Value.Contains("2147483647"))
								{
									// DWORD maximum signed int32 case
									valueMatches = true;
								}
								// Fallback to general comparison using CompareRegistryValues
								else if (parsedValues.Any(parsedValue => CompareRegistryValues(type: item.Type, regValue: regValue, expectedValue: parsedValue)))
								{
									valueMatches = true;
								}
							}
						}
					}
				}

				// Add a new result to the output list
				output.Add(new IndividualResult
				{
					FriendlyName = item.FriendlyName,
					Compliant = valueMatches,
					Value = regValueStr ?? string.Empty,
					Name = item.Name,
					Category = catName,
					Method = Enum.Parse<ConfirmSystemComplianceMethods.Method>(method, true)
				});
			}

		}

		// Return the output list
		return output;
	}

	private static readonly char[] separator = [','];



	// method to parse the registry value based on its type that is defined in the CSV file
	private static object ParseRegistryValue(string type, string value)
	{
		switch (type)
		{
			case "DWORD":
				{
					// DWORD values are typically 32-bit unsigned integers
					return uint.Parse(value, CultureInfo.InvariantCulture);
				}
			case "QWORD":
				{
					// QWORD values are typically 64-bit integers
					return long.Parse(value, CultureInfo.InvariantCulture);
				}
			case "String":
				{
					// String values are kept as strings
					return value;
				}
			case "MULTI_STRING":
				{
					// MULTI_STRING values are represented as an array of strings, separated by commas in the CSV file
					// Split the CSV value by comma and return as a string array
					return value.Split(separator, StringSplitOptions.None);
				}
			// Will add more types later if needed, e.g., BINARY
			default:
				{
					throw new ArgumentException($"ParseRegistryValue: Unknown registry value type: {type}");
				}
		}
	}

	// method to compare the registry value based on its type that is defined in the CSV file
	private static bool CompareRegistryValues(string type, object regValue, object expectedValue)
	{
		try
		{
			switch (type)
			{
				case "DWORD":
					{
						// DWORD values are typically 32-bit unsigned integers
						if (regValue is int v)
						{
							return (uint)v == (uint)expectedValue;
						}
						else if (regValue is uint v1)
						{
							return v1 == (uint)expectedValue;
						}
						break;
					}
				case "QWORD":
					{
						// QWORD values are typically 64-bit integers
						return Convert.ToInt64(regValue, CultureInfo.InvariantCulture) == (long)expectedValue;
					}
				case "String":
					{
						// String values are compared as strings using ordinal ignore case
						return string.Equals(regValue.ToString(), expectedValue.ToString(), StringComparison.OrdinalIgnoreCase);
					}
				case "MULTI_STRING":
					{
						// MULTI_STRING values are arrays of strings
						// Return false if either is not a string array
						if (regValue is not string[] regValueArray || expectedValue is not string[] expectedValueArray)
						{
							return false;
						}

						// Compare the arrays by length first, then compare each element using ordinal ignore case
						// The order of the MULTI_STRING registry keys will be taken into account when comparing the reg key value against the values defined in the CSV file
						return regValueArray.Length == expectedValueArray.Length &&
							   regValueArray.SequenceEqual(expectedValueArray, StringComparer.OrdinalIgnoreCase);
					}
				// Will add more types later if needed, e.g., BINARY
				default:
					{
						throw new ArgumentException($"CompareRegistryValues: Unknown registry value type: {type}");
					}
			}
		}
		catch (Exception)
		{
			//   Logger.LogMessage($"Error comparing registry values: {ex.Message}");
			return false;
		}
		return false;
	}

}
