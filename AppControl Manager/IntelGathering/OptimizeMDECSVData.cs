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
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace AppControlManager.IntelGathering;

internal static partial class OptimizeMDECSVData
{
	/// <summary>
	/// The Main method of the class.
	/// Optimizes the MDE CSV data by adding the nested properties in the "AdditionalFields" property to the parent record as first-level properties, all in one class.
	/// </summary>
	/// <param name="CSVFilePath"></param>
	/// <returns></returns>
	internal static List<MDEAdvancedHuntingData> Optimize(string CSVFilePath)
	{
		List<MDEAdvancedHuntingData> csvRecords = ReadCsv(CSVFilePath);
		return csvRecords;
	}

	/// <summary>
	/// Converts an entire MDE Advanced Hunting CSV file into a list of classes.
	/// </summary>
	/// <param name="filePath"></param>
	/// <returns></returns>
	/// <exception cref="InvalidDataException"></exception>
	private static List<MDEAdvancedHuntingData> ReadCsv(string filePath)
	{
		// Create a list to store each CSV row record.
		List<MDEAdvancedHuntingData> records = [];

		// Read the CSV file line by line.
		using StreamReader reader = new(filePath);

		// Read the header line which is the first line.
		string? header = reader.ReadLine() ?? throw new InvalidDataException("CSV file is empty or header is missing.");

		// Parse the header line.
		string[] headers = ParseCsvLine(header);

		// Map header names to their indices so columns can be located precisely regardless of their positions in the CSV file.
		Dictionary<string, int> headerMap = headers
			.Select((name, index) => new { name, index })
			.ToDictionary(x => x.name, x => x.index);

		// Read the remaining lines of the CSV file until the end of the stream is reached (EOF).
		while (!reader.EndOfStream)
		{
			// Read the next line.
			string? line = reader.ReadLine();

			// Skip empty lines.
			if (line is null) continue;

			// Split the line by commas.
			string[] values = ParseCsvLine(line);

			// Initialize a new MDEAdvancedHuntingData instance.
			// P.S not all rows have the same properties.
			MDEAdvancedHuntingData record = new()
			{
				Timestamp = GetValue(values, headerMap, "Timestamp"),
				DeviceId = GetValue(values, headerMap, "DeviceId"),
				DeviceName = GetValue(values, headerMap, "DeviceName"),
				ActionType = GetValue(values, headerMap, "ActionType"),
				FileName = GetValue(values, headerMap, "FileName"),
				FolderPath = GetValue(values, headerMap, "FolderPath"),
				SHA1 = GetValue(values, headerMap, "SHA1"),
				SHA256 = GetValue(values, headerMap, "SHA256"),
				InitiatingProcessSHA1 = GetValue(values, headerMap, "InitiatingProcessSHA1"),
				InitiatingProcessSHA256 = GetValue(values, headerMap, "InitiatingProcessSHA256"),
				InitiatingProcessMD5 = GetValue(values, headerMap, "InitiatingProcessMD5"),
				InitiatingProcessFileName = GetValue(values, headerMap, "InitiatingProcessFileName"),
				InitiatingProcessFileSize = GetValue(values, headerMap, "InitiatingProcessFileSize"),
				InitiatingProcessFolderPath = GetValue(values, headerMap, "InitiatingProcessFolderPath"),
				InitiatingProcessId = GetValue(values, headerMap, "InitiatingProcessId"),
				InitiatingProcessCommandLine = GetValue(values, headerMap, "InitiatingProcessCommandLine"),
				InitiatingProcessCreationTime = GetValue(values, headerMap, "InitiatingProcessCreationTime"),
				InitiatingProcessAccountDomain = GetValue(values, headerMap, "InitiatingProcessAccountDomain"),
				InitiatingProcessAccountName = GetValue(values, headerMap, "InitiatingProcessAccountName"),
				InitiatingProcessAccountSid = GetValue(values, headerMap, "InitiatingProcessAccountSid"),
				InitiatingProcessVersionInfoCompanyName = GetValue(values, headerMap, "InitiatingProcessVersionInfoCompanyName"),
				InitiatingProcessVersionInfoProductName = GetValue(values, headerMap, "InitiatingProcessVersionInfoProductName"),
				InitiatingProcessVersionInfoProductVersion = GetValue(values, headerMap, "InitiatingProcessVersionInfoProductVersion"),
				InitiatingProcessVersionInfoInternalFileName = GetValue(values, headerMap, "InitiatingProcessVersionInfoInternalFileName"),
				InitiatingProcessVersionInfoOriginalFileName = GetValue(values, headerMap, "InitiatingProcessVersionInfoOriginalFileName"),
				InitiatingProcessVersionInfoFileDescription = GetValue(values, headerMap, "InitiatingProcessVersionInfoFileDescription"),
				InitiatingProcessParentId = GetValue(values, headerMap, "InitiatingProcessParentId"),
				InitiatingProcessParentFileName = GetValue(values, headerMap, "InitiatingProcessParentFileName"),
				InitiatingProcessParentCreationTime = GetValue(values, headerMap, "InitiatingProcessParentCreationTime"),
				InitiatingProcessLogonId = GetValue(values, headerMap, "InitiatingProcessLogonId"),
				ReportId = GetValue(values, headerMap, "ReportId")
			};

			// Get the JSON string from the CSV which is in the AdditionalFields property.
			string? additionalFieldsString = GetValue(values, headerMap, "AdditionalFields");

			// Parse the AdditionalFields JSON if it exists.
			if (!string.IsNullOrWhiteSpace(additionalFieldsString))
			{
				// Format the JSON string so the next method won't throw an error.
				string formattedJSONString = EnsureAllValuesAreQuoted(additionalFieldsString);

				// Deserialize the JSON content into an AdditionalFields instance using the generated context.
				AdditionalFields? additionalFields = JsonSerializer.Deserialize(
					formattedJSONString,
					MDEAdvancedHuntingJSONSerializationContext.Default.AdditionalFields);

				if (additionalFields is not null)
				{
					// Populate the new properties from the JSON.
					record.PolicyID = additionalFields.PolicyID;
					record.PolicyName = additionalFields.PolicyName;
					record.RequestedSigningLevel = additionalFields.RequestedSigningLevel;
					record.ValidatedSigningLevel = additionalFields.ValidatedSigningLevel;
					record.ProcessName = additionalFields.ProcessName;
					record.StatusCode = additionalFields.StatusCode;
					record.Sha1FlatHash = additionalFields.Sha1FlatHash;
					record.Sha256FlatHash = additionalFields.Sha256FlatHash;
					record.USN = additionalFields.USN;
					record.SiSigningScenario = additionalFields.SiSigningScenario;
					record.PolicyHash = additionalFields.PolicyHash;
					record.PolicyGuid = additionalFields.PolicyGuid;
					record.UserWriteable = additionalFields.UserWriteable;
					record.OriginalFileName = additionalFields.OriginalFileName;
					record.InternalName = additionalFields.InternalName;
					record.FileDescription = additionalFields.FileDescription;
					record.FileVersion = additionalFields.FileVersion;
					record.EtwActivityId = additionalFields.EtwActivityId;
					record.IssuerName = additionalFields.IssuerName;
					record.IssuerTBSHash = additionalFields.IssuerTBSHash;
					record.NotValidAfter = additionalFields.NotValidAfter;
					record.NotValidBefore = additionalFields.NotValidBefore;
					record.PublisherName = additionalFields.PublisherName;
					record.PublisherTBSHash = additionalFields.PublisherTBSHash;
					record.SignatureType = additionalFields.SignatureType;
					record.TotalSignatureCount = additionalFields.TotalSignatureCount;
					record.VerificationError = additionalFields.VerificationError;
					record.Signature = additionalFields.Signature;
					record.Hash = additionalFields.Hash;
					record.Flags = additionalFields.Flags;
					record.PolicyBits = additionalFields.PolicyBits;
				}
			}

			// Add the populated record to the list.
			records.Add(record);
		}

		return records;
	}

	/// <summary>
	/// Ensures the JSON string is well formatted. If a field has no double quotes, it will add them around it.
	/// </summary>
	/// <param name="jsonString"></param>
	/// <returns></returns>
	private static string EnsureAllValuesAreQuoted(string jsonString)
	{
		// Regex to match unquoted values that are not inside quotes.
		Regex regex = JsonFixerRegex();

		// Replace the matched unquoted values with the same value wrapped in double quotes.
		string result = regex.Replace(jsonString, match => $"\"{match.Value.Trim()}\"");
		return result;
	}

	/// <summary>
	/// Parses each line/row of the CSV file.
	/// </summary>
	/// <param name="line"></param>
	/// <returns></returns>
	private static string[] ParseCsvLine(string line)
	{
		List<string> fields = [];
		StringBuilder currentField = new();
		bool inQuotes = false;

		// Iterate through each character in the line.
		for (int i = 0; i < line.Length; i++)
		{
			char c = line[i];

			// Handle quotes.
			if (c == '"')
			{
				// Handle escaped quotes ("")
				if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
				{
					_ = currentField.Append('"'); // Append a single quote if it's an escape sequence.
					i++; // Skip the next quote.
				}
				else
				{
					inQuotes = !inQuotes; // Toggle the inQuotes flag.
				}
			}
			// Handle commas.
			else if (c == ',' && !inQuotes)
			{
				// When we hit a comma outside of quotes, the field is complete.
				fields.Add(currentField.ToString());
				_ = currentField.Clear();
			}
			else
			{
				// Add characters to the current field.
				_ = currentField.Append(c);
			}
		}

		// Add the last field to the list.
		fields.Add(currentField.ToString());

		// Clean up: Remove the outermost quotes for non-JSON fields.
		// If a field has more than one set/pair of double quotes around it, only one pair will be removed.
		for (int i = 0; i < fields.Count; i++)
		{
			string field = fields[i];

			// If the field is a JSON field, we don't want to remove quotes.
			if (field.StartsWith('{') && field.EndsWith('}'))
			{
				continue; // Skip JSON fields.
			}

			// Remove leading and trailing quotes if they exist (for non-JSON fields).
			if (field.StartsWith('"') && field.EndsWith('"') && field.Length > 1)
			{
				fields[i] = field[1..^1];
			}
		}

		return [.. fields];
	}

	/// <summary>
	/// Gets the value of a column from the CSV row and returns it.
	/// Returns null if the column does not exist or the value is empty.
	/// </summary>
	/// <param name="values"></param>
	/// <param name="headerMap"></param>
	/// <param name="columnName"></param>
	/// <returns></returns>
	private static string? GetValue(string[] values, Dictionary<string, int> headerMap, string columnName)
	{
		if (headerMap.TryGetValue(columnName, out int index) && index < values.Length)
		{
			return values[index];
		}
		return null;
	}

	// 1. (?<=:)
	//    Positive Lookbehind: Asserts that the match must be preceded by a colon `:`.
	//    Ensures that we're matching a value that appears immediately after a key-value colon.
	//
	// 2. \s*
	//    Matches zero or more whitespace characters following the colon.
	//    Allows for optional spaces between the colon and the value.
	//
	// 3. (?!\"\")
	//    Negative Lookahead: Ensures that the match is NOT followed by a double quote `"` .
	//    This prevents already quoted values from being matched.
	//
	// 4. ([^\"",\s]+)
	//    Capturing Group: Matches one or more characters that are not a double quote `"`,
	//    comma `,`, or whitespace. This captures unquoted strings up to a comma, closing
	//    brace, or space, allowing only unquoted single-word values to be matched.
	//
	// 5. (?=\s*,|\s*})
	//    Positive Lookahead: Asserts that the match must be followed by either a comma `,`
	//    (indicating another key-value pair) or a closing brace `}`, with optional whitespace.
	//    This confirms the end of the unquoted value within the JSON structure.
	//
	// Summary:
	// Some MDE AH AdditionalFields JSON content have unquoted fields, this takes care of them.
	// The regex will fail if the field that is not quoted contains a comma(s), space(s) or double quote(s)
	// in it before the comma that marks the end of the field.
	// This is because the regex is designed to match unquoted fields that are single words/digits.
	[GeneratedRegex(@"(?<=:)\s*(?!\"")([^\"",\s]+)(?=\s*,|\s*})")]
	private static partial Regex JsonFixerRegex();
}
