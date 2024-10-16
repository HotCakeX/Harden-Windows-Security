using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;

#pragma warning disable IDE0038

#nullable enable

namespace HardenWindowsSecurity
{
    // Registry keys are case-insensitive
    // https://learn.microsoft.com/en-us/windows/win32/sysinfo/structure-of-the-registry
    public class CategoryProcessing
    {
        // to store the structure of the Registry resources CSV data
        private sealed class CsvRecord
        {
            public string? Origin { get; set; }
            public string? Category { get; set; }
            public string? Hive { get; set; }
            public string? Key { get; set; }
            public string? Name { get; set; }
            public string? FriendlyName { get; set; }
            public string? Type { get; set; }
            public List<string>? Value { get; set; }
            public bool ValueIsList { get; set; }
            public string? CSPLink { get; set; }
        }

        // method to parse the CSV file and return a list of CsvRecord objects
        private static List<CsvRecord> ReadCsv()
        {
            // Create a list to store the records
            List<CsvRecord> records = [];

            if (GlobalVars.path is null)
            {
                throw new ArgumentNullException("The path to the CSV file is not set.");
            }

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

                    if (fields.Length == 10)
                    {
                        // Determine if the ValueIsList field is true
                        bool valueIsList = bool.Parse(fields[8]);

                        // Split the value field by commas only if ValueIsList is true
                        List<string> values = valueIsList
                            ? fields[7].Trim('"').Split(',').Select(v => v.Trim()).ToList()
                            : [fields[7].Trim('"')];

                        records.Add(new CsvRecord
                        {
                            Origin = fields[0],
                            Category = fields[1],
                            Hive = fields[2],
                            Key = fields[3],
                            Name = fields[4],
                            FriendlyName = fields[5],
                            Type = fields[6],
                            Value = values,
                            ValueIsList = valueIsList,
                            CSPLink = fields[9]
                        });
                    }
                    else
                    {
                        throw new ArgumentException("The CSV file is not formatted correctly. There should be 10 fields in each line.");
                    }
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
        public static List<IndividualResult> ProcessCategory(string catName, string method)
        {
            // Create a list to store the results
            List<IndividualResult> output = [];

            // Read the CSV data
            List<CsvRecord> csvData = ReadCsv();

            // Filter the items based on category and origin
            var filteredItems = csvData.Where(item =>
                item.Category?.Equals(catName, StringComparison.OrdinalIgnoreCase) == true &&
                item.Origin?.Equals(method, StringComparison.OrdinalIgnoreCase) == true
            );

            // Process each filtered item
            foreach (var item in filteredItems)
            {
                // Initialize variables
                bool valueMatches = false;
                string? regValueStr = null;

                // If the type defined in the CSV is HKLM
                if (item.Hive is not null && item.Hive.Equals("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase))
                {
                    // Open the registry key in HKEY_LOCAL_MACHINE
                    if (item.Key is not null)
                    {
                        // Open the registry key in HKEY_LOCAL_MACHINE
                        using var key = Registry.LocalMachine.OpenSubKey(item.Key);

                        if (key is not null)
                        {
                            // Get the registry value
                            var regValue = key.GetValue(item.Name);

                            // Check if the registry value is an integer
                            if (regValue is int)
                            {
                                // Handle the case where the DWORD value is returned as an int
                                // because DWORD is an UInt32
                                // Then convert it to a string
                                regValueStr = unchecked((uint)(int)regValue).ToString(CultureInfo.InvariantCulture);
                            }
                            else if (regValue is uint)
                            {
                                // Handle the case where the DWORD value is returned as a uint
                                regValueStr = regValue.ToString();
                            }
                            else if (regValue is string[])
                            {
                                // Convert MULTI_STRING (string[]) to a comma-separated string for display
                                regValueStr = string.Join(",", (string[])regValue);
                            }
                            else
                            {
                                // Convert the registry value to a string otherwise
                                regValueStr = regValue?.ToString();
                            }

                            // Parse the expected values based on their type in the CSV file
                            var parsedValues = item.Type is not null
                                ? item.Value?.Select(v => ParseRegistryValue(type: item.Type, value: v)).ToList() ?? []
                                : [];

                            // Check if the registry value matches any of the expected values
                            if (regValue is not null && item.Type is not null)
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
                else if (item.Hive?.Equals("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase) == true)
                {
                    if (item.Key is not null)
                    {
                        // Open the registry key in HKEY_CURRENT_USER
                        using var key = Registry.CurrentUser.OpenSubKey(item.Key);

                        if (key is not null)
                        {
                            // Get the registry value
                            var regValue = key.GetValue(item.Name);

                            if (regValue is int)
                            {
                                // Handle the case where the DWORD value is returned as an int
                                regValueStr = unchecked((uint)(int)regValue).ToString(CultureInfo.InvariantCulture);
                            }
                            else if (regValue is uint)
                            {
                                // Handle the case where the DWORD value is returned as a uint
                                regValueStr = regValue.ToString();
                            }
                            else if (regValue is string[])
                            {
                                // Convert MULTI_STRING (string[]) to a comma-separated string for display
                                regValueStr = string.Join(",", (string[])regValue);
                            }
                            else
                            {
                                regValueStr = regValue?.ToString();
                            }

                            // Parse the expected values based on their type in the CSV file
                            var parsedValues = item.Type is not null
                                ? item.Value?.Select(v => ParseRegistryValue(type: item.Type, value: v)).ToList() ?? []
                                : [];

                            // Check if the registry value matches any of the expected values
                            if (regValue is not null && item.Type is not null)
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
                    FriendlyName = item.FriendlyName ?? "Unknown", // Ensure FriendlyName is non-null
                    Compliant = valueMatches,
                    Value = regValueStr ?? string.Empty,
                    Name = item.Name ?? "Unknown", // Ensure Name is non-null
                    Category = catName, // catName is non-null as it's a parameter
                    Method = method // method is non-null as it's a parameter
                });
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
                            if (regValue is int)
                            {
                                return (uint)(int)regValue == (uint)expectedValue;
                            }
                            else if (regValue is uint)
                            {
                                return (uint)regValue == (uint)expectedValue;
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
}
