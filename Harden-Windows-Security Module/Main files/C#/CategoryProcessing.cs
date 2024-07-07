using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;
using System.Text;

namespace HardeningModule
{
    public class CategoryProcessing
    {
        // to store the structure of the Registry resources CSV data
        private class CsvRecord
        {
            public string Origin { get; set; }
            public string Category { get; set; }
            public string Hive { get; set; }
            public string Key { get; set; }
            public string Name { get; set; }
            public string FriendlyName { get; set; }
            public string Type { get; set; }
            public string Value { get; set; }
            public string CSPLink { get; set; }
        }

        // method to parse the CSV file and return a list of CsvRecord objects
        private static List<CsvRecord> ReadCsv()
        {
            // Create a list to store the records
            List<CsvRecord> records = new List<CsvRecord>();

            // Define the path to the CSV file - hardcoded because it doesn't need to change
            string path = Path.Combine(GlobalVars.path, "Resources", "Registry resources.csv");

            // Open the file and read the contents
            using (StreamReader reader = new StreamReader(path))
            {
                // Read the header line
                string header = reader.ReadLine();

                // Return an empty list if the header is null
                if (header == null) return records;

                // Read the rest of the file line by line
                while (!reader.EndOfStream)
                {
                    string line = reader.ReadLine();

                    if (line == null) continue;

                    string[] fields = ParseCsvLine(line);

                    if (fields.Length == 9)
                    {
                        records.Add(new CsvRecord
                        {
                            Origin = fields[0],
                            Category = fields[1],
                            Hive = fields[2],
                            Key = fields[3],
                            Name = fields[4],
                            FriendlyName = fields[5],
                            Type = fields[6],
                            Value = fields[7],
                            CSPLink = fields[8]
                        });
                    }
                    else
                    {
                        throw new ArgumentException("The CSV file is not formatted correctly. There should be 9 fields in each line.");
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
            List<string> fields = new List<string>();

            // StringBuilder to build the current field
            StringBuilder currentField = new StringBuilder();

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
                    currentField.Clear();
                }
                else
                {
                    // Append the character to the current field
                    currentField.Append(c);
                }
            }

            // Add the last field (trimming surrounding quotes)
            fields.Add(currentField.ToString().Trim('"'));

            // Convert list of fields to array and return
            return fields.ToArray();
        }


        // method to process a category based on the CSV data
        // The method used to verify the hardening category, which can be 'Group Policy' or 'Registry Keys'
        public static List<IndividualResult> ProcessCategory(string catName, string method)
        {
            // Create a list to store the results
            List<IndividualResult> output = new List<IndividualResult>();

            // Read the CSV data
            List<CsvRecord> csvData = ReadCsv();

            // Filter the items based on category and origin
            var filteredItems = csvData.Where(item => item.Category == catName && item.Origin == method);

            // Process each filtered item
            foreach (var item in filteredItems)
            {
                // Initialize valueMatches to "false"
                string valueMatches = "false";
                string regValueStr = null;

                // If the type defined in the CSV is HKLM
                if (item.Hive == "HKEY_LOCAL_MACHINE")
                {
                    // Open the registry key in HKEY_LOCAL_MACHINE
                    using (var key = Registry.LocalMachine.OpenSubKey(item.Key))
                    {
                        if (key != null)
                        {
                            // Get the registry value
                            var regValue = key.GetValue(item.Name);

                            // Check if the registry value is an integer
                            if (regValue is int)
                            {
                                // Handle the case where the DWORD value is returned as an int
                                // because DWORD is an UInt32
                                // Then convert it to a string
                                regValueStr = ((uint)(int)regValue).ToString();
                            }
                            else if (regValue is uint)
                            {
                                // Handle the case where the DWORD value is returned as a uint
                                regValueStr = regValue.ToString();
                            }
                            else
                            {
                                // Convert the registry value to a string otherwise
                                regValueStr = regValue?.ToString();
                            }

                            // Parse the expected value based on its type in the CSV file
                            object parsedValue = ParseRegistryValue(type: item.Type, value: item.Value);

                            // Check if the registry value matches the expected value
                            if (regValue != null && CompareRegistryValues(type: item.Type, regValue: regValue, expectedValue: parsedValue))
                            {
                                // Set valueMatches to "true" if it matches
                                valueMatches = "true";
                            }
                        }
                    }
                }
                // If the type defined in the CSV is HKCU
                else if (item.Hive == "HKEY_CURRENT_USER")
                {
                    // Open the registry key in HKEY_CURRENT_USER
                    using (var key = Registry.CurrentUser.OpenSubKey(item.Key))
                    {
                        if (key != null)
                        {
                            // Get the registry value
                            var regValue = key.GetValue(item.Name);

                            if (regValue is int)
                            {
                                // Handle the case where the DWORD value is returned as an int
                                regValueStr = ((uint)(int)regValue).ToString();
                            }
                            else if (regValue is uint)
                            {
                                // Handle the case where the DWORD value is returned as a uint
                                regValueStr = regValue.ToString();
                            }
                            else
                            {
                                regValueStr = regValue?.ToString();
                            }

                            // Parse the expected value based on its type in the CSV file
                            object parsedValue = ParseRegistryValue(type: item.Type, value: item.Value);

                            // Check if the registry value matches the expected value
                            if (regValue != null && CompareRegistryValues(type: item.Type, regValue: regValue, expectedValue: parsedValue))
                            {
                                // Set valueMatches to "true" if it matches
                                valueMatches = "true";
                            }
                        }
                    }
                }

                // Add a new result to the output list
                output.Add(new IndividualResult
                {
                    FriendlyName = item.FriendlyName,
                    Compliant = valueMatches,
                    Value = regValueStr,
                    Name = item.Name,
                    Category = catName,
                    Method = method
                });
            }

            // Return the output list
            return output;
        }

        // method to parse the registry value based on its type that is defined in the CSV file
        private static object ParseRegistryValue(string type, string value)
        {
            switch (type)
            {
                case "DWORD":
                    {
                        // DWORD values are typically 32-bit unsigned integers
                        return uint.Parse(value);
                    }
                case "QWORD":
                    {
                        // QWORD values are typically 64-bit integers
                        return long.Parse(value);
                    }
                case "String":
                    {
                        // String values are kept as strings
                        return value;
                    }
                // Will add more types later if needed, e.g., BINARY, MULTI_STRING etc.
                default:
                    {
                        throw new ArgumentException($"ParseRegistryValue: sUnknown registry value type: {type}");
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
                            return Convert.ToInt64(regValue) == (long)expectedValue;
                        }
                    case "String":
                        {
                            // String values are compared as strings
                            return regValue.ToString() == expectedValue.ToString();
                        }
                    // Will add more types later if needed, e.g., BINARY, MULTI_STRING etc.
                    default:
                        {
                            throw new ArgumentException($"CompareRegistryValues: Unknown registry value type: {type}");
                        }
                }
            }
            catch (Exception)
            {
                //   Console.WriteLine($"Error comparing registry values: {ex.Message}");
                return false;
            }
            return false;
        }
    }
}
