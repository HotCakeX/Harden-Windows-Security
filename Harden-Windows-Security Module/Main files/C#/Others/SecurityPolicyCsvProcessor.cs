using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

#nullable enable

namespace HardenWindowsSecurity
{
    // Represents a record in the security policy
    public class SecurityPolicyRecord
    {
        public string? Category { get; set; }
        public string? Section { get; set; }
        public string? Path { get; set; }
        public string? Value { get; set; }
        public string? Name { get; set; }
    }

    // Processes the CSV file "SecurityPoliciesVerification.csv" containing security policy records
    public class SecurityPolicyCsvProcessor
    {
        // Reads and processes the CSV file, returning a list of SecurityPolicyRecord objects
        public static List<SecurityPolicyRecord> ProcessSecurityPolicyCsvFile(string csvFilePath)
        {
            var securityPolicyRecordsOutput = new List<SecurityPolicyRecord>();

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
                    // Add a new SecurityPolicyRecord to the output list
                    securityPolicyRecordsOutput.Add(new SecurityPolicyRecord
                    {
                        Category = fields[0].Trim(),
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
}
