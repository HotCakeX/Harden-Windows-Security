// Import necessary namespaces
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;

// Define the namespace for the HardeningModule
namespace HardeningModule
{
    // Define the CategoryProcessing class
    public class CategoryProcessing
    {
        // Define a private class to store the structure of the Registry resources CSV data
        private class CsvRecord
        {
            public string Origin { get; set; }         // Column for origin
            public string Category { get; set; }       // Column for category
            public string Hive { get; set; }           // Column for registry hive (e.g., HKEY_LOCAL_MACHINE)
            public string Key { get; set; }            // Column for registry key
            public string Name { get; set; }           // Column for registry value name
            public string FriendlyName { get; set; }   // Column for a friendly name description
            public string Type { get; set; }           // Column for the type of the registry value
            public string Value { get; set; }          // Column for the expected value
            public string CSPLink { get; set; }        // Column for a link to related documentation
        }

        // Define a private method to parse the CSV file and return a list of CsvRecord objects
        private static List<CsvRecord> ReadCsv()
        {
            // Create a list to store the records
            List<CsvRecord> records = new List<CsvRecord>();

            // Define the path to the CSV file
            string path = Path.Combine(GlobalVars.path, "Resources", "Registry resources.csv");

            // Open the file and read the contents
            using (StreamReader reader = new StreamReader(path))
            {
                // Read the header line
                var header = reader.ReadLine();

                // Return an empty list if the header is null
                if (header == null) return records;

                // Read the rest of the file line by line
                while (!reader.EndOfStream)
                {
                    var line = reader.ReadLine();

                    // Skip if the line is null
                    if (line == null) continue;

                    // Split the line by commas to get the values, that's the CSV's delimiter
                    var values = line.Split(',');

                    // Check if the number of values is 9
                    if (values.Length == 9)
                    {
                        // Add a new CsvRecord to the list
                        records.Add(new CsvRecord
                        {
                            Origin = values[0],
                            Category = values[1],
                            Hive = values[2],
                            Key = values[3],
                            Name = values[4],
                            FriendlyName = values[5],
                            Type = values[6],
                            Value = values[7],
                            CSPLink = values[8]
                        });
                    }
                }
            }

            // Return the list of records
            return records;
        }

        // Define a public method to process a category based on the CSV data
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

                // Check the registry hive
                if (item.Hive == "HKEY_LOCAL_MACHINE")
                {
                    // Open the registry key in HKEY_LOCAL_MACHINE
                    // key variable is scoped to the using block and after the using block it will be disposed of just like try/finally blocks
                    using (var key = Registry.LocalMachine.OpenSubKey(item.Key))
                    {
                        if (key != null)
                        {
                            // Get the registry value
                            var regValue = key.GetValue(item.Name);

                            // Check if the registry value matches the expected value
                            if (regValue != null && regValue.ToString() == item.Value)
                            {
                                // Set valueMatches to "true" if it matches
                                valueMatches = "true";
                            }
                        }
                    }
                }
                else if (item.Hive == "HKEY_CURRENT_USER")
                {
                    // Open the registry key in HKEY_CURRENT_USER
                    using (var key = Registry.CurrentUser.OpenSubKey(item.Key))
                    {
                        if (key != null)
                        {
                            // Get the registry value
                            var regValue = key.GetValue(item.Name);

                            // Check if the registry value matches the expected value
                            if (regValue != null && regValue.ToString() == item.Value)
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
                    Value = item.Value,
                    Name = item.Name,
                    Category = catName,
                    Method = method
                });
            }

            // Return the output list
            return output;
        }
    }
}
