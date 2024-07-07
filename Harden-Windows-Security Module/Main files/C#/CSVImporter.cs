using System;
using System.Collections.Generic;
using System.IO;

namespace HardeningModule
{
    public class HardeningRegistryKeys
    {
        // Define a public class to store the structure of the new CSV data
        public class CsvRecord
        {
            public string Category { get; set; }       // Column for category
            public string Path { get; set; }           // Column for registry path
            public string Key { get; set; }            // Column for registry key
            public string Value { get; set; }          // Column for the expected value
            public string Type { get; set; }           // Column for the type of the registry value
            public string Action { get; set; }         // Column for the action to be taken
            public string Comment { get; set; }        // Column for comments
        }

        // Define a public method to parse the CSV file and save the records to RegistryCSVItems
        public static void ReadCsv()
        {
            // Define the path to the CSV file
            string path = Path.Combine(GlobalVars.path, "Resources", "Registry.csv");

            // Open the file and read the contents
            using (StreamReader reader = new StreamReader(path))
            {
                // Read the header line
                var header = reader.ReadLine();

                // Return if the header is null
                if (header == null) return;

                // Read the rest of the file line by line
                while (!reader.EndOfStream)
                {
                    var line = reader.ReadLine();

                    // Skip if the line is null
                    if (line == null) continue;

                    // Split the line by commas to get the values, that's the CSV's delimiter
                    var values = line.Split(',');

                    // Check if the number of values is 7
                    if (values.Length == 7)
                    {
                        // Add a new CsvRecord to the list
                        HardeningModule.GlobalVars.RegistryCSVItems.Add(new CsvRecord
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
    }
}
