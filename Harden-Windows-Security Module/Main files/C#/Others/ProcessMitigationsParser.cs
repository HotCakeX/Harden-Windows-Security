using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public class ProcessMitigationsParser
    {
        // Define a public class to store the structure of the new CSV data
        public class ProcessMitigationsRecords
        {
            public string? ProgramName { get; set; }    // Column for program name
            public string? Mitigation { get; set; }     // Column for mitigation
            public string? Action { get; set; }         // Column for action
            public bool RemovalAllowed { get; set; } // Column for removal allowed
            public string? Comment { get; set; }        // Column for comments
        }

        // Define a public method to parse the CSV file and save the records to RegistryCSVItems
        public static void ReadCsv()
        {

            // Initializing the path variable for the CSV file
            string path = string.Empty;

            if (GlobalVars.path != null)
            {
                // Define the path to the CSV file
                path = Path.Combine(GlobalVars.path, "Resources", "ProcessMitigations.csv");
            }
            else
            {
                throw new Exception("");
            }

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

                    // Check if the number of values is 5
                    if (values.Length == 5)
                    {
                        // Add a new ProcessMitigationsRecords to the list
                        HardenWindowsSecurity.GlobalVars.ProcessMitigations!.Add(new ProcessMitigationsRecords
                        {
                            ProgramName = values[0],
                            Mitigation = values[1],
                            Action = values[2],
                            RemovalAllowed = Convert.ToBoolean(values[3], CultureInfo.InvariantCulture),
                            Comment = values[4]
                        });
                    }
                }
            }
        }
    }
}
