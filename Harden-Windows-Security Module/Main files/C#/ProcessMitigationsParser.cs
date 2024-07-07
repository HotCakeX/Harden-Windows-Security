using System;
using System.Collections.Generic;
using System.IO;

namespace HardeningModule
{
    public class ProcessMitigationsParser
    {
        // Define a public class to store the structure of the new CSV data
        public class ProcessMitigationsRecords
        {
            public string ProgramName { get; set; }    // Column for program name
            public string Mitigation { get; set; }     // Column for mitigation
            public string Action { get; set; }         // Column for action
            public string RemovalAllowed { get; set; } // Column for removal allowed
            public string Comment { get; set; }        // Column for comments
        }

        // Define a public method to parse the CSV file and save the records to RegistryCSVItems
        public static void ReadCsv()
        {
            // Define the path to the CSV file
            string path = Path.Combine(GlobalVars.path, "Resources", "ProcessMitigations.csv");

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
                        HardeningModule.GlobalVars.ProcessMitigations.Add(new ProcessMitigationsRecords
                        {
                            ProgramName = values[0],
                            Mitigation = values[1],
                            Action = values[2],
                            RemovalAllowed = values[3],
                            Comment = values[4]
                        });
                    }
                }
            }
        }
    }
}
