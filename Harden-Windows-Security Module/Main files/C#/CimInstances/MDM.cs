using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Threading.Tasks;

#nullable enable

/// root\cimv2\mdm is the namespace for CSPs
/// https://learn.microsoft.com/en-us/windows/win32/wmisdk/common-information-model
namespace HardenWindowsSecurity
{
    // Class that deals with MDM/CSPs/Intune
    public class MDM
    {
        // Gets the results of all of the Intune policies from the system
        public static Dictionary<string, List<Dictionary<string, object>>> Get()
        {
            // Running the asynchronous method synchronously and returning the result
            return Task.Run(() => GetAsync()).GetAwaiter().GetResult();
        }

        // Asynchronous method to get the results
        private static async Task<Dictionary<string, List<Dictionary<string, object>>>> GetAsync()
        {
            // Set the location of the CSV file containing the MDM list
            string path = HardenWindowsSecurity.GlobalVars.path ?? throw new InvalidOperationException("GlobalVars.path is null");
            string csvFilePath = Path.Combine(path, "Resources", "MDMResultClasses.csv");

            // Create a dictionary where keys are the class names and values are lists of dictionaries
            Dictionary<string, List<Dictionary<string, object>>> results = [];

            try
            {
                // Read class names and namespaces from CSV file asynchronously
                var records = await ReadCsvFileAsync(csvFilePath);

                // Create a list of tasks for querying each class
                List<Task> tasks = [];

                // Iterate through records
                foreach (var record in records)
                {
                    // Process only authorized records
                    if (record.Authorized?.Equals("TRUE", StringComparison.OrdinalIgnoreCase) == true)
                    {

                        // Debugging output
                        // HardenWindowsSecurity.Logger.LogMessage($"Namespace: {record.Namespace}, Class: {record.Class}");

                        // Add a new task for each class query
                        tasks.Add(Task.Run(() =>
                        {
                            // List to store results for the current class
                            List<Dictionary<string, object>> classResults = [];

                            // Create management scope object
                            ManagementScope scope = new(record.Namespace);
                            // Connect to the WMI namespace
                            try
                            {
                                scope.Connect();
                            }
                            catch (ManagementException e)
                            {
                                // Write verbose error message if connection fails
                                HardenWindowsSecurity.Logger.LogMessage($"Error connecting to namespace {record.Namespace}: {e.Message}", LogTypeIntel.Error);
                            }

                            // Create object query for the current class
                            string classQuery = record.Class?.Trim() ?? throw new InvalidOperationException("Record.Class is null");
                            ObjectQuery query = new("SELECT * FROM " + classQuery);

                            // Create management object searcher for the query
                            ManagementObjectSearcher searcher = new(scope, query);

                            try
                            {
                                // Execute the query and iterate through the results
                                foreach (ManagementObject obj in searcher.Get().Cast<ManagementObject>())
                                {
                                    // Dictionary to store properties of the current class instance
                                    Dictionary<string, object> classInstance = [];

                                    // Iterate through properties of the current object
                                    foreach (PropertyData prop in obj.Properties)
                                    {
                                        // Store property name and its value
                                        classInstance[prop.Name] = GetPropertyOriginalValue(prop);
                                    }

                                    // Add class instance to results
                                    classResults.Add(classInstance);
                                }
                            }
                            catch (ManagementException e)
                            {
                                // Write verbose error message if query fails
                                HardenWindowsSecurity.Logger.LogMessage($"Error querying {record.Class}: {e.Message}", LogTypeIntel.Error);
                            }

                            // Add class results to main results dictionary in a thread-safe manner
                            lock (results)
                            {
                                results[record.Class] = classResults;
                            }
                        }));
                    }
                }

                // Wait for all tasks to complete
                await Task.WhenAll(tasks);
            }
            catch (IOException ex)
            {
                // Throw exception with error message if reading CSV file fails
                throw new InvalidOperationException($"Error reading CSV file: {ex.Message}");
            }

            // Return dictionary containing results for each class
            return results;
        }

        // Helper method to get property value as original type
        private static object GetPropertyOriginalValue(PropertyData prop)
        {
            // Return the value of the property
            return prop.Value;
        }

        // Helper method to read CSV file asynchronously
        private static async Task<List<MdmRecord>> ReadCsvFileAsync(string filePath)
        {
            var records = new List<MdmRecord>();

            using (var reader = new StreamReader(filePath))
            {
                string? line; // Explicitly declare line as nullable
                bool isFirstLine = true;
                while ((line = await reader.ReadLineAsync()) is not null)
                {
                    if (isFirstLine)
                    {
                        isFirstLine = false;
                        continue; // Skip the header line
                    }

                    if (line is null) // This check is redundant but shows explicit handling
                        continue;

                    var values = line.Split(',');
                    // because of using "Comment" column in the CSV file optionally for certain MDM CIMs
                    if (values.Length >= 3)
                    {
                        records.Add(new MdmRecord
                        {
                            Namespace = values[0].Trim(),
                            Class = values[1].Trim(),
                            Authorized = values[2].Trim()
                        });
                    }
                }
            }

            return records;
        }


        // Class to represent a record in the CSV file
        private sealed class MdmRecord
        {
            public string? Namespace { get; set; }
            public string? Class { get; set; }
            public string? Authorized { get; set; }
        }
    }
}
