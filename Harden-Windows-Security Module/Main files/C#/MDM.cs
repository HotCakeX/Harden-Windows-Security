using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Threading.Tasks;

/// root\cimv2\mdm is the namespace for CSPs
/// https://learn.microsoft.com/en-us/windows/win32/wmisdk/common-information-model

namespace HardeningModule
{
    // Class that deals with MDM/CSPs/Intune
    public class MDM
    {
        // Gets the results of all of the Intune policies from the system
        public static Dictionary<string, List<object>> Get()
        {
            // Running the asynchronous method synchronously and returning the result
            return Task.Run(() => GetAsync()).GetAwaiter().GetResult();
        }

        // Asynchronous method to get the results
        private static async Task<Dictionary<string, List<object>>> GetAsync()
        {
            // Set the namespace for MDM queries
            string namespaceName = @"root\cimv2\mdm\dmmap";
            // Set the location of the text file containing the MDM list
            string classNamesFilePath = Path.Combine(HardeningModule.GlobalVars.path, "Resources", "MDMResultClasses.txt");

            // Create a dictionary where keys are the class names and values are lists of results
            Dictionary<string, List<object>> results = new Dictionary<string, List<object>>();

            try
            {
                // Read class names from file asynchronously
                string[] classNames = await File.ReadAllLinesAsync(classNamesFilePath);

                // Create management scope object
                ManagementScope scope = new ManagementScope(namespaceName);
                // Connect to the WMI namespace
                scope.Connect();

                // Create a list of tasks for querying each class
                List<Task> tasks = new List<Task>();

                // Iterate through class names
                foreach (string className in classNames)
                {
                    // Add a new task for each class query
                    tasks.Add(Task.Run(() =>
                    {
                        // List to store results for the current class
                        List<object> classResults = new List<object>();

                        // Create object query for the current class
                        ObjectQuery query = new ObjectQuery("SELECT * FROM " + className.Trim());

                        // Create management object searcher for the query
                        ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);

                        try
                        {
                            // Execute the query and iterate through the results
                            foreach (ManagementObject obj in searcher.Get())
                            {
                                // Dictionary to store properties of the current class instance
                                Dictionary<string, object> classInstance = new Dictionary<string, object>();

                                // Store class name
                                classInstance["Class"] = className;

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
                            // Throw exception with error message if query fails
                            throw new Exception($"Error querying {className}: {e.Message}");
                        }

                        // Add class results to main results dictionary in a thread-safe manner
                        lock (results)
                        {
                            results[className] = classResults;
                        }
                    }));
                }

                // Wait for all tasks to complete
                await Task.WhenAll(tasks);
            }
            catch (IOException ex)
            {
                // Throw exception with error message if reading class names file fails
                throw new Exception($"Error reading class names file: {ex.Message}");
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
    }
}
