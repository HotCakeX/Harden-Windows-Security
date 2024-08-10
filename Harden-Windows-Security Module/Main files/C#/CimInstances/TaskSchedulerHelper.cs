using System;
using System.Collections.Generic;
using System.Management;
using System.Globalization;

#nullable enable

namespace HardenWindowsSecurity
{
    public class TaskSchedulerHelper
    {

        // Enums for ScheduledTask
        public enum StateEnum
        {
            Unknown = 0,
            Disabled = 1,
            Queued = 2,
            Ready = 3,
            Running = 4
        }

        public enum CompatibilityEnum
        {
            At = 0,
            V1 = 1,
            Vista = 2,
            Win7 = 3,
            Win8 = 4
        }

        public enum RunLevelEnum
        {
            Limited = 0,
            Highest = 1
        }

        public enum ProcessTokenSidTypeEnum
        {
            None = 0,
            Unrestricted = 1,
            Default = 2
        }

        public enum LogonTypeEnum
        {
            None = 0,
            Password = 1,
            S4U = 2,
            Interactive = 3,
            Group = 4,
            ServiceAccount = 5,
            InteractiveOrPassword = 6
        }

        public enum MultipleInstancesEnum
        {
            Parallel = 0,
            Queue = 1,
            IgnoreNew = 2
        }

        public enum ClusterTaskTypeEnum
        {
            ResourceSpecific = 1,
            AnyNode = 2,
            ClusterWide = 3
        }


        // Enumeration to specify the type of output
        public enum OutputType
        {
            Boolean,    // Returns true/false based on task existence
            TaskList    // Returns a list of ManagementObject tasks
        }

        /// <summary>
        /// Retrieves scheduled tasks from the Task Scheduler based on specified criteria.
        /// </summary>
        /// <param name="taskName">Optional. The name of the task to filter by.</param>
        /// <param name="taskPath">Optional. The path of the task to filter by.</param>
        /// <param name="outputType">Specifies whether to return a boolean or a list of tasks.</param>
        /// <returns>If outputType is Boolean: Returns true if tasks matching the criteria are found, otherwise false.
        /// If outputType is TaskList: Returns a list of ManagementObject containing the matching tasks.</returns>
        /// PowerShell equivalent:
        /// $taskName = 'MSFT Driver Block list update'
        /// $taskPath = '\MSFT Driver Block list update\'
        /// Get-CimInstance -Namespace Root/Microsoft/Windows/TaskScheduler -ClassName MSFT_ScheduledTask | Where-Object { $_.TaskName -eq $taskName -and $_.TaskPath -eq $taskPath }
        public static object Get(string taskName, string taskPath, OutputType outputType)
        {
            try
            {
                // Define the WMI query to select all instances of MSFT_ScheduledTask
                string query = $"SELECT * FROM MSFT_ScheduledTask";

                // Define the WMI namespace
                string scope = @"\\.\Root\Microsoft\Windows\TaskScheduler";

                // Create a ManagementObjectSearcher instance with the query and scope
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query))
                {
                    // Execute the WMI query and retrieve the results
                    using (ManagementObjectCollection results = searcher.Get())
                    {
                        // Initialize a list to store matching tasks
                        List<ManagementObject> matchingTasks = new List<ManagementObject>();

                        // Iterate through each ManagementObject in the results
                        foreach (ManagementObject obj in results)
                        {
                            // Retrieve the TaskName and TaskPath properties from the ManagementObject
                            string? name = obj["TaskName"]?.ToString();
                            string? path = obj["TaskPath"]?.ToString();

                            // Check if the TaskName matches the provided taskName (if specified)
                            // and TaskPath matches the provided taskPath (if specified)
                            bool nameMatches = string.IsNullOrEmpty(taskName) || string.Equals(name, taskName, StringComparison.OrdinalIgnoreCase);
                            bool pathMatches = string.IsNullOrEmpty(taskPath) || string.Equals(path, taskPath, StringComparison.OrdinalIgnoreCase);

                            // If both TaskName and TaskPath match the provided criteria, add the task to the matchingTasks list
                            if (nameMatches && pathMatches)
                            {
                                matchingTasks.Add(obj);
                            }
                        }

                        // Depending on the outputType parameter, return either a boolean or a list of tasks
                        if (outputType == OutputType.Boolean)
                        {
                            return matchingTasks.Count > 0; // Return true if any matching tasks were found, otherwise false
                        }
                        else if (outputType == OutputType.TaskList)
                        {
                            return matchingTasks; // Return the list of matching tasks
                        }
                    }
                }
            }
            catch (ManagementException e)
            {
                // Handle any ManagementException that may occur during the WMI query execution
                HardenWindowsSecurity.VerboseLogger.Write($"An error occurred while querying for WMI data: {e.Message}");

                // Depending on the outputType parameter, return either false or an empty list
                if (outputType == OutputType.Boolean)
                {
                    return false; // Return false indicating no tasks found (error occurred)
                }
                else
                {
                    return new List<ManagementObject>(); // Return an empty list of tasks
                }
            }

            // Default return statement (should not be reached)
            if (outputType == OutputType.Boolean)
            {
                return false; // Return false indicating no tasks found
            }
            else
            {
                return new List<ManagementObject>(); // Return an empty list of tasks
            }
        }

        /// More methods on the way...
    }
}
