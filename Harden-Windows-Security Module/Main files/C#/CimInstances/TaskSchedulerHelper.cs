using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;

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
                using ManagementObjectSearcher searcher = new(scope, query);

                // Execute the WMI query and retrieve the results
                using ManagementObjectCollection results = searcher.Get();

                // Initialize a list to store matching tasks
                List<ManagementObject> matchingTasks = [];

                // Iterate through each ManagementObject in the results
                foreach (ManagementObject obj in results.Cast<ManagementObject>())
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
            catch (ManagementException e)
            {
                // Handle any ManagementException that may occur during the WMI query execution
                HardenWindowsSecurity.Logger.LogMessage($"An error occurred while querying for WMI data: {e.Message}", LogTypeIntel.Error);

                // Depending on the outputType parameter, return either false or an empty list
                if (outputType == OutputType.Boolean)
                {
                    return false; // Return false indicating no tasks found (error occurred)
                }
                else
                {
                    // Return an empty list of tasks
                    return new List<ManagementObject>();
                }
            }

            // Default return statement (should not be reached)
            if (outputType == OutputType.Boolean)
            {
                return false; // Return false indicating no tasks found
            }
            else
            {
                // Return an empty list of tasks
                return new List<ManagementObject>();
            }
        }



        /// <summary>
        /// Deletes a scheduled task if it exists
        /// </summary>
        /// <param name="taskName">The task name to be deleted</param>
        /// <param name="taskPath">The path where the task is located</param>
        /// <param name="taskFolderName">The folder name of the task must not have and back slashes in it</param>
        /// <returns></returns>
        public static bool Delete(string taskName, string taskPath, string taskFolderName)
        {
            try
            {
                // The WMI query to select the specific instance of MSFT_ScheduledTask
                string query = "SELECT * FROM MSFT_ScheduledTask";

                // Defining the WMI namespace
                string scope = @"\\.\Root\Microsoft\Windows\TaskScheduler";

                // Creating a ManagementObjectSearcher instance with the query and scope
                using ManagementObjectSearcher searcher = new(scope, query);

                // Execute the WMI query and retrieve the results
                using ManagementObjectCollection results = searcher.Get();

                // If no tasks were found, return false
                if (results.Count == 0)
                {
                    HardenWindowsSecurity.Logger.LogMessage($"No tasks found in Task Scheduler.", LogTypeIntel.Warning);
                    return false;
                }

                // Iterate through each ManagementObject in the results
                foreach (ManagementObject obj in results.Cast<ManagementObject>())
                {
                    string? name = obj["TaskName"]?.ToString();
                    string? path = obj["TaskPath"]?.ToString();

                    // Match based on taskName and taskPath
                    if (string.Equals(name, taskName, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(path, taskPath, StringComparison.OrdinalIgnoreCase))
                    {
                        try
                        {
                            // Call DeleteInstance to delete the task
                            obj.Delete();

                            HardenWindowsSecurity.Logger.LogMessage($"Task '{taskName}' with path '{taskPath}' was deleted successfully.", LogTypeIntel.Information);

                            // Return true indicating the task was deleted
                            return true;
                        }
                        catch (ManagementException ex)
                        {
                            HardenWindowsSecurity.Logger.LogMessage($"Failed to delete task '{taskName}' with path '{taskPath}': {ex.Message}", LogTypeIntel.Error);

                            // Return false indicating failure to delete the task
                            return false;
                        }
                    }
                }

                HardenWindowsSecurity.Logger.LogMessage($"No task found with the name '{taskName}' and path '{taskPath}'.", LogTypeIntel.Information);
                return false; // Task not found
            }
            catch (ManagementException e)
            {
                // for any ManagementException that may occur during the WMI query execution
                HardenWindowsSecurity.Logger.LogMessage($"An error occurred while querying for WMI data: {e.Message}", LogTypeIntel.Error);

                // Return false indicating no task was deleted (error occurred)
                return false;
            }
            finally
            {
                // Attempt to delete the task folder whether or not the task itself exists
                DeleteTaskFolder(taskFolderName);
            }
        }

        /// <summary>
        /// Deletes the folder of a scheduled task
        /// same as: (schtasks.exe /Delete /TN "Task Folder Name" /F)
        /// </summary>
        /// <param name="FolderName"></param>
        private static void DeleteTaskFolder(string FolderName)
        {

            // Initialize some variables
            dynamic? rootFolder = null;
            dynamic? scheduleObject = null;

            try
            {

                // Create COM object for Schedule.Service
                Type? schedulerType = Type.GetTypeFromProgID("Schedule.Service");
                scheduleObject = Activator.CreateInstance(schedulerType!);

                // Connect to the service
                scheduleObject!.Connect();

                // Get the root folder
                rootFolder = scheduleObject.GetFolder("\\");

                // Delete the folder with the name
                rootFolder.DeleteFolder(FolderName, null);

                Logger.LogMessage($"Folder named {FolderName} was successfully deleted.", LogTypeIntel.Information);
            }
            catch
            {
                Logger.LogMessage("Couldn't create/connect to Schedule.Service COM Object or the folder could not be deleted.", LogTypeIntel.Error);
            }
            finally
            {
                try
                {
                    // Cleanup (Release the COM objects)
                    if (rootFolder is not null)
                    {
                        Marshal.ReleaseComObject(rootFolder);
                    }

                    if (scheduleObject is not null)
                    {
                        Marshal.ReleaseComObject(scheduleObject);
                    }
                }
                // suppress any errors that might occur during resource clean up
                catch { }
            }
        }
    }
}
