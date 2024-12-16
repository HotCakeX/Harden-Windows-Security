using System;
using System.Linq;
using System.Management;
using AppControlManager.Logging;

namespace AppControlManager;

internal static class TaskSchedulerHelper
{
	/// <summary>
	/// Deletes a scheduled task if it exists
	/// </summary>
	/// <param name="taskName">The task name to be deleted</param>
	/// <param name="taskPath">The path where the task is located</param>
	/// <returns></returns>
	internal static void Delete(string taskName, string taskPath)
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
				Logger.Write("No tasks found in Task Scheduler.");
				return;
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

						Logger.Write($"Task '{taskName}' with path '{taskPath}' was deleted successfully.");

						return;
					}
					catch (ManagementException ex)
					{
						Logger.Write($"Failed to delete task '{taskName}' with path '{taskPath}': {ex.Message}");
						return;
					}
				}
			}

			Logger.Write($"No task found with the name '{taskName}' and path '{taskPath}'.");
		}
		catch (ManagementException e)
		{
			// for any ManagementException that may occur during the WMI query execution
			Logger.Write($"An error occurred while querying for WMI data: {e.Message}");
		}
	}
}
