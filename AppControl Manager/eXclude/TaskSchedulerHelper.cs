// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

namespace AppControlManager.Others;

// Incompatible with Native AOT

/*

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
			if (results.Count is 0)
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

*/
