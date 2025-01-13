using System;
using System.Diagnostics.Eventing.Reader;
using System.IO;

namespace AppControlManager.Others;

internal static class EventLogUtility
{

	private const string logName = "Microsoft-Windows-CodeIntegrity/Operational";

	/// <summary>
	/// Increase Code Integrity Operational Event Logs size from the default 1MB to user-defined size.
	/// Also automatically increases the log size by 1MB if the current free space is less than 1MB and the current maximum log size is less than or equal to 10MB.
	/// This is to prevent infinitely expanding the max log size automatically.
	/// </summary>
	/// <param name="logSize">Size of the Code Integrity Operational Event Log</param>
	internal static void SetLogSize(ulong logSize = 0)
	{
		Logger.Write("Setting the Code Integrity Log Size");

		using EventLogConfiguration logConfig = new(logName);
		string logFilePath = Environment.ExpandEnvironmentVariables(logConfig.LogFilePath);
		FileInfo logFileInfo = new(logFilePath);
		long currentLogFileSize = logFileInfo.Length;
		long currentLogMaxSize = logConfig.MaximumSizeInBytes;

		if (logSize == 0)
		{
			if ((currentLogMaxSize - currentLogFileSize) < 1 * 1024 * 1024)
			{
				if (currentLogMaxSize <= 10 * 1024 * 1024)
				{
					Logger.Write("Increasing the Code Integrity log size by 1MB because its current free space is less than 1MB.");
					logConfig.MaximumSizeInBytes = currentLogMaxSize + 1 * 1024 * 1024;
					logConfig.IsEnabled = true;
					logConfig.SaveChanges();
				}
			}
		}
		else
		{
			// Check if the provided log size is greater than 1100 KB
			// To prevent from disabling the log or setting it to a very small size that is lower than its default size
			if (logSize > 1100 * 1024)
			{
				Logger.Write($"Setting Code Integrity log size to {logSize}.");
				logConfig.MaximumSizeInBytes = (long)logSize;
				logConfig.IsEnabled = true;
				logConfig.SaveChanges();
			}
			else
			{
				Logger.Write("Provided log size is less than or equal to 1100 KB. No changes made.");
			}
		}
	}


	/// <summary>
	/// Gets the Code Integrity Operational Log Max capacity in Double
	/// </summary>
	/// <returns></returns>
	internal static double GetCurrentLogSize()
	{
		Logger.Write("Getting the Code Integrity Log Capacity");

		try
		{
			using EventLogConfiguration logConfig = new(logName);
			long logCapacityBytes = logConfig.MaximumSizeInBytes;

			// Convert bytes to megabytes
			double logCapacityMB = logCapacityBytes / (1024.0 * 1024.0);

			Logger.Write($"Log capacity: {logCapacityMB:F2} MB.");

			return logCapacityMB;
		}
		catch (Exception ex)
		{
			Logger.Write($"An error occurred while retrieving the log capacity: {ex.Message}");
			throw;
		}
	}


}
