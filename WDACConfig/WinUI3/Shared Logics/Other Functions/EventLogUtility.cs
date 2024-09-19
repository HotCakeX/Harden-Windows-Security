using System;
using System.Diagnostics.Eventing.Reader;
using System.IO;

#nullable enable

namespace WDACConfig
{
    public static class EventLogUtility
    {
        /// <summary>
        /// Increase Code Integrity Operational Event Logs size from the default 1MB to user-defined size.
        /// Also automatically increases the log size by 1MB if the current free space is less than 1MB and the current maximum log size is less than or equal to 10MB.
        /// This is to prevent infinitely expanding the max log size automatically.
        /// </summary>
        /// <param name="logSize">Size of the Code Integrity Operational Event Log</param>
        public static void SetLogSize(ulong logSize = 0)
        {
            WDACConfig.Logger.Write("Set-SetLogSize method started...");

            string logName = "Microsoft-Windows-CodeIntegrity/Operational";

            using var logConfig = new EventLogConfiguration(logName);
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
                        WDACConfig.Logger.Write("Increasing the Code Integrity log size by 1MB because its current free space is less than 1MB.");
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
                    WDACConfig.Logger.Write($"Setting Code Integrity log size to {logSize}.");
                    logConfig.MaximumSizeInBytes = (long)logSize;
                    logConfig.IsEnabled = true;
                    logConfig.SaveChanges();
                }
                else
                {
                    WDACConfig.Logger.Write("Provided log size is less than or equal to 1100 KB. No changes made.");
                }
            }
        }
    }
}
