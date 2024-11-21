using System;
using System.IO;

namespace WDACConfig
{
    public static class Logger
    {
        // The Logs directory
        internal static readonly string LogsDirectory = Path.Combine(GlobalVars.UserConfigDir, "Logs");

        // The Logs file path
        private static readonly string LogFileName = Path.Combine(LogsDirectory, $"WDACConfig_AppLogs_{DateTime.Now:yyyy-MM-dd HH-mm-ss}.txt");

        static Logger()
        {
            // Create the Logs directory if it doesn't exist, won't do anything if it exists
            _ = Directory.CreateDirectory(LogsDirectory);

            // Check the size of the directory and clear it if it exceeds 100 MB
            // To ensure the logs directory doesn't get too big
            if (GetDirectorySize(LogsDirectory) > 100 * 1024 * 1024) // 100 MB in bytes
            {
                // Empty the directory while retaining the most recent file
                EmptyDirectory(LogsDirectory);
            }
        }

        /// <summary>
        /// Write a verbose message to the console
        /// https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostuserinterface
        /// </summary>
        /// <param name="message"></param>
        public static void Write(string message)
        {
            try
            {

                // Write the message to the log file
                using StreamWriter sw = File.AppendText(LogFileName);
                sw.WriteLine($"{DateTime.Now}: {message}");

            }
            // Do not do anything if errors occur
            // Since many methods write to the console or text file asynchronously or in parallel, this might throw errors
            catch { }
        }

        private static long GetDirectorySize(string directoryPath)
        {
            long size = 0;

            // Get all files in the directory and its subdirectories
            FileInfo[] files = new DirectoryInfo(directoryPath).GetFiles("*", SearchOption.AllDirectories);

            foreach (FileInfo file in files)
            {
                // Add the size of each file to the total size
                size += file.Length;
            }

            // Return the total size in bytes
            return size;
        }

        private static void EmptyDirectory(string directoryPath)
        {
            // Get all files in the directory
            FileInfo[] files = new DirectoryInfo(directoryPath).GetFiles();

            // Sort files by last write time in descending order
            Array.Sort(files, (x, y) => y.LastWriteTime.CompareTo(x.LastWriteTime));

            // Retain the most recent file, delete others
            // Start from 1 to skip the most recent file
            for (int i = 1; i < files.Length; i++)
            {
                try
                {
                    // Delete the file
                    files[i].Delete();
                }
                catch
                { }
            }
        }
    }
}
