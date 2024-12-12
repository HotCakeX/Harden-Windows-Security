using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace HardenWindowsSecurity
{
    internal static class GetOneDriveDirectories
    {

        /// <summary>
        /// Retrieves the paths to all OneDrive directories on the system
        /// These paths are under each user directory can start with OneDrive such as "OneDrive", "OneDrive Personal", "OneDrive Business" etc.
        /// </summary>
        /// <returns></returns>
        internal static List<string> Get()
        {
            // List to store the OneDrive directories found
            List<string> directoriesList = [];

            // Retrieve the system drive
            string systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? string.Empty;

            if (string.IsNullOrEmpty(systemDrive))
            {
                throw new InvalidOperationException("SystemDrive environment variable is not set.");
            }

            // Combine system drive with "Users" to get the path to the Users directory
            string usersPath = Path.Combine(systemDrive, "Users");

            try
            {
                // Enumerate all top-level directories under the Users directory
                IEnumerable<string> userDirectories = Directory.EnumerateDirectories(usersPath);

                foreach (string userDirectory in userDirectories)
                {
                    try
                    {
                        // Enumerate directories within each user directory that start with "OneDrive"
                        IEnumerable<string> directories = Directory.EnumerateDirectories(userDirectory, "OneDrive*", SearchOption.TopDirectoryOnly)
                                                   .Where(dir => dir.StartsWith(Path.Combine(userDirectory, "OneDrive"), StringComparison.OrdinalIgnoreCase));

                        // Add each found directory to the list
                        directoriesList.AddRange(directories);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        // If access is denied to a directory, skip it
                        continue;
                    }
                    catch (DirectoryNotFoundException)
                    {
                        // If a directory is not found (e.g., it was deleted), skip it
                        continue;
                    }
                }
            }
            catch (Exception ex)
            {
                // If an unexpected error occurs, handle it as necessary (e.g., log it)
                Logger.LogMessage($"An error occurred: {ex.Message}", LogTypeIntel.Error);
            }

            // Return the list of OneDrive directories found
            return directoriesList;
        }
    }
}
