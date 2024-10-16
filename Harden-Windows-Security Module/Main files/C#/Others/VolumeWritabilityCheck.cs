using System;
using System.Collections.Generic;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    internal static partial class VolumeWritabilityCheck
    {
        /// <summary>
        /// Gets a list of BitLockerVolumes and returns only those that are writable
        /// </summary>
        /// <param name="Volumes"></param>
        /// <returns></returns>
        public static List<BitLocker.BitLockerVolume>? GetWritableVolumes(List<BitLocker.BitLockerVolume>? Volumes)
        {

            if (Volumes is null)
            {
                return null;
            }

            // List to store the available writable volumes
            List<BitLocker.BitLockerVolume>? availableWritableVolumes = [];

            // Iterate over each volume
            foreach (var Volume in Volumes)
            {

                if (Volume.MountPoint is null)
                {
                    Logger.LogMessage($"A volume with the size {Volume.CapacityGB} has null mount point.", LogTypeIntel.Warning);
                    continue;
                }

                // Create a random file name using GUID
                string GUID = System.Guid.NewGuid().ToString().Replace("-", "", StringComparison.OrdinalIgnoreCase);

                try
                {
                    // Create a test file on the volume to check if it's writable
                    string testFilePath = Path.Combine(Volume.MountPoint, $"{GUID}.txt");
                    using (FileStream fs = File.Create(testFilePath))
                    {
                        // Write some data
                        byte[] testData = new System.Text.UTF8Encoding(true).GetBytes("test");
                        fs.Write(testData, 0, testData.Length);
                    }

                    // If no exception occurs, the volume is writable, so delete the test file
                    File.Delete(testFilePath);

                    // Add the Volume to the list if it was writable
                    availableWritableVolumes.Add(Volume);
                }
                catch (UnauthorizedAccessException)
                {
                    // If an UnauthorizedAccessException occurs, the Volume is likely write-protected
                    // Do nothing, just skip adding this volume
                }
                catch (Exception ex)
                {
                    Logger.LogMessage($"Error accessing volume {Volume.MountPoint}: {ex.Message}", LogTypeIntel.Error);
                }
            }

            // Return the list of available writable volumes
            return availableWritableVolumes;
        }
    }
}
