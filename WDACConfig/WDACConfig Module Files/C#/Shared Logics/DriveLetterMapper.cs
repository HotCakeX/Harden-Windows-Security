using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

#nullable enable

#pragma warning disable CA1838 // Avoid 'StringBuilder' parameters for P/Invoke methods

namespace WDACConfig
{
    public static class DriveLetterMapper
    {
        // Importing the GetVolumePathNamesForVolumeNameW function from kernel32.dll
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetVolumePathNamesForVolumeNameW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpszVolumeName,
            [MarshalAs(UnmanagedType.LPWStr)][Out] StringBuilder lpszVolumeNamePaths,
            uint cchBuferLength,
            ref UInt32 lpcchReturnLength);

        // Importing the FindFirstVolume function from kernel32.dll
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr FindFirstVolume(
            [Out] StringBuilder lpszVolumeName,
            uint cchBufferLength);

        // Importing the FindNextVolume function from kernel32.dll
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool FindNextVolume(
            IntPtr hFindVolume,
            [Out] StringBuilder lpszVolumeName,
            uint cchBufferLength);

        // Importing the QueryDosDevice function from kernel32.dll
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern uint QueryDosDevice(
            string lpDeviceName,
            StringBuilder lpTargetPath,
            int ucchMax);

        // Class to store drive mapping information
        public class DriveMapping
        {
            // Property to store drive letter
            public string? DriveLetter { get; set; }
            // Property to store device path
            public string? DevicePath { get; set; }
            // Property to store volume name
            public string? VolumeName { get; set; }
        }

        /// <summary>
        /// A method that gets the DriveLetter mappings in the global root namespace
        /// And fixes these: \Device\Harddiskvolume
        /// </summary>
        /// <returns>A list of DriveMapping objects containing drive information</returns>
        /// <exception cref="System.ComponentModel.Win32Exception"></exception>
        public static List<DriveMapping> GetGlobalRootDrives()
        {
            // List to store drive mappings
            var drives = new List<DriveMapping>();
            // Maximum buffer size for volume names, paths, and mount points
            uint max = 65535;
            // StringBuilder for storing volume names
            var sbVolumeName = new StringBuilder((int)max);
            // StringBuilder for storing path names
            var sbPathName = new StringBuilder((int)max);
            // StringBuilder for storing mount points
            var sbMountPoint = new StringBuilder((int)max);
            // Variable to store the length of the return string
            uint lpcchReturnLength = 0;

            // Get the first volume handle
            IntPtr volumeHandle = FindFirstVolume(sbVolumeName, max);

            // Check if the volume handle is valid
            if (volumeHandle == IntPtr.Zero)
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            // Loop through all the volumes
            do
            {
                // Convert the volume name to a string
                string volume = sbVolumeName.ToString();
                // Get the mount point for the volume
                _ = GetVolumePathNamesForVolumeNameW(volume, sbMountPoint, max, ref lpcchReturnLength);
                // Get the device path for the volume
                uint returnLength = QueryDosDevice(volume.Substring(4, volume.Length - 5), sbPathName, (int)max);

                // Check if the device path is found
                if (returnLength > 0)
                {
                    // Add the drive mapping to the list
                    drives.Add(new DriveMapping
                    {
                        DriveLetter = sbMountPoint.ToString(),
                        VolumeName = volume,
                        DevicePath = sbPathName.ToString()
                    });
                }
                else
                {
                    // Add the drive mapping with no mount point found
                    drives.Add(new DriveMapping
                    {
                        DriveLetter = null,
                        VolumeName = volume,
                        DevicePath = "No mountpoint found"
                    });
                }

            } while (FindNextVolume(volumeHandle, sbVolumeName, max)); // Continue until there are no more volumes

            // Return the list of drive mappings
            return drives;
        }
    }
}
