using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;

namespace AppControlManager.IntelGathering
{
    internal static partial class DriveLetterMapper
    {
        [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16, EntryPoint = "FindFirstVolumeW")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static partial IntPtr FindFirstVolume(
            [MarshalUsing(CountElementName = "cchBufferLength")][Out] char[] lpszVolumeName,
            uint cchBufferLength);

        [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16, EntryPoint = "FindNextVolumeW")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool FindNextVolume(
            IntPtr hFindVolume,
            [MarshalUsing(CountElementName = "cchBufferLength")][Out] char[] lpszVolumeName,
            uint cchBufferLength);

        [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16, EntryPoint = "QueryDosDeviceW")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static partial uint QueryDosDevice(
            string lpDeviceName,
            [MarshalUsing(CountElementName = "ucchMax")][Out] char[] lpTargetPath,
            int ucchMax);

        [LibraryImport("kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16, EntryPoint = "GetVolumePathNamesForVolumeNameW")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool GetVolumePathNamesForVolumeNameW(
            [MarshalAs(UnmanagedType.LPWStr)] string lpszVolumeName,
            [MarshalUsing(CountElementName = "cchBuferLength")][Out] char[] lpszVolumeNamePaths,
            uint cchBuferLength,
            ref uint lpcchReturnLength);


        // Class to store drive mapping information
        internal sealed class DriveMapping
        {
            // Property to store drive letter
            internal string? DriveLetter { get; set; }
            // Property to store device path
            internal string? DevicePath { get; set; }
            // Property to store volume name
            internal string? VolumeName { get; set; }
        }

        /// <summary>
        /// A method that gets the DriveLetter mappings in the global root namespace
        /// And fixes these: \Device\Harddiskvolume
        /// </summary>
        /// <returns>A list of DriveMapping objects containing drive information</returns>
        /// <exception cref="System.ComponentModel.Win32Exception"></exception>
        internal static List<DriveMapping> GetGlobalRootDrives()
        {
            // List to store drive mappings
            List<DriveMapping> drives = [];
            // Maximum buffer size for volume names, paths, and mount points
            uint max = 65535;
            // char[] for storing volume names
            char[] volumeNameBuffer = new char[max];
            // char[] for storing path names
            char[] pathNameBuffer = new char[max];
            // char[] for storing mount points
            char[] mountPointBuffer = new char[max];
            // Variable to store the length of the return string
            uint lpcchReturnLength = 0;

            // Get the first volume handle
            IntPtr volumeHandle = FindFirstVolume(volumeNameBuffer, max);

            // Check if the volume handle is valid
            if (volumeHandle == IntPtr.Zero)
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            // Loop through all the volumes
            do
            {
                // Convert the volume name to a string, trimming any leftover null characters
                string volume = new string(volumeNameBuffer).TrimEnd('\0');
                // Get the mount point for the volume
                _ = GetVolumePathNamesForVolumeNameW(volume, mountPointBuffer, max, ref lpcchReturnLength);
                // Get the device path for the volume
                uint returnLength = QueryDosDevice(volume[4..^1], pathNameBuffer, (int)max);

                // Check if the device path is found
                if (returnLength > 0)
                {
                    // Add a new drive mapping to the list with valid details
                    drives.Add(new DriveMapping
                    {
                        // Extract the drive letter (mount point) from the buffer
                        // Use Array.IndexOf to locate the first null character ('\0')
                        // If null is not found, use the entire length of the buffer
                        // Replace ":\" with ":" for consistent formatting
                        DriveLetter = new string(mountPointBuffer, 0, Array.IndexOf(mountPointBuffer, '\0') >= 0
                            ? Array.IndexOf(mountPointBuffer, '\0')
                            : mountPointBuffer.Length)
                            .Replace(@":\", ":", StringComparison.OrdinalIgnoreCase),

                        // Assign the current volume name
                        VolumeName = volume,

                        // Extract the device path from the buffer
                        // Use Array.IndexOf to locate the first null character ('\0')
                        // If null is not found, use the entire length of the buffer
                        DevicePath = new string(pathNameBuffer, 0, Array.IndexOf(pathNameBuffer, '\0') >= 0
                            ? Array.IndexOf(pathNameBuffer, '\0')
                            : pathNameBuffer.Length)
                    });
                }
                else
                {
                    // Add a new drive mapping with "No mountpoint found" when the path is invalid
                    drives.Add(new DriveMapping
                    {
                        // No drive letter since the mount point is unavailable
                        DriveLetter = null,

                        // Assign the current volume name
                        VolumeName = volume,

                        // Assign a placeholder string indicating no mount point is found
                        DevicePath = "No mountpoint found"
                    });
                }

            } while (FindNextVolume(volumeHandle, volumeNameBuffer, max)); // Continue until there are no more volumes

            // Return the list of drive mappings
            return drives;
        }
    }
}
