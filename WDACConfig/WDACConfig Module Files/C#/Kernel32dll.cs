// Used for resolving global root names of volumes
using System;
using System.Text;
using System.Runtime.InteropServices;

namespace PInvoke
{
    public class Win32Utils
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetVolumePathNamesForVolumeNameW([MarshalAs(UnmanagedType.LPWStr)] string lpszVolumeName,
        [MarshalAs(UnmanagedType.LPWStr)][Out] StringBuilder lpszVolumeNamePaths, uint cchBuferLength,
        ref UInt32 lpcchReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr FindFirstVolume([Out] StringBuilder lpszVolumeName,
        uint cchBufferLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FindNextVolume(IntPtr hFindVolume, [Out] StringBuilder lpszVolumeName, uint cchBufferLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
    }
}
