using System;
using System.Runtime.InteropServices;
using System.ComponentModel;

namespace HardenWindowsSecurity
{
    public class OSVersionInfo
    {
        // Import the GetVersionEx function from kernel32.dll for OS version information
        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetVersionEx(ref OSVERSIONINFOEX osVersion);

        // Struct to hold OS version information
        // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-osversioninfoexa
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct OSVERSIONINFOEX
        {
            public uint dwOSVersionInfoSize; // Size of the structure
            public uint dwMajorVersion;       // Major version number
            public uint dwMinorVersion;       // Minor version number
            public uint dwBuildNumber;        // Build number
            public uint dwPlatformId;         // Platform identifier
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;       // Service pack identifier
            public ushort wServicePackMajor;  // Major service pack number
            public ushort wServicePackMinor;  // Minor service pack number
            public ushort wSuiteMask;          // Suite mask
            public byte wProductType;          // Product type
            public byte wReserved;             // Reserved for future use
        }

        // Class to hold detailed OS version information and return in the end
        public class OSVersionDetails
        {
            public uint MajorVersion { get; set; }
            public uint MinorVersion { get; set; }
            public uint BuildNumber { get; set; }
            public string ServicePack { get; set; }
            public ushort ServicePackMajor { get; set; }
            public ushort ServicePackMinor { get; set; }
            public ushort SuiteMask { get; set; }
            public string SuiteMaskDetails { get; set; }
            public byte ProductType { get; set; }
            public string ProductTypeDetails { get; set; }
        }

        // Method to get the OS version details
        public static OSVersionDetails GetOSVersion()
        {
            OSVERSIONINFOEX osVersion = new OSVERSIONINFOEX
            {
                // Set the size of the OSVERSIONINFOEX structure
                dwOSVersionInfoSize = (uint)Marshal.SizeOf<OSVERSIONINFOEX>()
            };

            // Call the GetVersionEx function and check for errors
            if (!GetVersionEx(ref osVersion))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            // Populate and return an OSVersionDetails object with the retrieved information
            return new OSVersionDetails
            {
                MajorVersion = osVersion.dwMajorVersion,
                MinorVersion = osVersion.dwMinorVersion,
                BuildNumber = osVersion.dwBuildNumber,
                ServicePack = osVersion.szCSDVersion,
                ServicePackMajor = osVersion.wServicePackMajor,
                ServicePackMinor = osVersion.wServicePackMinor,
                SuiteMask = osVersion.wSuiteMask,
                SuiteMaskDetails = GetSuiteMaskDetails(osVersion.wSuiteMask),
                ProductType = osVersion.wProductType,
                ProductTypeDetails = GetProductTypeDetails(osVersion.wProductType)
            };
        }

        // Method to get details based on the suite mask
        private static string GetSuiteMaskDetails(ushort suiteMask)
        {
            // Array of suite names and corresponding flags
            string[] suiteNames = { "Enterprise", "BackOffice", "Communications", "Terminal",
                                    "SmallBusiness", "Enterprise", "EmbeddedNT", "Datacenter",
                                    "SingleUserTS", "Personal", "Blade", "StorageServer",
                                    "ComputeCluster", "HomeServer" };
            ushort[] suiteFlags = { 0x0002, 0x0004, 0x0008, 0x0010,
                                    0x0020, 0x0040, 0x0080, 0x0100,
                                    0x0200, 0x0400, 0x0800, 0x2000,
                                    0x4000, 0x8000 };

            var details = new System.Text.StringBuilder();
            // Loop through the flags and append corresponding names
            for (int i = 0; i < suiteFlags.Length; i++)
            {
                if ((suiteMask & suiteFlags[i]) != 0)
                {
                    details.Append(suiteNames[i]).Append(" ");
                }
            }
            return details.ToString().Trim(); // Return concatenated string of suite details
        }

        // Method to get product type details based on product type byte
        private static string GetProductTypeDetails(byte productType)
        {
            return productType switch
            {
                1 => "Workstation",
                2 => "Domain Controller",
                3 => "Server",
                _ => "Unknown"
            };
        }
    }
}
