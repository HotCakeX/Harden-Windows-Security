using System;
using Microsoft.Win32;

namespace HardeningModule
{
    public static class GlobalVars
    {
        // Minimum required OS build number
        public const string Requiredbuild = "22621.3155";

        // Current OS build version
        public static readonly int OSBuildNumber = Environment.OSVersion.Version.Build;

        // Update Build Revision (UBR) number
        public static readonly int UBR;

        // Create full OS build number as seen in Windows Settings
        public static readonly string FullOSBuild;

        public static int TotalNumberOfTrueCompliantValues = 238;

        // Stores the value of $PSScriptRoot in a global constant variable to allow the internal functions to use it when navigating the module structure
        public static string path;
        public static object MDAVConfigCurrent;
        public static object MDAVPreferencesCurrent;


        // Static constructor for the GlobalVars class
        static GlobalVars()
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
            {
                if (key != null)
                {
                    object ubrValue = key.GetValue("UBR");
                    if (ubrValue != null && int.TryParse(ubrValue.ToString(), out int ubr))
                    {
                        UBR = ubr;
                    }
                    else
                    {
                        UBR = -1; // Default value in case of error
                    }
                }
                else
                {
                    UBR = -1; // Default value in case the registry key is not found
                }
            }

            // Concatenate OSBuildNumber and UBR to form the final string
            FullOSBuild = $"{OSBuildNumber}.{UBR}";
        }
    }
}
