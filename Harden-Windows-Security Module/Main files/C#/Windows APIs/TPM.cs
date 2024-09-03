using System;
using System.Runtime.InteropServices;
using System.Globalization;

#nullable enable

namespace HardenWindowsSecurity
{
    // Class that contains the results of TPM status checks
    internal class TpmResult
    {
        internal bool IsEnabled { get; set; }
        internal bool IsActivated { get; set; }
        internal string? ErrorMessage { get; set; }
    }

    internal static class TpmStatus
    {
        // Method to use the Windows APIs to check if the TPM is enabled and activated
        internal static TpmResult Get()
        {
            bool isEnabled = false;
            bool isActivated = false;
            string? errorMessage = null;

            byte isEnabledByte;
            byte isActivatedByte;

            // Call TpmIsEnabled and check result
            uint result = TpmCoreProvisioningFunctions.TpmIsEnabled(out isEnabledByte);
            if (result == 0)
            {
                isEnabled = isEnabledByte != 0;
            }
            else
            {
                errorMessage = $"{result}";
            }

            // Call TpmIsActivated and check result
            result = TpmCoreProvisioningFunctions.TpmIsActivated(out isActivatedByte);
            if (result == 0)
            {
                isActivated = isActivatedByte != 0;
            }
            else
            {
                errorMessage = $"{result}";
            }

            return new TpmResult { IsEnabled = isEnabled, IsActivated = isActivated, ErrorMessage = errorMessage };
        }

        // Class that imports TpmCoreProvisioning.dll and use its exported functions
        private static class TpmCoreProvisioningFunctions
        {
            [DllImport("TpmCoreProvisioning", CharSet = CharSet.Unicode)]
            internal static extern uint TpmIsEnabled(out byte pfIsEnabled);

            [DllImport("TpmCoreProvisioning", CharSet = CharSet.Unicode)]
            internal static extern uint TpmIsActivated(out byte pfIsActivated);
        }
    }
}
