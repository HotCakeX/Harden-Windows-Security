using System;
using System.Runtime.InteropServices;

namespace HardeningModule
{
    // Class that contains the results of TPM status checks
    public class TpmResult
    {
        public bool IsEnabled { get; set; }
        public bool IsActivated { get; set; }
    }

    public static class TpmStatus
    {
        // Method to use the Windows APIs to check if the TPM is enabled and activated
        public static TpmResult Get()
        {
            bool isEnabled = false;
            bool isActivated = false;

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
                throw new Exception($"Failed to get TPM IsEnabled status, error code: {result}");
            }

            // Call TpmIsActivated and check result
            result = TpmCoreProvisioningFunctions.TpmIsActivated(out isActivatedByte);
            if (result == 0)
            {
                isActivated = isActivatedByte != 0;
            }
            else
            {
                throw new Exception($"Failed to get TPM IsActivated status, error code: {result}");
            }

            return new TpmResult { IsEnabled = isEnabled, IsActivated = isActivated };
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
