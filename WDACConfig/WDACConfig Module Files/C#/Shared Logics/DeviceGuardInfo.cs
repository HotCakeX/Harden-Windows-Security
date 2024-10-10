using System.Linq;
using System.Management;

#nullable enable

namespace WDACConfig
{

    public class DeviceGuardStatus
    {
        public uint? UsermodeCodeIntegrityPolicyEnforcementStatus { get; set; }
        public uint? CodeIntegrityPolicyEnforcementStatus { get; set; }
    }

    public class DeviceGuardInfo
    {
        /// <summary>
        /// Get the Device Guard status information from the Win32_DeviceGuard WMI class
        /// </summary>
        /// <returns></returns>
        public static DeviceGuardStatus? GetDeviceGuardStatus()
        {
            // Define the WMI query to get the Win32_DeviceGuard class information
            string query = "SELECT UsermodeCodeIntegrityPolicyEnforcementStatus, CodeIntegrityPolicyEnforcementStatus FROM Win32_DeviceGuard";

            // Define the scope (namespace) for the query
            string scope = @"\\.\root\Microsoft\Windows\DeviceGuard";

            // Create a ManagementScope object for the WMI namespace
            ManagementScope managementScope = new(scope);

            // Create an ObjectQuery to specify the WMI query
            ObjectQuery objectQuery = new(query);

            // Create a ManagementObjectSearcher to execute the query
            using (ManagementObjectSearcher searcher = new(managementScope, objectQuery))
            {
                // Execute the query and retrieve the results
                foreach (ManagementObject obj in searcher.Get().Cast<ManagementObject>())
                {
                    // Create an instance of the custom class to hold the result
                    DeviceGuardStatus status = new()
                    {
                        // Retrieve the relevant properties and assign them to the class
                        UsermodeCodeIntegrityPolicyEnforcementStatus = obj["UsermodeCodeIntegrityPolicyEnforcementStatus"] as uint?,
                        CodeIntegrityPolicyEnforcementStatus = obj["CodeIntegrityPolicyEnforcementStatus"] as uint?
                    };

                    return status;  // Return the first instance (assuming one instance)
                }
            }

            return new DeviceGuardStatus();
        }
    }
}
