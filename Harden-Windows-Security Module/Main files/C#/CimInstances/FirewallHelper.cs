using System;
using System.Collections.Generic;
using System.Management;

namespace HardeningModule
{
    public static class FirewallHelper
    {
        // Method to get firewall rules based on RuleGroup and Direction
        public static List<ManagementObject> GetFirewallRules(string ruleGroup, ushort direction)
        {
            string namespacePath = @"root\standardcimv2";
            string className = "MSFT_NetFirewallRule";

            // List to store results
            List<ManagementObject> results = new List<ManagementObject>();

            try
            {
                // Create management scope and connect
                ManagementScope scope = new ManagementScope(namespacePath);
                scope.Connect();

                // Ensure the connection is established
                if (!scope.IsConnected)
                {
                    throw new InvalidOperationException("Failed to connect to WMI namespace.");
                }

                // Retrieve all firewall rules
                ObjectQuery query = new ObjectQuery($"SELECT * FROM {className}");
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query))
                using (ManagementObjectCollection queryCollection = searcher.Get())
                {
                    foreach (ManagementObject mObject in queryCollection)
                    {
                        // Filter results based on RuleGroup and Direction
                        // supplying the RuleGroup directly wouldn't work
                        // This however works in PowerShell:
                        // Get-CimInstance -Namespace 'root/standardcimv2' -ClassName 'MSFT_NetFirewallRule' |
                        // Where-Object {
                        // ($_.RuleGroup -eq '@%SystemRoot%\system32\firewallapi.dll,-37302') -and
                        // ($_.Direction -eq '1')
                        // }
                        // OR this
                        // Get-NetFirewallRule | Where-Object -FilterScript {
                        // ($_.RuleGroup -eq '@%SystemRoot%\system32\firewallapi.dll,-37302') -and
                        // ($_.Direction -eq 'inbound')
                        // }
                        if (mObject["RuleGroup"]?.ToString() == ruleGroup && (ushort)mObject["Direction"] == direction)
                        {
                            results.Add(mObject);
                        }
                    }
                }
            }
            // catch exceptions specific to WMI
            catch (ManagementException mex)
            {
                HardeningModule.VerboseLogger.Write($"WMI ManagementException: {mex.Message}");
            }
            // Catch block for unauthorized access exceptions
            catch (UnauthorizedAccessException uex)
            {
                HardeningModule.VerboseLogger.Write($"UnauthorizedAccessException: {uex.Message}");
            }
            // General catch block for any other exceptions
            catch (Exception ex)
            {
                HardeningModule.VerboseLogger.Write($"An error occurred: {ex.Message}");
            }

            return results;
        }


        public enum NetSecurityEnabled : ushort
        {
            True = 1,
            False = 2
        }

        [Flags]
        public enum NetSecurityProfile : ushort
        {
            Any = 0,
            Public = 4,
            Private = 2,
            Domain = 1,
            NotApplicable = 65535
        }

        public enum NetSecurityDirection : ushort
        {
            Inbound = 1,
            Outbound = 2
        }

        public enum NetSecurityAction : ushort
        {
            NotConfigured = 0,
            Allow = 2,
            Block = 4
        }

        public enum NetSecurityEdgeTraversal : ushort
        {
            Block = 0,
            Allow = 1,
            DeferToUser = 2,
            DeferToApp = 3
        }

        public enum NetSecurityPrimaryStatus : ushort
        {
            Unknown = 0,
            OK = 1,
            Inactive = 2,
            Error = 3
        }

        public enum NetSecurityPolicyStoreType : ushort
        {
            None = 0,
            Local = 1,
            GroupPolicy = 2,
            Dynamic = 3,
            Generated = 4,
            Hardcoded = 5,
            MDM = 6,
            HostFirewallLocal = 8,
            HostFirewallGroupPolicy = 9,
            HostFirewallDynamic = 10,
            HostFirewallMDM = 11
        }

        [Flags]
        public enum NetSecurityDynamicTransport : uint
        {
            Any = 0,
            ProximityApps = 1,
            ProximitySharing = 2,
            WifiDirectPrinting = 4,
            WifiDirectDisplay = 8,
            WifiDirectDevices = 16
        }

        [Flags]
        public enum NetSecurityInterfaceType : uint
        {
            Any = 0,
            Wired = 1,
            Wireless = 2,
            RemoteAccess = 4
        }

        public enum NetSecurityAuthentication : ushort
        {
            NotRequired = 0,
            Required = 1,
            NoEncap = 2
        }

        public enum NetSecurityEncryption : ushort
        {
            NotRequired = 0,
            Required = 1,
            Dynamic = 2
        }
    }
}
