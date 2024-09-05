using Microsoft.Management.Infrastructure.Options;
using Microsoft.Management.Infrastructure;
using System;
using System.Collections.Generic;
using System.Management;
using System.Net.Http;
using System.Linq;

#nullable enable

namespace HardenWindowsSecurity
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
                HardenWindowsSecurity.Logger.LogMessage($"WMI ManagementException: {mex.Message}", LogTypeIntel.Error);
            }
            // Catch block for unauthorized access exceptions
            catch (UnauthorizedAccessException uex)
            {
                HardenWindowsSecurity.Logger.LogMessage($"UnauthorizedAccessException: {uex.Message}", LogTypeIntel.Error);
            }
            // General catch block for any other exceptions
            catch (Exception ex)
            {
                HardenWindowsSecurity.Logger.LogMessage($"An error occurred: {ex.Message}", LogTypeIntel.Error);
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


        public enum FirewallRuleAction
        {
            Enable,
            Disable
        }


        /// <summary>
        /// This method can Add or Remove Firewall rules added to the Group Policy store that are responsible for blocking pre-defined country IP Addresses.
        /// If the same rules already exist, the method will delete the old ones and recreate new ones in order to let the system have up to date IP ranges.
        /// Group Policy is idempotent so it will actively maintain the policies set in it.
        /// Another benefit of using LocalStore is that it supports large arrays of IP addresses.
        /// The default store which goes to Windows firewall store does not support large arrays and throws: "The array bounds are invalid" error.
        /// </summary>
        /// <param name="DisplayName">The DisplayName of the Firewall rule</param>
        /// <param name="ListDownloadURL">Link to the GitHub file that contains the IP Addresses</param>
        /// <param name="ToAdd">If true, the firewall rules will be added. If false, the firewall rules will only be deleted.</param>
        public static void BlockIPAddressListsInGroupPolicy(string DisplayName, string? ListDownloadURL, bool ToAdd)
        {
            // An array to hold the IP Address ranges
            string[] ipList = Array.Empty<string>();

            if (ToAdd)
            {
                if (ListDownloadURL == null)
                {
                    throw new Exception("ListDownloadURL cannot be null when creating Firewall rules.");
                }

                Logger.LogMessage("Downloading the IP Address list", LogTypeIntel.Information);
                // Download the IP Addresses list
                ipList = DownloadIPList(ListDownloadURL);
            }

            // Establish a CIM session to localhost
            CimSession cimSession = CimSession.Create(null);

            // Define options to specify the policy store
            CimOperationOptions options = new CimOperationOptions();
            options.SetCustomOption("PolicyStore", "localhost", mustComply: true);

            // Delete existing rules with the same name
            // it is thorough, any number of firewall rules that match the same name in both inbound and outbound sections of the Group policy firewall rules will be included
            DeleteFirewallRules(cimSession, DisplayName, "localhost");

            if (ToAdd)
            {
                // Create inbound and outbound rules
                CreateFirewallRule(cimSession, DisplayName, ipList, isInbound: true);
                CreateFirewallRule(cimSession, DisplayName, ipList, isInbound: false);
            }

            // Downloads the IP Address list from the GitHub URLs and converts them into string arrays
            string[] DownloadIPList(string URL)
            {
                // Download the fresh list of IPs
                using HttpClient client = new HttpClient();
                HttpResponseMessage response = client.GetAsync(URL).Result;
                string content = response.Content.ReadAsStringAsync().Result;

                // Converts the list from string to string array
                return content.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            }

            // Deletes the Firewall rules
            void DeleteFirewallRules(CimSession cimSession, string ruleName, string policyStore)
            {
                // Define custom options for the operation
                CimOperationOptions options = new CimOperationOptions();
                options.SetCustomOption("PolicyStore", policyStore, mustComply: true);

                // Check for existing rules with the same name and delete them
                var existingRules = cimSession.EnumerateInstances("root/StandardCimv2", "MSFT_NetFirewallRule", options)
                                              .Where(instance => instance.CimInstanceProperties["ElementName"].Value.ToString() == ruleName);

                foreach (var rule in existingRules)
                {
                    cimSession.DeleteInstance("root/StandardCimv2", rule, options);
                    Logger.LogMessage($"Deleted existing firewall rule: {ruleName}", LogTypeIntel.Information);
                }
            }

            // Creates the Firewall rules
            void CreateFirewallRule(CimSession cimSession, string name, string[] ipList, bool isInbound)
            {
                // Define custom options for the operation
                CimOperationOptions options = new CimOperationOptions();
                options.SetCustomOption("PolicyStore", "localhost", mustComply: true);

                // The LocalAddress and RemoteAddress accept String[] type
                // SetCustomOption doesn't support string arrays using 3 overloads variations
                // so we have to use the 4 overload variation that allows us to explicitly define the type
                string[] emptyArray = Array.Empty<string>();
                // Empty array will set it to "Any"
                options.SetCustomOption("LocalAddress", emptyArray, Microsoft.Management.Infrastructure.CimType.StringArray, mustComply: true);
                options.SetCustomOption("RemoteAddress", ipList, Microsoft.Management.Infrastructure.CimType.StringArray, mustComply: true);

                // Define properties for the new firewall rule
                CimInstance newFirewallRule = new CimInstance("MSFT_NetFirewallRule", "root/StandardCimv2");
                newFirewallRule.CimInstanceProperties.Add(CimProperty.Create("ElementName", name, CimFlags.None)); // ElementName is the same as DisplayName
                newFirewallRule.CimInstanceProperties.Add(CimProperty.Create("Description", name, CimFlags.None)); // Setting the Description the same value as the DisplayName
                newFirewallRule.CimInstanceProperties.Add(CimProperty.Create("Direction", (ushort)(isInbound ? 1 : 2), CimFlags.None)); // 1 for Inbound, 2 for Outbound
                newFirewallRule.CimInstanceProperties.Add(CimProperty.Create("Action", (ushort)4, CimFlags.None)); // Block
                newFirewallRule.CimInstanceProperties.Add(CimProperty.Create("Enabled", (ushort)1, CimFlags.None)); // Enable
                newFirewallRule.CimInstanceProperties.Add(CimProperty.Create("Profiles", (ushort)0, CimFlags.None)); // Any
                newFirewallRule.CimInstanceProperties.Add(CimProperty.Create("EdgeTraversalPolicy", (ushort)0, CimFlags.None)); // Block

                // Create the instance
                cimSession.CreateInstance("root/StandardCimv2", newFirewallRule, options);

                Logger.LogMessage($"Successfully created a Firewall rule with the name {name} and the direction {(isInbound ? "Inbound" : "Outbound")}.", LogTypeIntel.Information);
            }
        }
    }
}
