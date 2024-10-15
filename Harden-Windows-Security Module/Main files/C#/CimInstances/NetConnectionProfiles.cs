using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;

#nullable enable

namespace HardenWindowsSecurity
{
    public class NetConnectionProfiles
    {
        /// <summary>
        /// This method outputs a list of all network connection profiles.
        /// The output is precisely the same as the output of the Get-NetConnectionProfile cmdlet in PowerShell.
        /// </summary>
        /// <returns></returns>
        public static List<ManagementObject> Get()
        {
            // Create a list to store the profiles
            List<ManagementObject> profiles = [];

            try
            {
                // Define the namespace, class, and query string
                string namespaceName = @"root\StandardCimv2";
                string className = "MSFT_NetConnectionProfile";
                string queryString = $"SELECT * FROM {className}";

                // Create a ManagementScope object and connect to it
                ManagementScope scope = new(namespaceName);
                scope.Connect();

                // Create a ManagementObjectQuery object and a ManagementObjectSearcher object
                ObjectQuery query = new(queryString);

                using ManagementObjectSearcher searcher = new(scope, query);

                // Execute the query and store the results in a ManagementObjectCollection object
                ManagementObjectCollection queryCollection = searcher.Get();

                // Add each profile to the list
                foreach (ManagementObject m in queryCollection.Cast<ManagementObject>())
                {
                    profiles.Add(m);
                }
            }
            catch (Exception e)
            {
                HardenWindowsSecurity.Logger.LogMessage($"An error occurred: {e.Message}", LogTypeIntel.Error);
            }

            // Return the list of profiles
            return profiles;
        }

        /// <summary>
        /// This method sets the NetworkCategory of network connection profiles based on InterfaceIndex or InterfaceAlias.
        /// </summary>
        /// <param name="interfaceIndices">Array of InterfaceIndex values of the network connection profiles.</param>
        /// <param name="interfaceAliases">Array of InterfaceAlias values of the network connection profiles.</param>
        /// <param name="networkCategory">The new NetworkCategory to set.</param>
        /// PS Example: [HardenWindowsSecurity.NetConnectionProfiles]::Set((3, 22), $null, [HardenWindowsSecurity.NetConnectionProfiles+NetworkCategory]::public)
        /// PS Example: [HardenWindowsSecurity.NetConnectionProfiles]::Set($null, ('Ethernet', 'Wi-Fi'), [HardenWindowsSecurity.NetConnectionProfiles+NetworkCategory]::private)
        /// <returns>True if successful, otherwise false.</returns>
        public static bool Set(NetworkCategory networkCategory, int[]? interfaceIndices = null, string[]? interfaceAliases = null)
        {
            try
            {
                // Define the namespace and class
                string namespaceName = @"root\StandardCimv2";
                string className = "MSFT_NetConnectionProfile";
                ManagementScope scope = new(namespaceName);
                scope.Connect();

                // Process interface indices
                if (interfaceIndices is not null)
                {
                    foreach (int index in interfaceIndices)
                    {
                        string queryString = $"SELECT * FROM {className} WHERE InterfaceIndex = {index}";
                        UpdateNetworkCategory(scope, queryString, networkCategory);
                    }
                }

                // Process interface aliases
                if (interfaceAliases is not null)
                {
                    foreach (string alias in interfaceAliases)
                    {
                        string queryString = $"SELECT * FROM {className} WHERE InterfaceAlias = '{alias}'";
                        UpdateNetworkCategory(scope, queryString, networkCategory);
                    }
                }

                return true;
            }
            catch (Exception e)
            {
                HardenWindowsSecurity.Logger.LogMessage($"An error occurred: {e.Message}", LogTypeIntel.Error);
                return false;
            }
        }

        private static void UpdateNetworkCategory(ManagementScope scope, string queryString, NetworkCategory networkCategory)
        {
            ObjectQuery query = new(queryString);

            using ManagementObjectSearcher searcher = new(scope, query);

            ManagementObjectCollection queryCollection = searcher.Get();

            foreach (ManagementObject m in queryCollection.Cast<ManagementObject>())
            {
                m["NetworkCategory"] = (uint)networkCategory;
                _ = m.Put();
            }
        }

        // The following enums are used to represent the properties of the MSFT_NetConnectionProfile class
        public enum NetworkCategory : uint
        {
            Public = 0,
            Private = 1,
            DomainAuthenticated = 2
        }

        public enum DomainAuthenticationKind : uint
        {
            None = 0,
            Ldap = 1,
            Tls = 2
        }

        public enum IPv4Connectivity : uint
        {
            Disconnected = 0,
            NoTraffic = 1,
            Subnet = 2,
            LocalNetwork = 3,
            Internet = 4
        }

        public enum IPv6Connectivity : uint
        {
            Disconnected = 0,
            NoTraffic = 1,
            Subnet = 2,
            LocalNetwork = 3,
            Internet = 4
        }
    }
}
