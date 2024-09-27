using System;
using System.Collections.Generic;
using System.Xml;

#nullable enable

namespace WDACConfig
{

    public class CheckPolicyDeploymentStatus
    {

        /// <summary>
        /// Check if a policy is deployed on the system
        /// </summary>
        /// <param name="policyXMLFile"></param>
        /// <returns></returns>
        public static bool IsDeployed(string policyXMLFile)
        {

            // Create a new HashSet with case-insensitive string comparison
            var currentPolicyIDs = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase);

            // Get all of the deployed policies on the system
            var policies = CiToolHelper.GetPolicies(false, true, true);

            // Loop through each policy and add its ID to the HashSet
            foreach (WDACConfig.CiPolicyInfo item in policies)
            {
                _ = currentPolicyIDs.Add(item.PolicyID!);
            }

            // Load XML document
            XmlDocument xmlDoc = new();
            xmlDoc.Load(policyXMLFile);

            // Create namespace manager and add the default namespace with a prefix
            XmlNamespaceManager namespaceManager = new(xmlDoc.NameTable);
            namespaceManager.AddNamespace("ns", "urn:schemas-microsoft-com:sipolicy");

            // Retrieve BasePolicyID and PolicyID
            //  XmlNode? basePolicyNode = xmlDoc.SelectSingleNode("//ns:BasePolicyID", namespaceManager);
            XmlNode? policyNode = xmlDoc.SelectSingleNode("//ns:PolicyID", namespaceManager);

            if (policyNode is not null)
            {
                // string basePolicyID = basePolicyNode.InnerText;

                string policyID = policyNode.InnerText;

                // Make sure the ID is in correct comparable format
                policyID = policyID.Trim('"', '"');
                policyID = policyID.Trim('{', '}');
                policyID = policyID.Trim('"', '"');
                policyID = $"{policyID}";
                policyID = policyID.ToLowerInvariant();

                // If the PolicyID of the currently selected XML is in the HashSet of the deployed policy IDs, then it is deployed
                return currentPolicyIDs.Contains(policyID);
            }
            else
            {
                return false;
            }
        }
    }
}
