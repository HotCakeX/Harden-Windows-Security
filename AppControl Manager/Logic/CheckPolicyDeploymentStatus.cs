using System;
using System.Collections.Generic;

namespace AppControlManager
{

    internal static class CheckPolicyDeploymentStatus
    {

        /// <summary>
        /// Check if a policy is deployed on the system
        /// </summary>
        /// <param name="policyXMLFile"></param>
        /// <returns></returns>
        internal static bool IsDeployed(string policyXMLFile)
        {

            // Create a new HashSet with case-insensitive string comparison
            HashSet<string> currentPolicyIDs = new(StringComparer.InvariantCultureIgnoreCase);

            // Get all of the deployed policies on the system
            List<CiPolicyInfo> policies = CiToolHelper.GetPolicies(false, true, true);

            // Loop through each policy and add its ID to the HashSet
            foreach (CiPolicyInfo item in policies)
            {
                _ = currentPolicyIDs.Add(item.PolicyID!);
            }

            // Instantiate the policy
            CodeIntegrityPolicy codeIntegrityPolicy = new(policyXMLFile, null);

            string policyID = codeIntegrityPolicy.PolicyIDNode.InnerText;

            // Make sure the ID is in correct comparable format
            policyID = policyID.Trim('"', '"');
            policyID = policyID.Trim('{', '}');
            policyID = policyID.Trim('"', '"');
            policyID = $"{policyID}";
            policyID = policyID.ToLowerInvariant();

            // If the PolicyID of the currently selected XML is in the HashSet of the deployed policy IDs, then it is deployed
            return currentPolicyIDs.Contains(policyID);

        }
    }
}
