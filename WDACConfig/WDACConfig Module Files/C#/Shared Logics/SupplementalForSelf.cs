using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

#nullable enable

namespace WDACConfig
{

    internal static class SupplementalForSelf
    {
        /// <summary>
        /// Deploys the Supplemental Policy that allows the Application to be allowed to run after deployment
        /// Each Base policy should have this supplemental policy
        /// </summary>
        /// <param name="StagingArea"></param>
        public static void Deploy(string StagingArea, string basePolicyID)
        {

            string policyName = "AppControlManagerSupplementalPolicy";

            // Get the base directory where the app is running
            string xmlFilePath = Path.Combine(AppContext.BaseDirectory, @"Resources\AppControlManagerSupplementalPolicy.xml");

            // Instantiate the policy
            CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);

            #region Replace the BasePolicyID of the Supplemental Policy and reset its PolicyID which is necessary in order to have more than 1 of these supplemental policies deployed on the system

            codeIntegrityPolicy.BasePolicyIDNode.InnerText = basePolicyID;

            // Generate a new GUID
            Guid newRandomGUID = Guid.NewGuid();

            // Convert it to string
            string newRandomGUIDString = $"{{{newRandomGUID.ToString().ToUpperInvariant()}}}";

            codeIntegrityPolicy.PolicyIDNode.InnerText = newRandomGUIDString;

            #endregion

            string savePath = Path.Combine(StagingArea, $"{policyName}.xml");

            string cipPath = Path.Combine(StagingArea, $"{policyName}.cip");

            // Save the XML to the path as XML file
            codeIntegrityPolicy.XmlDocument.Save(savePath);

            Logger.Write($"Checking the deployment status of '{policyName}' Supplemental policy");

            // Get all the deployed supplemental policies to see if our policy is among them

            string trimmedBasePolicyID = basePolicyID.Trim('{', '}');

            List<CiPolicyInfo> CurrentlyDeployedSupplementalPolicyNoFilter = CiToolHelper.GetPolicies(false, false, true);

            List<CiPolicyInfo> CurrentlyDeployedSupplementalPolicy1stFilter = CurrentlyDeployedSupplementalPolicyNoFilter.Where(policy => string.Equals(policy.FriendlyName, policyName, StringComparison.OrdinalIgnoreCase)).ToList();

            List<CiPolicyInfo> CurrentlyDeployedSupplementalPolicy = CurrentlyDeployedSupplementalPolicy1stFilter.Where(policy => string.Equals(policy.BasePolicyID, trimmedBasePolicyID, StringComparison.OrdinalIgnoreCase)).ToList();

            if (CurrentlyDeployedSupplementalPolicy.Count > 0)
            {
                Logger.Write($"Supplemental policy named {policyName} is already deployed for the base policy with the BasePolicyID {basePolicyID}, skipping its deployment.");
            }
            else
            {
                Logger.Write($"Supplemental policy named {policyName} is not deployed for the base policy with the BasePolicyID {basePolicyID}, deploying it now.");

                PolicyToCIPConverter.Convert(savePath, cipPath);

                CiToolHelper.UpdatePolicy(cipPath);
            }

        }

    }
}
