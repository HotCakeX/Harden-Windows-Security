using System;
using System.Collections.Generic;
using System.Xml;

namespace WDACConfig
{
    public static class PolicyFileSigningStatusDetection
    {

        /// <summary>
        /// Check the signing status of an App Control policy file
        /// </summary>
        /// <param name="policyXMLPath"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static IntelGathering.SignatureStatus Check(string policyXMLPath)
        {

            // Make sure the policy file is valid first
            _ = CiPolicyTest.TestCiPolicy(policyXMLPath, "");

            HashSet<string> supplementalSignerIDs = [];
            HashSet<string> updatePolicySignerIDs = [];

            // Instantiate the policy
            CodeIntegrityPolicy codeIntegrityPolicy = new(policyXMLPath, null);

            // Check if SupplementalPolicySigners exists and has child nodes
            XmlNodeList? supplementalPolicySignersNodes = codeIntegrityPolicy.SiPolicyNode.SelectNodes("ns:SupplementalPolicySigners/ns:SupplementalPolicySigner", codeIntegrityPolicy.NamespaceManager);

            if (supplementalPolicySignersNodes is not null && supplementalPolicySignersNodes.Count > 0)
            {
                // Get unique SignerIds from SupplementalPolicySigners
                foreach (XmlElement node in supplementalPolicySignersNodes)
                {
                    _ = supplementalSignerIDs.Add(node.GetAttribute("SignerId"));
                }
            }

            // Check if UpdatePolicySigners exists and has child nodes
            XmlNodeList? updatePolicySignersNodes = codeIntegrityPolicy.SiPolicyNode.SelectNodes("ns:UpdatePolicySigners/ns:UpdatePolicySigner", codeIntegrityPolicy.NamespaceManager);

            if (updatePolicySignersNodes is not null && updatePolicySignersNodes.Count > 0)
            {
                // Get unique SignerIds from UpdatePolicySigners
                foreach (XmlElement node in updatePolicySignersNodes)
                {
                    _ = updatePolicySignerIDs.Add(node.GetAttribute("SignerId"));
                }
            }

            // Return a status
            return (supplementalSignerIDs.Count > 0 || updatePolicySignerIDs.Count > 0) ? IntelGathering.SignatureStatus.IsSigned : IntelGathering.SignatureStatus.IsUnsigned;
        }
    }
}
