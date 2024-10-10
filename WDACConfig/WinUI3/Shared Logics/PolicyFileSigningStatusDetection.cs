using System;
using System.Collections.Generic;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    public class PolicyFileSigningStatusDetection
    {

        public enum SigningStatus
        {
            Signed,
            Unsigned
        }

        /// <summary>
        /// Check the signing status of a WDAC policy file
        /// </summary>
        /// <param name="policyXMLPath"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static SigningStatus Check(string policyXMLPath)
        {

            // Make sure the policy file is valid first
            _ = CiPolicyTest.TestCiPolicy(policyXMLPath, "");

            var supplementalSignerIDs = new HashSet<string>();
            var updatePolicySignerIDs = new HashSet<string>();

            // Load XML document
            XmlDocument xmlDoc = new();
            xmlDoc.Load(policyXMLPath);

            // Create namespace manager and add the default namespace with a prefix
            XmlNamespaceManager namespaceManager = new(xmlDoc.NameTable);
            namespaceManager.AddNamespace("ns", "urn:schemas-microsoft-com:sipolicy");

            // Get SiPolicy node
            XmlNode? siPolicyNode = xmlDoc.SelectSingleNode("//ns:SiPolicy", namespaceManager) ?? throw new InvalidOperationException("Invalid XML structure, SiPolicy node not found");

            // Check if SupplementalPolicySigners exists and has child nodes
            XmlNodeList? supplementalPolicySignersNodes = siPolicyNode.SelectNodes("ns:SupplementalPolicySigners/ns:SupplementalPolicySigner", namespaceManager);

            if (supplementalPolicySignersNodes is not null && supplementalPolicySignersNodes.Count > 0)
            {
                // Get unique SignerIds from SupplementalPolicySigners
                foreach (XmlElement node in supplementalPolicySignersNodes)
                {
                    _ = supplementalSignerIDs.Add(node.GetAttribute("SignerId"));
                }
            }

            // Check if UpdatePolicySigners exists and has child nodes
            XmlNodeList? updatePolicySignersNodes = siPolicyNode.SelectNodes("ns:UpdatePolicySigners/ns:UpdatePolicySigner", namespaceManager);

            if (updatePolicySignersNodes is not null && updatePolicySignersNodes.Count > 0)
            {
                // Get unique SignerIds from UpdatePolicySigners
                foreach (XmlElement node in updatePolicySignersNodes)
                {
                    _ = updatePolicySignerIDs.Add(node.GetAttribute("SignerId"));
                }
            }

            // Return a status
            return (supplementalSignerIDs.Count > 0 || updatePolicySignerIDs.Count > 0) ? SigningStatus.Signed : SigningStatus.Unsigned;
        }
    }
}
