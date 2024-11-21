using System;
using System.Collections.Generic;
using System.Xml;

namespace WDACConfig
{
    public static class CiPolicyHandler
    {
        /// <summary>
        /// Removes the entire SupplementalPolicySigners block
        /// and any Signer in Signers node that have the same ID as the SignerIds of the SupplementalPolicySigner(s) in <SupplementalPolicySigners>...</SupplementalPolicySigners> node
        /// from a CI policy XML file
        ///
        /// It doesn't do anything if the input policy file has no SupplementalPolicySigners block.
        /// It will also always check if the Signers node is not empty, like
        /// <Signers>
        /// </Signers>
        /// if it is then it will close it: <Signers />
        /// The function can run infinite number of times on the same file.
        /// </summary>
        /// <param name="path">The path to the CI policy XML file</param>
        /// <exception cref="InvalidOperationException"></exception>
        public static void RemoveSupplementalSigners(string path)
        {

            // Validate input XML file compliance with CI policy schema
            if (CiPolicyTest.TestCiPolicy(path, "") is not true)
            {
                throw new InvalidOperationException("The input XML file is not compliant with the CI policy schema");
            }

            // Instantiate the policy
            CodeIntegrityPolicy codeIntegrityPolicy = new(path, null);

            // Check if SupplementalPolicySigners exists and has child nodes
            XmlNodeList? supplementalPolicySignersNodes = codeIntegrityPolicy.SiPolicyNode.SelectNodes("ns:SupplementalPolicySigners", codeIntegrityPolicy.NamespaceManager);

            if (supplementalPolicySignersNodes is not null && supplementalPolicySignersNodes.Count > 0)
            {
                Logger.Write("Removing the SupplementalPolicySigners blocks and corresponding Signers");

                // Store SignerIds to remove
                HashSet<string> signerIds = [];

                // Loop through each SupplementalPolicySigners node
                foreach (XmlNode supplementalPolicySignersNode in supplementalPolicySignersNodes)
                {
                    XmlNodeList? supplementalPolicySigners = supplementalPolicySignersNode.SelectNodes("ns:SupplementalPolicySigner", codeIntegrityPolicy.NamespaceManager);

                    // Get unique SignerIds
                    foreach (XmlElement node in supplementalPolicySigners!)
                    {
                        _ = signerIds.Add(node.GetAttribute("SignerId"));
                    }

                    // Remove the entire SupplementalPolicySigners node
                    _ = codeIntegrityPolicy.SiPolicyNode.RemoveChild(supplementalPolicySignersNode);
                }

                // Remove corresponding Signers
                foreach (string signerId in signerIds)
                {
                    XmlNodeList? signersToRemove = codeIntegrityPolicy.SiPolicyNode.SelectNodes($"ns:Signers/ns:Signer[@ID='{signerId}']", codeIntegrityPolicy.NamespaceManager);
                    if (signersToRemove is not null)
                    {
                        foreach (XmlNode signerNode in signersToRemove)
                        {
                            _ = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:Signers", codeIntegrityPolicy.NamespaceManager)?.RemoveChild(signerNode);
                        }
                    }
                }
            }


            // Check if the Signers node is empty, if so, close it properly
            XmlNode? signersNode = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:Signers", codeIntegrityPolicy.NamespaceManager);

            if (signersNode is not null && !signersNode.HasChildNodes)
            {
                // Create a new self-closing element with the same name and attributes as the old one
                XmlElement newSignersNode = codeIntegrityPolicy.XmlDocument.CreateElement("Signers", codeIntegrityPolicy.NameSpaceURI);

                if (signersNode.Attributes is not null)
                {

                    foreach (XmlAttribute attribute in signersNode.Attributes)
                    {
                        newSignersNode.SetAttribute(attribute.Name, attribute.Value);
                    }

                    _ = codeIntegrityPolicy.SiPolicyNode.ReplaceChild(newSignersNode, signersNode);
                }
            }

            // Save the updated XML content back to the file
            codeIntegrityPolicy.XmlDocument.Save(path);
        }
    }
}
