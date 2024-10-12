using System;
using System.Collections.Generic;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    public class CiPolicyHandler
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
            if (WDACConfig.CiPolicyTest.TestCiPolicy(path, "") is not true)
            {
                throw new InvalidOperationException("The input XML file is not compliant with the CI policy schema");
            }

            // Load XML document
            XmlDocument xmlDoc = new();
            xmlDoc.Load(path);

            // Create namespace manager and add the default namespace with a prefix
            XmlNamespaceManager namespaceManager = new(xmlDoc.NameTable);
            namespaceManager.AddNamespace("ns", "urn:schemas-microsoft-com:sipolicy");

            // Get SiPolicy node
            XmlNode? siPolicyNode = xmlDoc.SelectSingleNode("//ns:SiPolicy", namespaceManager) ?? throw new InvalidOperationException("Invalid XML structure, SiPolicy node not found");

            // Check if SupplementalPolicySigners exists and has child nodes
            XmlNodeList? supplementalPolicySignersNodes = siPolicyNode.SelectNodes("ns:SupplementalPolicySigners", namespaceManager);

            if (supplementalPolicySignersNodes is not null && supplementalPolicySignersNodes.Count > 0)
            {
                Logger.Write("Removing the SupplementalPolicySigners blocks and corresponding Signers");

                // Store SignerIds to remove
                var signerIds = new HashSet<string>();

                // Loop through each SupplementalPolicySigners node
                foreach (XmlNode supplementalPolicySignersNode in supplementalPolicySignersNodes)
                {
                    var supplementalPolicySigners = supplementalPolicySignersNode.SelectNodes("ns:SupplementalPolicySigner", namespaceManager);

                    // Get unique SignerIds
                    foreach (XmlElement node in supplementalPolicySigners!)
                    {
                        _ = signerIds.Add(node.GetAttribute("SignerId"));
                    }

                    // Remove the entire SupplementalPolicySigners node
                    _ = siPolicyNode.RemoveChild(supplementalPolicySignersNode);
                }

                // Remove corresponding Signers
                foreach (var signerId in signerIds)
                {
                    XmlNodeList? signersToRemove = siPolicyNode.SelectNodes($"ns:Signers/ns:Signer[@ID='{signerId}']", namespaceManager);
                    if (signersToRemove != null)
                    {
                        foreach (XmlNode signerNode in signersToRemove)
                        {
                            _ = siPolicyNode.SelectSingleNode("ns:Signers", namespaceManager)?.RemoveChild(signerNode);
                        }
                    }
                }
            }


            // Check if the Signers node is empty, if so, close it properly
            XmlNode? signersNode = siPolicyNode.SelectSingleNode("ns:Signers", namespaceManager);

            if (signersNode is not null && !signersNode.HasChildNodes)
            {
                // Create a new self-closing element with the same name and attributes as the old one
                XmlElement newSignersNode = xmlDoc.CreateElement("Signers", "urn:schemas-microsoft-com:sipolicy");

                if (signersNode.Attributes is not null)
                {

                    foreach (XmlAttribute attribute in signersNode.Attributes)
                    {
                        newSignersNode.SetAttribute(attribute.Name, attribute.Value);
                    }

                    _ = siPolicyNode.ReplaceChild(newSignersNode, signersNode);
                }
            }

            // Save the updated XML content back to the file
            xmlDoc.Save(path);
        }
    }
}
