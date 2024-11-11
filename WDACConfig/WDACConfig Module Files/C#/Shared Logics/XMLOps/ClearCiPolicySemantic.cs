using System.Collections.Generic;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    public static class ClearCiPolicySemantic
    {
        /// <summary>
        /// Clears the CI Policy XML file from all nodes except the base nodes
        /// According to the CI Schema
        /// </summary>
        /// <param name="xmlFilePath"></param>
        public static void Clear(string xmlFilePath)
        {
            // Instantiate the policy
            CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);

            #region Defining the Nodes to keep and clear, according to the CI Schema

            List<XmlNode> baseNodes = [];
            baseNodes.Add(codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:EKUs", codeIntegrityPolicy.NamespaceManager)!);
            baseNodes.Add(codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:FileRules", codeIntegrityPolicy.NamespaceManager)!);
            baseNodes.Add(codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:Signers", codeIntegrityPolicy.NamespaceManager)!);

            if (codeIntegrityPolicy.UMCI_ProductSignersNode is not null)
            {
                baseNodes.Add(codeIntegrityPolicy.UMCI_ProductSignersNode);
            }

            baseNodes.Add(codeIntegrityPolicy.KMCI_ProductSignersNode);

            XmlNode? fileRulesRefUMC = codeIntegrityPolicy.UMCI_ProductSignersNode?.SelectSingleNode("ns:FileRulesRef", codeIntegrityPolicy.NamespaceManager);
            if (fileRulesRefUMC is not null)
            {
                baseNodes.Add(fileRulesRefUMC);
            }

            XmlNode? fileRulesRefKMCS = codeIntegrityPolicy.KMCI_ProductSignersNode.SelectSingleNode("ns:FileRulesRef", codeIntegrityPolicy.NamespaceManager);
            if (fileRulesRefKMCS is not null)
            {
                baseNodes.Add(fileRulesRefKMCS);
            }

            XmlNode? updatePolicySigners = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:UpdatePolicySigners", codeIntegrityPolicy.NamespaceManager);
            if (updatePolicySigners is not null)
            {
                baseNodes.Add(updatePolicySigners);
            }
            baseNodes.Add(codeIntegrityPolicy.CiSignersNode);

            #endregion

            // Remove <Macros> node completely since it can't be left empty and it's not a base node
            XmlNode? macros = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:Macros", codeIntegrityPolicy.NamespaceManager);
            if (macros is not null)
            {
                _ = codeIntegrityPolicy.SiPolicyNode.RemoveChild(macros);
            }

            // Loop over each base node
            foreach (XmlNode node in baseNodes)
            {
                // Remove all child nodes
                while (node.HasChildNodes)
                {
                    _ = node.RemoveChild(node.FirstChild!);
                }

                // Set the node/element to be serialized in the short tag format
                // https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmlelement.isempty
                if (node is XmlElement element)
                {
                    element.IsEmpty = true;
                }
            }

            codeIntegrityPolicy.XmlDocument.Save(xmlFilePath);
        }
    }
}
