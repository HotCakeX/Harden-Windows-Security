using System.Collections.Generic;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    internal static class RemoveAllowElementsSemantic
    {

        /// <summary>
        /// Removes duplicate <Allow> elements from the <FileRules> node and their corresponding <FileRuleRef> elements from the <FileRulesRef> node of the <ProductSigners> node under each <SigningScenario> node
        /// The criteria for removing duplicates is the Hash attribute of the <Allow> elements.
        /// If there are multiple <Allow> elements with the same Hash, the method keeps the first element and removes the rest.
        /// The method only considers <Allow> elements that are part of the same <SigningScenario> node and have the same Hash attribute as duplicates.
        /// After the method completes its operation, the XML file will not have any duplicate <Allow> elements, duplicate <FileRuleRef> elements or any orphan <FileRuleRef> elements.
        /// This is according to the CI Schema.
        ///
        /// Each <Allow> node is associated only with one Signing scenario at a time.
        ///
        /// </summary>
        /// <param name="xmlFilePath"></param>
        internal static void Remove(string xmlFilePath)
        {

            // Instantiate the policy
            CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);

            // Get the <FileRules> node
            XmlNode fileRulesNode = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:FileRules", codeIntegrityPolicy.NamespaceManager)!;

            // Get all of the <Allow> nodes inside the <FileRules> node
            XmlNodeList? allowNodes = codeIntegrityPolicy.SiPolicyNode.SelectNodes("ns:FileRules//ns:Allow", codeIntegrityPolicy.NamespaceManager);

            if (allowNodes is null)
            {
                Logger.Write("No <Allow> nodes have been found in the <FileRules> node");
                return;
            }

            // Find the FileRulesRef Nodes inside the ProductSigners Nodes of each Signing Scenario
            XmlNode? UserModeFileRefs = codeIntegrityPolicy.UMCI_ProductSignersNode.SelectSingleNode("ns:FileRulesRef", codeIntegrityPolicy.NamespaceManager);
            XmlNode? KernelModeFileRefs = codeIntegrityPolicy.KMCI_ProductSignersNode.SelectSingleNode("ns:FileRulesRef", codeIntegrityPolicy.NamespaceManager);

            // To store all of the Allow nodes' unique keys
            HashSet<string> allAllowNodes = [];

            // Iterate over every <Allow> node in the <FileRules> node
            foreach (XmlNode allowNode in allowNodes)
            {
                // The ID of the current <Allow> node
                string allowNodeID = allowNode.Attributes!["ID"]!.Value;

                // The Hash of the current <Allow> node
                string allowedNodeHash = allowNode.Attributes!["Hash"]!.Value;

                // Any possible FileRuleRef in User Mode or Kernel mode signing scenarios, associated with the current <Allow> node
                XmlNode? UserModeFileRuleRef = null;
                XmlNode? KernelModeFileRuleRef = null;

                if (UserModeFileRefs is not null)
                {
                    UserModeFileRuleRef = UserModeFileRefs.SelectSingleNode($"ns:FileRuleRef[@RuleID='{allowNodeID}']", codeIntegrityPolicy.NamespaceManager);
                }

                if (KernelModeFileRefs is not null)
                {
                    KernelModeFileRuleRef = KernelModeFileRefs.SelectSingleNode($"ns:FileRuleRef[@RuleID='{allowNodeID}']", codeIntegrityPolicy.NamespaceManager);
                }

                // Determine the SigningScenario of the current <Allow> node
                string signingScenario = UserModeFileRuleRef is not null ? "UserMode" : "KernelMode";

                // Unique key to distinguish the current <Allow> node
                string uniqueAllowNodeKey = $"{allowedNodeHash} | {signingScenario}";

                // Check to see if it's an orphan <Allow> node, meaning it has no corresponding FileRuleRef
                if (UserModeFileRuleRef is null && KernelModeFileRuleRef is null)
                {
                    // Remove the current <Allow> node from its parent node <FileRules>
                    _ = fileRulesNode.RemoveChild(allowNode);
                    continue;
                }

                // If the current <Allow> node can't be added to the HashSet using its unique key, then remove it
                // As it's an indication that it's a duplicate
                if (!allAllowNodes.Add(uniqueAllowNodeKey))
                {
                    // Remove the <FileRulesRef> node of the current <Allow> node from whichever SigningScenario that has it
                    if (UserModeFileRuleRef is not null)
                    {
                        _ = UserModeFileRuleRef.ParentNode!.RemoveChild(UserModeFileRuleRef);
                    }

                    if (KernelModeFileRuleRef is not null)
                    {
                        _ = KernelModeFileRuleRef.ParentNode!.RemoveChild(KernelModeFileRuleRef);
                    }

                    // Remove the current <Allow> node from its parent node <FileRules>
                    _ = fileRulesNode.RemoveChild(allowNode);
                }
            }
            codeIntegrityPolicy.XmlDocument.Save(xmlFilePath);
        }
    }
}
