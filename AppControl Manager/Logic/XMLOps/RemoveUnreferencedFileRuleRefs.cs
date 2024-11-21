using System.Collections.Generic;
using System.Xml;

namespace WDACConfig
{
    public static class RemoveUnreferencedFileRuleRefs
    {
        /// <summary>
        /// Removes <FileRuleRef> elements from the <FileRulesRef> node of each Signing Scenario that are not referenced by any <Allow> element in the <FileRules> node
        /// </summary>
        /// <param name="xmlFilePath"></param>
        public static void Remove(string xmlFilePath)
        {
            // Instantiate the policy
            CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);

            // Find all Allow elements and store their IDs
            XmlNodeList? allowNodes = codeIntegrityPolicy.SiPolicyNode.SelectNodes("ns:FileRules/ns:Allow", codeIntegrityPolicy.NamespaceManager);

            List<string> allowNodesIDs = [];

            if (allowNodes is not null)
            {
                foreach (XmlNode allowNode in allowNodes)
                {
                    allowNodesIDs.Add(allowNode.Attributes!["ID"]!.Value);
                }
            }

            // Select FileRuleRef nodes inside FileRulesRef node under each ProductSigners node
            XmlNodeList? fileRuleRefNodes = codeIntegrityPolicy.SiPolicyNode.SelectNodes("//ns:ProductSigners/ns:FileRulesRef/ns:FileRuleRef", codeIntegrityPolicy.NamespaceManager);

            if (fileRuleRefNodes is not null)
            {
                foreach (XmlNode fileRuleRefNode in fileRuleRefNodes)
                {

                    // Check if the RuleID attribute is not in the list of allowed IDs
                    if (!allowNodesIDs.Contains(fileRuleRefNode.Attributes!["RuleID"]!.Value))
                    {
                        _ = fileRuleRefNode.ParentNode?.RemoveChild(fileRuleRefNode);
                    }

                }
            }

            // Save the changes to the XML
            codeIntegrityPolicy.XmlDocument.Save(xmlFilePath);
        }
    }
}
