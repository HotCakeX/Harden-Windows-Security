using System.IO;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    public static class PolicyEditor
    {
        public static void EditGuids(string policyIdInput, FileInfo policyFilePathInput)
        // Swaps the PolicyID and BasePolicyID GUIDs in a WDAC policy XML file for Base policies.
        // Shouldn't be used for supplemental policies.
        {
            string policyId = "{" + policyIdInput + "}";

            // Load the XML document
            XmlDocument xmlDoc = new();
            xmlDoc.Load(policyFilePathInput.FullName);

            // Define the new values for PolicyID and BasePolicyID
            string newPolicyId = policyId;
            string newBasePolicyId = policyId;

            // Select the nodes and update their values
            XmlNamespaceManager nsMgr = new(xmlDoc.NameTable);
            nsMgr.AddNamespace("ns", "urn:schemas-microsoft-com:sipolicy");

            XmlNode? policyIdNode = xmlDoc.SelectSingleNode("/ns:SiPolicy/ns:PolicyID", nsMgr);
            if (policyIdNode != null)
            {
                policyIdNode.InnerText = newPolicyId;
            }

            XmlNode? basePolicyIdNode = xmlDoc.SelectSingleNode("/ns:SiPolicy/ns:BasePolicyID", nsMgr);
            if (basePolicyIdNode != null)
            {
                basePolicyIdNode.InnerText = newBasePolicyId;
            }

            xmlDoc.Save(policyFilePathInput.FullName);
        }
    }
}
