using System;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    public class UpdateHvciOptions
    {
        /// <summary>
        /// Sets the HVCI option to Strict or (2) in a policy XML file
        /// It does this just like the Set-HVCIOptions cmdlet.
        /// First it checks if <HvciOptions> node exists and if its value is anything other than 2, it sets it to 2.
        /// If <HvciOptions> node does not exists, it tries to find the <CiSigners> node and insert the <HvciOptions> node after it.
        /// If <CiSigners> node does not exists, it inserts the <HvciOptions> node before the end of <SiPolicy> node.
        /// </summary>
        /// <param name="filePath"></param>
        /// <exception cref="InvalidOperationException"></exception>
        public static void Update(string filePath)
        {
            // Load the XML document
            XmlDocument xmlDoc = new();
            xmlDoc.Load(filePath);

            // Create a namespace manager for the XML document
            XmlNamespaceManager namespaceManager = new(xmlDoc.NameTable);
            namespaceManager.AddNamespace("ns", "urn:schemas-microsoft-com:sipolicy");

            // Select the HvciOptions node
            XmlNode? hvciOptionsNode = xmlDoc.SelectSingleNode("//ns:HvciOptions", namespaceManager);

            // Check if the CiSigners node exists
            XmlNode? ciSignersNode = xmlDoc.SelectSingleNode("//ns:CiSigners", namespaceManager);

            // If HvciOptions node exists
            if (hvciOptionsNode != null)
            {
                // Ensure the value is "2"
                if (hvciOptionsNode.InnerText != "2")
                {
                    hvciOptionsNode.InnerText = "2";
                }
            }
            else
            {
                // Create the HvciOptions node if it doesn't exist
                hvciOptionsNode = xmlDoc.CreateElement("HvciOptions", "urn:schemas-microsoft-com:sipolicy");
                hvciOptionsNode.InnerText = "2";

                // Insert it after CiSigners node if it exists
                if (ciSignersNode != null)
                {
                    // Insert after CiSigners
                    _ = ciSignersNode.ParentNode?.InsertAfter(hvciOptionsNode, ciSignersNode);
                }
                else
                {
                    // Insert before the end of SiPolicy node if CiSigners does not exist
                    XmlNode siPolicyNode = xmlDoc.SelectSingleNode("//ns:SiPolicy", namespaceManager) ?? throw new InvalidOperationException("SiPolicy node not found");
                    _ = siPolicyNode.AppendChild(hvciOptionsNode);
                }
            }

            // Save the modified XML document
            xmlDoc.Save(filePath);

            // Validate the XML file at the end
            if (!(bool)CiPolicyTest.TestCiPolicy(filePath, null)!)
            {
                throw new InvalidOperationException("UpdateHvciOptions: The XML file created at the end is not compliant with the CI policy schema");
            }

            Logger.Write($"Successfully set the HVCI in the policy file '{filePath}' to Strict.");
        }
    }
}
