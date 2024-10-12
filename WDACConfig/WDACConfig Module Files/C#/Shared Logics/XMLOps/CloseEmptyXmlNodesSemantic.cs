using System;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    public class CloseEmptyXmlNodesSemantic
    {

        /// <summary>
        /// Closes all empty XML nodes and removes empty nodes that are neither base nodes nor 'ProductSigners' nodes
        /// According to the CI Schema
        /// </summary>
        /// <param name="xmlFilePath">The path to the XML file to be processed</param>

        /*

          For example, it converts this

          <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="Auto generated policy on 03-13-2024">
            <ProductSigners>
              <AllowedSigners>
              </AllowedSigners>
            </ProductSigners>
          </SigningScenario>

          Or this

          <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="Auto generated policy on 03-13-2024">
            <ProductSigners>
              <AllowedSigners />
            </ProductSigners>
          </SigningScenario>

          to this

          <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="Auto generated policy on 03-13-2024">
            <ProductSigners />
          </SigningScenario>

          */

        public static void Close(string xmlFilePath)
        {
            // Define the base node names that should not be removed even if empty
            string[] baseNodeNames = { "SiPolicy", "Rules", "EKUs", "FileRules", "Signers", "SigningScenarios",
                                   "UpdatePolicySigners", "CiSigners", "HvciOptions", "BasePolicyID", "PolicyID" };

            // Load the XML file
            XmlDocument xmlDoc = new();
            xmlDoc.Load(xmlFilePath);

            // Start the recursive method from the root element
            CloseEmptyNodesRecursively(xmlDoc.DocumentElement!, baseNodeNames);

            // Save the changes back to the XML file
            xmlDoc.Save(xmlFilePath);
        }

        // Helper method to recursively close empty XML nodes
        private static void CloseEmptyNodesRecursively(XmlElement xmlNode, string[] baseNodeNames)
        {
            // Iterate through child nodes
            foreach (XmlNode childNode in xmlNode.ChildNodes)
            {
                if (childNode is XmlElement childElement)
                {
                    // Recursively close empty child nodes
                    CloseEmptyNodesRecursively(childElement, baseNodeNames);

                    // Check if the node is empty
                    if (!childElement.HasChildNodes && !childElement.HasAttributes)
                    {
                        // Check if it's a base node
                        if (Array.Exists(baseNodeNames, baseNodeName => baseNodeName.Equals(childElement.LocalName, StringComparison.OrdinalIgnoreCase)))
                        {
                            // Self-close it
                            childElement.IsEmpty = true;
                        }
                        // Special case for ProductSigners because it's a required node inside each SigningScenario but can't be empty
                        else if (childElement.LocalName.Equals("ProductSigners", StringComparison.OrdinalIgnoreCase))
                        {
                            // Self-close it
                            childElement.IsEmpty = true;
                        }
                        else
                        {
                            // If it's not a base node, remove it
                            _ = xmlNode.RemoveChild(childElement);
                        }
                    }
                }
            }
        }
    }
}
