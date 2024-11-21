using System;
using System.Xml;

namespace WDACConfig
{
    // This class represents a single Code Integrity XML policy
    // It Makes sure PolicyType attribute, BasePolicyID node and PolicyID nodes exist and remove PolicyTypeID node if it exists

    internal sealed class CodeIntegrityPolicy
    {

        // NameSpace URI
        internal readonly string NameSpaceURI = "urn:schemas-microsoft-com:sipolicy";

        internal XmlDocument XmlDocument { get; }
        internal XmlNamespaceManager NamespaceManager { get; }

        internal XmlNode SiPolicyNode { get; }

        // These items must only be read and not assigned
        // Their assignments in other methods must happen through their respective nodes exposed by the instantiated class
        internal string PolicyType { get; }

        internal string PolicyID { get; }
        internal string BasePolicyID { get; }

        internal XmlNode PolicyIDNode { get; }
        internal XmlNode BasePolicyIDNode { get; }

        internal XmlNode SignersNode { get; }

        internal XmlNode? UMCI_SigningScenarioNode { get; }
        internal XmlNode KMCI_SigningScenarioNode { get; }

        internal XmlNode? UMCI_ProductSignersNode { get; }
        internal XmlNode KMCI_ProductSignersNode { get; }

        internal XmlNode CiSignersNode { get; }

        internal XmlNode VersionExNode { get; }

        internal CodeIntegrityPolicy(string? xmlFilePath, XmlDocument? xmlDocument)
        {

            if (xmlFilePath is not null)
            {
                XmlDocument = new XmlDocument();
                XmlDocument.Load(xmlFilePath);
            }
            else if (xmlDocument is not null)
            {
                XmlDocument = xmlDocument;
            }
            else
            {
                throw new InvalidOperationException("Either xmlFilePath or xmlDocument must be provided");
            }

            // Create namespace manager and add the default namespace with a prefix
            NamespaceManager = new XmlNamespaceManager(XmlDocument.NameTable);
            NamespaceManager.AddNamespace("ns", NameSpaceURI);

            // Get SiPolicy node
            SiPolicyNode = XmlDocument.SelectSingleNode("ns:SiPolicy", NamespaceManager)
                ?? throw new InvalidOperationException("Invalid XML structure, SiPolicy node not found");

            // Find the Signers Node
            SignersNode = SiPolicyNode.SelectSingleNode("ns:Signers", NamespaceManager)
                ?? throw new InvalidOperationException("Signers node not found");

            // Find the SigningScenario Node for User Mode - It is nullable because Kernel-Mode Strict policy won't have this section
            UMCI_SigningScenarioNode = SiPolicyNode.SelectSingleNode("ns:SigningScenarios/ns:SigningScenario[@Value='12']", NamespaceManager);

            // Find the SigningScenario Node for Kernel Mode
            KMCI_SigningScenarioNode = SiPolicyNode.SelectSingleNode("ns:SigningScenarios/ns:SigningScenario[@Value='131']", NamespaceManager)
                ?? throw new InvalidOperationException("KMCI Signing Scenario node not found");

            // Find the ProductSigners Node for User Mode - It is nullable because Kernel-Mode Strict policy won't have this section
            UMCI_ProductSignersNode = SiPolicyNode.SelectSingleNode("ns:SigningScenarios/ns:SigningScenario[@Value='12']/ns:ProductSigners", NamespaceManager);

            // Find the ProductSigners Node for Kernel Mode
            KMCI_ProductSignersNode = SiPolicyNode.SelectSingleNode("ns:SigningScenarios/ns:SigningScenario[@Value='131']/ns:ProductSigners", NamespaceManager)
                ?? throw new InvalidOperationException("KMCI Product Signers node not found");


            #region CiSigners Node

            // Find the CiSigners Node
            XmlNode? ciSignersNode = SiPolicyNode.SelectSingleNode("ns:CiSigners", NamespaceManager);

            if (ciSignersNode is null)
            {
                XmlElement newCiSignersNode = XmlDocument.CreateElement("CiSigners", NameSpaceURI);
                _ = SiPolicyNode.AppendChild(newCiSignersNode);

                CiSignersNode = newCiSignersNode;
            }
            else
            {
                CiSignersNode = ciSignersNode;
            }

            #endregion


            #region PolicyType Attribute

            // If PolicyType attribute does not exist in the SiPolicyNode then add it and set it to Base policy
            string? policyType = SiPolicyNode.Attributes?["PolicyType"]?.Value;

            if (policyType is null)
            {
                // Create PolicyType attribute and set it to "Base Policy"
                XmlAttribute newPolicyTypeAttribute = XmlDocument.CreateAttribute("PolicyType");
                newPolicyTypeAttribute.Value = "Base Policy";
                _ = SiPolicyNode.Attributes!.Append(newPolicyTypeAttribute);

                PolicyType = newPolicyTypeAttribute.Value;
            }
            else
            {
                PolicyType = policyType;
            }

            #endregion


            // Generate a new GUID
            Guid newRandomGUID = System.Guid.NewGuid();

            // Convert it to string
            string newRandomGUIDString = $"{{{newRandomGUID.ToString().ToUpperInvariant()}}}";


            #region BasePolicyID

            XmlNode? basePolicyIDNode = SiPolicyNode.SelectSingleNode("ns:BasePolicyID", NamespaceManager);

            if (basePolicyIDNode is null)
            {
                // Create the node
                XmlElement newBasePolicyIDNode = XmlDocument.CreateElement("BasePolicyID", NameSpaceURI);

                // Set its value to match PolicyID because we are making it a Base policy when the node doesn't exist
                newBasePolicyIDNode.InnerText = newRandomGUIDString;

                // Append the new BasePolicyID node to the SiPolicy node
                _ = SiPolicyNode.AppendChild(newBasePolicyIDNode);

                BasePolicyIDNode = newBasePolicyIDNode;

                BasePolicyID = newRandomGUIDString;
            }
            else
            {
                BasePolicyIDNode = basePolicyIDNode;


                BasePolicyID = basePolicyIDNode.InnerText;
            }


            #endregion


            #region PolicyID

            XmlNode? policyIDNode = SiPolicyNode.SelectSingleNode("ns:PolicyID", NamespaceManager);

            if (policyIDNode is null)
            {
                // Create the node
                XmlElement newPolicyIDNode = XmlDocument.CreateElement("PolicyID", NameSpaceURI);

                // Set its value to match PolicyID because this is a Base policy
                newPolicyIDNode.InnerText = newRandomGUIDString;

                // Append the new BasePolicyID node to the SiPolicy node
                _ = SiPolicyNode.AppendChild(newPolicyIDNode);

                PolicyIDNode = newPolicyIDNode;

                PolicyID = newRandomGUIDString;
            }
            else
            {
                PolicyIDNode = policyIDNode;

                PolicyID = policyIDNode.InnerText;
            }

            #endregion


            #region PolicyTypeID

            /*
            // Dictionary to map Code Integrity Policy Type GUIDs to their purpose
            Dictionary<Guid, string> ciPolicyDictionary = new()
            {
                { Guid.Parse("4e61c68c-97f6-430b-9cd7-9b1004706770"), "Advanced Threat Protection Code Integrity Policy" },
                { Guid.Parse("976d12c8-cb9f-4730-be52-54600843238e"), "SKU Code Integrity Policy" },
                { Guid.Parse("5951a96a-e0b5-4d3d-8fb8-3e5b61030784"), "Windows Lockdown Code Integrity Policy" },
                { Guid.Parse("d2bda982-ccf6-4344-ac5b-0b44427b6816"), "Driver Code Integrity Policy" },
                { Guid.Parse("a244370e-44c9-4c06-b551-f6016e563076"), "Enterprise Code Integrity Policy" },
                { Guid.Parse("2a5a0136-f09f-498e-99cc-51099011157c"), "Windows Revoke Code Integrity Policy" },
            };
            */

            XmlNode? policyTypeIDNode = SiPolicyNode.SelectSingleNode("ns:PolicyTypeID", NamespaceManager);

            // Don't need this if it exists, usually exists in Microsoft Recommended block rules
            if (policyTypeIDNode is not null)
            {
                // Remove the policyTypeIDNode from its parent (siPolicyNode)
                _ = SiPolicyNode.RemoveChild(policyTypeIDNode);
            }

            #endregion


            #region VersionEx

            VersionExNode = SiPolicyNode.SelectSingleNode("ns:VersionEx", NamespaceManager) ?? throw new InvalidOperationException($"VersionEx was not found.");

            #endregion


            // TODO: The TESTCiPolicy must accept XML Document
            /*

            // Validate the XML file at the end
            if (!(bool)CiPolicyTest.TestCiPolicy(filePath, null)!)
            {
                throw new InvalidOperationException("The XML file created at the end is not compliant with the CI policy schema");
            }
            */

        }
    }
}
