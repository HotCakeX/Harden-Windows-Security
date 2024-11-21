using System;
using System.Collections.Generic;
using System.Xml;

namespace WDACConfig
{
    internal static class NewFilePublisherLevelRules
    {

        /// <summary>
        /// Creates new FilePublisher level rules in an XML file
        /// Each rules includes the FileAttribs, Signers, AllowedSigners, and CiSigners(depending on kernel/user mode)
        /// </summary>
        /// <param name="xmlFilePath"></param>
        /// <param name="filePublisherSigners"> The FilePublisherSigners to be used for creating the rules, they are the output of the BuildSignerAndHashObjects Method </param>
        /// <exception cref="InvalidOperationException"></exception>
        internal static void Create(string xmlFilePath, List<FilePublisherSignerCreator> filePublisherSigners)
        {

            if (filePublisherSigners is null || filePublisherSigners.Count == 0)
            {
                Logger.Write($"NewFilePublisherLevelRules: no FilePublisher signers detected to create rules for.");
                return;
            }

            // Instantiate the policy
            CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);

            // This method isn't suitable for strict Kernel-Mode policy
            if (codeIntegrityPolicy.UMCI_ProductSignersNode is null)
            {
                throw new InvalidOperationException("NewFilePublisherLevelRules.Create method isn't suitable for strict Kernel-Mode policy");
            }


            #region

            // Find AllowedSigners node in each ProductSigners node
            XmlNode? UMCI_ProductSigners_AllowedSigners_Node = codeIntegrityPolicy.UMCI_ProductSignersNode.SelectSingleNode("ns:AllowedSigners", codeIntegrityPolicy.NamespaceManager);
            XmlNode? KMCI_ProductSigners_AllowedSigners_Node = codeIntegrityPolicy.KMCI_ProductSignersNode.SelectSingleNode("ns:AllowedSigners", codeIntegrityPolicy.NamespaceManager);

            // Check if AllowedSigners node exists, if not, create it
            if (UMCI_ProductSigners_AllowedSigners_Node is null)
            {
                XmlElement UMCI_AllowedSignersNew = codeIntegrityPolicy.XmlDocument.CreateElement("AllowedSigners", codeIntegrityPolicy.NameSpaceURI);
                _ = codeIntegrityPolicy.UMCI_ProductSignersNode.AppendChild(UMCI_AllowedSignersNew);

                UMCI_ProductSigners_AllowedSigners_Node = codeIntegrityPolicy.UMCI_ProductSignersNode.SelectSingleNode("ns:AllowedSigners", codeIntegrityPolicy.NamespaceManager);
            }

            if (UMCI_ProductSigners_AllowedSigners_Node is null)
            {
                throw new InvalidOperationException("UMCI Product Signers AllowedSigners node not found despite creating it");
            }

            // Check if AllowedSigners node exists, if not, create it
            if (KMCI_ProductSigners_AllowedSigners_Node is null)
            {
                XmlElement KMCI_AllowedSignersNew = codeIntegrityPolicy.XmlDocument.CreateElement("AllowedSigners", codeIntegrityPolicy.NameSpaceURI);
                _ = codeIntegrityPolicy.KMCI_ProductSignersNode.AppendChild(KMCI_AllowedSignersNew);
                KMCI_ProductSigners_AllowedSigners_Node = codeIntegrityPolicy.KMCI_ProductSignersNode.SelectSingleNode("ns:AllowedSigners", codeIntegrityPolicy.NamespaceManager);
            }

            if (KMCI_ProductSigners_AllowedSigners_Node is null)
            {
                throw new InvalidOperationException("KMCI Product Signers AllowedSigners node not found despite creating it");
            }

            #endregion

            XmlNode fileRulesNode = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:FileRules", codeIntegrityPolicy.NamespaceManager)!;

            Logger.Write($"NewFilePublisherLevelRules: There are {filePublisherSigners.Count} File Publisher Signers to be added to the XML file");

            foreach (FilePublisherSignerCreator filePublisherData in filePublisherSigners)
            {

                string guid = Guid.NewGuid().ToString().Replace("-", "", StringComparison.OrdinalIgnoreCase).ToUpperInvariant();

                string FileAttribID = $"ID_FILEATTRIB_A_{guid}";

                #region Creating File <FileAttrib> node

                XmlElement newFileAttribNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileAttrib", codeIntegrityPolicy.NameSpaceURI);
                newFileAttribNode.SetAttribute("ID", FileAttribID);
                newFileAttribNode.SetAttribute("FriendlyName", filePublisherData.FileName);

                #region Creating File Attributes with automatic fallback

                if (!string.IsNullOrWhiteSpace(filePublisherData.OriginalFileName))
                {
                    newFileAttribNode.SetAttribute("FileName", filePublisherData.OriginalFileName);
                }

                else if (!string.IsNullOrWhiteSpace(filePublisherData.InternalName))
                {
                    newFileAttribNode.SetAttribute("InternalName", filePublisherData.InternalName);
                }

                else if (!string.IsNullOrWhiteSpace(filePublisherData.FileDescription))
                {
                    newFileAttribNode.SetAttribute("FileDescription", filePublisherData.FileDescription);
                }

                else if (!string.IsNullOrWhiteSpace(filePublisherData.ProductName))
                {
                    newFileAttribNode.SetAttribute("ProductName", filePublisherData.ProductName);
                }

                #endregion Creating File Attributes with automatic fallback

                newFileAttribNode.SetAttribute("MinimumFileVersion", filePublisherData.FileVersion!.ToString());

                // Add the new node to the FileRules node
                _ = fileRulesNode.AppendChild(newFileAttribNode);

                #endregion Creating File Attributes


                #region Creating Signers

                // Create signer for each certificate details in the FilePublisherSigners
                // Some files are signed by multiple signers

                foreach (CertificateDetailsCreator signerData in filePublisherData.CertificateDetails)
                {

                    string guid2 = Guid.NewGuid().ToString().Replace("-", "", StringComparison.OrdinalIgnoreCase).ToUpperInvariant();

                    string signerID = $"ID_SIGNER_A_{guid2}";

                    // Create the new Signer element
                    XmlElement newSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("Signer", codeIntegrityPolicy.NameSpaceURI);
                    newSignerNode.SetAttribute("ID", signerID);
                    newSignerNode.SetAttribute("Name", signerData.IntermediateCertName);

                    // Create the CertRoot element and add it to the Signer element
                    XmlElement newCertRootNode = codeIntegrityPolicy.XmlDocument.CreateElement("CertRoot", codeIntegrityPolicy.NameSpaceURI);
                    newCertRootNode.SetAttribute("Type", "TBS");
                    newCertRootNode.SetAttribute("Value", signerData.IntermediateCertTBS);
                    _ = newSignerNode.AppendChild(newCertRootNode);

                    // Create the CertPublisher element and add it to the Signer element
                    XmlElement newCertPublisherNode = codeIntegrityPolicy.XmlDocument.CreateElement("CertPublisher", codeIntegrityPolicy.NameSpaceURI);
                    newCertPublisherNode.SetAttribute("Value", signerData.LeafCertName);
                    _ = newSignerNode.AppendChild(newCertPublisherNode);

                    // Create the FileAttribRef element and add it to the Signer element
                    XmlElement newFileAttribRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileAttribRef", codeIntegrityPolicy.NameSpaceURI);
                    newFileAttribRefNode.SetAttribute("RuleID", FileAttribID);
                    _ = newSignerNode.AppendChild(newFileAttribRefNode);

                    // Add the new Signer element to the Signers node
                    _ = codeIntegrityPolicy.SignersNode.AppendChild(newSignerNode);


                    #region Adding signer to the Signer Scenario and CiSigners

                    // For User-Mode files
                    if (filePublisherData.SiSigningScenario == 1)
                    {

                        // Create Allowed Signers inside the <AllowedSigners> -> <ProductSigners> -> <SigningScenario Value="12">
                        XmlElement newUMCIAllowedSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("AllowedSigner", codeIntegrityPolicy.NameSpaceURI);
                        newUMCIAllowedSignerNode.SetAttribute("SignerId", signerID);
                        _ = UMCI_ProductSigners_AllowedSigners_Node.AppendChild(newUMCIAllowedSignerNode);

                        // Create a CI Signer for the User Mode Signer
                        XmlElement newCiSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("CiSigner", codeIntegrityPolicy.NameSpaceURI);
                        newCiSignerNode.SetAttribute("SignerId", signerID);
                        _ = codeIntegrityPolicy.CiSignersNode.AppendChild(newCiSignerNode);

                    }

                    // For Kernel-Mode files
                    else if (filePublisherData.SiSigningScenario == 0)
                    {

                        // Create Allowed Signers inside the <AllowedSigners> -> <ProductSigners> -> <SigningScenario Value="131">
                        XmlElement newKMCIAllowedSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("AllowedSigner", codeIntegrityPolicy.NameSpaceURI);
                        newKMCIAllowedSignerNode.SetAttribute("SignerId", signerID);
                        _ = KMCI_ProductSigners_AllowedSigners_Node.AppendChild(newKMCIAllowedSignerNode);

                        // Kernel-Mode signers don't need CI Signers
                    }

                    #endregion Adding signer to the Signer Scenario and CiSigners
                }

                #endregion Creating Signers
            }

            codeIntegrityPolicy.XmlDocument.Save(xmlFilePath);
        }
    }
}
