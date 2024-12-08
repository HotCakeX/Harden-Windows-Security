using System;
using System.Collections.Generic;
using System.Xml;

namespace AppControlManager
{
    internal static class NewCertificateSignerRules
    {
        /// <summary>
        /// Creates new Signer rules for Certificates, in the XML file
        /// The level is Pca/Root/Leaf certificate, meaning there is no certificate publisher mentioned
        /// Only Certificate TBS and its name is used.
        /// </summary>
        /// <param name="xmlFilePath"></param>
        /// <param name="signerData"></param>
        internal static void Create(string xmlFilePath, List<CertificateSignerCreator> signerData)
        {
            // Instantiate the policy
            CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);

            // This method isn't suitable for strict Kernel-Mode policy
            if (codeIntegrityPolicy.UMCI_ProductSignersNode is null)
            {
                throw new InvalidOperationException("NewCertificateSignerRules.Create method isn't suitable for strict Kernel-Mode policy");
            }

            #region

            // Find AllowedSigners node in each ProductSigners node
            XmlNode? UMCI_ProductSigners_AllowedSigners_Node = codeIntegrityPolicy.UMCI_ProductSignersNode.SelectSingleNode("ns:AllowedSigners", codeIntegrityPolicy.NamespaceManager);
            XmlNode? KMCI_ProductSigners_AllowedSigners_Node = codeIntegrityPolicy.KMCI_ProductSignersNode?.SelectSingleNode("ns:AllowedSigners", codeIntegrityPolicy.NamespaceManager);

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
                _ = codeIntegrityPolicy.KMCI_ProductSignersNode?.AppendChild(KMCI_AllowedSignersNew);
                KMCI_ProductSigners_AllowedSigners_Node = codeIntegrityPolicy.KMCI_ProductSignersNode?.SelectSingleNode("ns:AllowedSigners", codeIntegrityPolicy.NamespaceManager);
            }

            if (KMCI_ProductSigners_AllowedSigners_Node is null)
            {
                throw new InvalidOperationException("KMCI Product Signers AllowedSigners node not found despite creating it");
            }

            #endregion

            foreach (CertificateSignerCreator signer in signerData)
            {
                // Create a unique ID for the Signer element
                string guid = SiPolicyIntel.GUIDGenerator.GenerateUniqueGUIDToUpper();

                string SignerID = $"ID_SIGNER_R_{guid}";

                // Create the new Signer element
                XmlElement newSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("Signer", codeIntegrityPolicy.NameSpaceURI);
                newSignerNode.SetAttribute("ID", SignerID);
                newSignerNode.SetAttribute("Name", signer.SignerName);

                // Create the CertRoot element and add it to the Signer element
                XmlElement certRootNode = codeIntegrityPolicy.XmlDocument.CreateElement("CertRoot", codeIntegrityPolicy.NameSpaceURI);
                certRootNode.SetAttribute("Type", "TBS");
                certRootNode.SetAttribute("Value", signer.TBS);

                _ = newSignerNode.AppendChild(certRootNode);

                // Add the new Signer element to the Signers node
                _ = codeIntegrityPolicy.SignersNode.AppendChild(newSignerNode);


                // For User-Mode files
                if (signer.SiSigningScenario == 1)
                {
                    // Create Allowed Signers inside the <AllowedSigners> -> <ProductSigners> -> <SigningScenario Value="12">
                    XmlElement newAllowedSigner = codeIntegrityPolicy.XmlDocument.CreateElement("AllowedSigner", codeIntegrityPolicy.NameSpaceURI);
                    newAllowedSigner.SetAttribute("SignerId", SignerID);
                    _ = UMCI_ProductSigners_AllowedSigners_Node.AppendChild(newAllowedSigner);


                    // Create a CI Signer for the User Mode Signer
                    XmlElement newCiSigner = codeIntegrityPolicy.XmlDocument.CreateElement("CiSigner", codeIntegrityPolicy.NameSpaceURI);
                    newCiSigner.SetAttribute("SignerId", SignerID);
                    _ = codeIntegrityPolicy.CiSignersNode.AppendChild(newCiSigner);
                }

                // For Kernel-Mode files
                else if (signer.SiSigningScenario == 0)
                {
                    // Create Allowed Signers inside the <AllowedSigners> -> <ProductSigners> -> <SigningScenario Value="131">
                    XmlElement newAllowedSigner = codeIntegrityPolicy.XmlDocument.CreateElement("AllowedSigner", codeIntegrityPolicy.NameSpaceURI);
                    newAllowedSigner.SetAttribute("SignerId", SignerID);
                    _ = KMCI_ProductSigners_AllowedSigners_Node.AppendChild(newAllowedSigner);

                    // Kernel-Mode signers don't need CI Signers
                }

                codeIntegrityPolicy.XmlDocument.Save(xmlFilePath);
            }
        }
    }
}
