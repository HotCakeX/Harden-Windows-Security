using System;
using System.Collections.Generic;
using System.Xml;

namespace AppControlManager
{

    // Comparer for XmlNode objects based on their "RuleID" attribute
    internal sealed class XmlNodeComparer : IEqualityComparer<XmlNode>
    {
        // Checks if two XmlNode objects are equal based on their "RuleID" attribute
        public bool Equals(XmlNode? x, XmlNode? y)
        {
            if (x == null || y == null)
                return false;

            return x.Attributes?["RuleID"]?.Value == y.Attributes?["RuleID"]?.Value;
        }

        // Returns the hash code for an XmlNode object based on its "RuleID" attribute
        public int GetHashCode(XmlNode obj)
        {
            return obj.Attributes?["RuleID"]?.Value.GetHashCode(StringComparison.OrdinalIgnoreCase) ?? 0;
        }
    }

    // A HashSet to store unique XmlNode objects
    internal sealed class UniqueXmlNodeSet
    {
        private readonly HashSet<XmlNode> nodes;

        // Constructor initializes the HashSet with XmlNodeComparer as the comparer logic
        public UniqueXmlNodeSet()
        {
            nodes = new HashSet<XmlNode>(new XmlNodeComparer());
        }

        // Adds an XmlNode to the set if it is not already present
        public bool Add(XmlNode node)
        {
            return nodes.Add(node);
        }

        // Returns the collection of unique XmlNode objects
        public IEnumerable<XmlNode> GetNodes()
        {
            return nodes;
        }
    }

    // A class representing a Kernel mode signer
    internal sealed class KernelModeSigner(XmlNode signer, XmlNode allowedSigners)
    {
        public XmlNode Signer { get; set; } = signer;
        public XmlNode AllowedSigner { get; set; } = allowedSigners;
    }

    // A class representing a User mode signer
    internal sealed class UserModeSigner(XmlNode signer, XmlNode allowedSigner, XmlNode ciSigner)
    {
        public XmlNode Signer { get; set; } = signer;
        public XmlNode AllowedSigner { get; set; } = allowedSigner;
        public XmlNode CiSigner { get; set; } = ciSigner;
    }



    internal static class MergeSignersSemantic
    {
        /// <summary>
        /// Merges the FilePublisher and Publisher Signers in an XML file based on their TBS, Name, and CertPublisher values
        /// For each FilePublisher signer, if two signers are found with the same TBS, Name, and CertPublisher, only one of them will be kept, and their FileAttribRefs are merged
        /// For each Publisher signer, if two signers are found with the same TBS, Name, and CertPublisher, only one of them will be kept
        ///
        /// If two signers have the same TBS, Name, and CertPublisher but only one of them has FileAttribRefs, then they are not the same.This method makes the distinction between FilePublisher and Publisher signers.
        /// Signers are also properly detected to belong to user-mode or kernel-mode signing scenario.
        ///
        /// So there are 4 different Signer types to consider.
        ///
        /// At the end, the XML file will have unique FilePublisher and Publisher signers for Signing Scenario 131 and 12, unique nodes in the <AllowedSigners> and <CiSigners> nodes.
        /// Also, each Signer will have unique and valid FileAttribRef nodes with IDs that point to an existing <FileAttrib> node in the <FileRules> node.
        ///
        /// </summary>
        /// <param name="xmlFilePath"></param>
        internal static void Merge(string xmlFilePath)
        {

            // Instantiate the policy
            CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);

            // Get the User Mode Signing Scenario node
            XmlNode? allowedSigners12 = codeIntegrityPolicy.UMCI_ProductSignersNode?.SelectSingleNode("ns:AllowedSigners", codeIntegrityPolicy.NamespaceManager);

            // Get the Kernel Mode Signing Scenario node
            XmlNode? allowedSigners131 = codeIntegrityPolicy.KMCI_ProductSignersNode.SelectSingleNode("ns:AllowedSigners", codeIntegrityPolicy.NamespaceManager);


            // Find all <Signer> nodes in the <Signers> node
            XmlNodeList? signerNodes = codeIntegrityPolicy.SignersNode.SelectNodes("ns:Signer", codeIntegrityPolicy.NamespaceManager);

            if (signerNodes is null)
            {
                Logger.Write("MergeSignersSemantic: No Signer nodes found in the XML file. Exiting the function.");
                return;
            }


            // A dictionary to track unique FilePublisher signers for Signing Scenario 131 - Signers that have at least one FileAttribRef
            Dictionary<string, KernelModeSigner> uniqueFilePublisherSigners131 = [];

            // A dictionary to track unique Publisher signers for Signing Scenario 131 - Signers that have no FileAttribRef
            Dictionary<string, KernelModeSigner> uniquePublisherSigners131 = [];

            // A dictionary to track unique FilePublisher signers for Signing Scenario 12 - Signers that have at least one FileAttribRef
            Dictionary<string, UserModeSigner> uniqueFilePublisherSigners12 = [];

            // A dictionary to track unique Publisher signers for Signing Scenario 12 - Signers that have no FileAttribRef
            Dictionary<string, UserModeSigner> uniquePublisherSigners12 = [];

            // Find all of the <FileAttrib> elements in the <FileRules> node
            XmlNodeList? fileRulesElements = codeIntegrityPolicy.SiPolicyNode.SelectNodes("ns:FileRules/ns:FileAttrib", codeIntegrityPolicy.NamespaceManager);


            HashSet<string> fileRulesValidID_HashSet = [];

            if (fileRulesElements is not null)
            {
                foreach (XmlNode node in fileRulesElements)
                {
                    string? id = node?.Attributes?["ID"]?.Value;
                    if (id is not null)
                    {
                        _ = fileRulesValidID_HashSet.Add(id);
                    }
                }
            }


            // Iterate over each Signer node
            foreach (XmlNode signer in signerNodes)
            {

                // Get the current Signer's details
                string signerID = signer.Attributes!["ID"]!.Value; // Signer ID (required by CI Schema)
                string? signerCertRoot = signer.SelectSingleNode("ns:CertRoot", codeIntegrityPolicy.NamespaceManager)?.Attributes?["Value"]?.Value; // Signer's CertRoot aka TBS value (if it exists)
                string signerName = signer.Attributes!["Name"]!.Value; // Signer Name (required by CI Schema)
                string? signerCertPublisher = signer.SelectSingleNode("ns:CertPublisher", codeIntegrityPolicy.NamespaceManager)?.Attributes?["Value"]?.Value; // Signer Cert Publisher value (if it exists)

                // Create a unique key for each signer based on TBS, Name, and CertPublisher
                // All 4 types of signers will use the same key for identification
                string uniqueSignerKey = $"{signerCertRoot} | {signerName} | {signerCertPublisher}";

                // Get all of the <FileAttribRef> nodes of the current Signer
                XmlNodeList? signerFileAttribRef = signer.SelectNodes("ns:FileAttribRef", codeIntegrityPolicy.NamespaceManager);

                // If the signer has FileAttribRefs, it is a FilePublisher signer
                if (signerFileAttribRef is not null)
                {

                    // Making sure that each FilePublisher Signer has valid and unique FileAttribRef elements with IDs that point to an existing FileAttrib element in the <FileRules> node
                    UniqueXmlNodeSet ContentToReplaceWith = new();

                    foreach (XmlNode attribRef in signerFileAttribRef)
                    {

                        // Get the ID of the current <FileAttribRef> node under the current signer
                        string? ruleID = attribRef.Attributes?["RuleID"]?.Value;

                        if (ruleID is not null)
                        {
                            // Add the <FileAttribRef> node to the collection as long as it has a corresponding <FileAttrib> node in the <FileRules> node
                            if (fileRulesValidID_HashSet.Contains(ruleID))
                            {
                                _ = ContentToReplaceWith.Add(attribRef);
                            }
                        }

                        // Remove the FileAttribRef element from the Signer, whether it is valid or not
                        _ = attribRef.ParentNode!.RemoveChild(attribRef);
                    }

                    // Add the valid FileAttribRef elements back to the Signer
                    foreach (XmlNode node in ContentToReplaceWith.GetNodes())
                    {
                        _ = signer.AppendChild(codeIntegrityPolicy.XmlDocument.ImportNode(node, true));
                    }

                    // Determine the Signing Scenario by detecting which product signer contains the <AllowedSigner> node of the current signer in its <AllowedSigners> node
                    XmlNode? signingScenario = codeIntegrityPolicy.KMCI_ProductSignersNode.SelectSingleNode($"ns:AllowedSigners/ns:AllowedSigner[@SignerId='{signerID}']", codeIntegrityPolicy.NamespaceManager);

                    // If the signer is part of Signing Scenario 131 - Kernel Mode
                    if (signingScenario is not null)
                    {

                        // If the signer is not in the dictionary, add it with its necessary details
                        if (!uniqueFilePublisherSigners131.TryGetValue(uniqueSignerKey, out KernelModeSigner? possibleExistingSignerInfo))
                        {

                            // Create a temp class to store the signer and its details
                            KernelModeSigner kernelModeSigner = new(
                               signer.Clone(),
                                allowedSigners131?.SelectSingleNode($"ns:AllowedSigner[@SignerId='{signerID}']", codeIntegrityPolicy.NamespaceManager)!
                            );

                            // Add the signer class to the main Dictionary
                            uniqueFilePublisherSigners131.Add(uniqueSignerKey, kernelModeSigner);

                        }

                        // If the signer is already in the HashTable
                        else
                        {
                            // add each of its FileAttribRefs to the existing signer
                            foreach (XmlNode fileAttribRef in signerFileAttribRef)
                            {
                                _ = possibleExistingSignerInfo.Signer.AppendChild(codeIntegrityPolicy.XmlDocument.ImportNode(fileAttribRef, true));
                            }
                        }
                    }

                    // If the signer is part of Signing Scenario 12 - User Mode
                    else
                    {

                        // If the signer is not in the dictionary, add it with its necessary details
                        if (!uniqueFilePublisherSigners12.TryGetValue(uniqueSignerKey, out UserModeSigner? possibleExistingSignerInfo))
                        {

                            // Create a temp class to store the signer and its details
                            UserModeSigner userModeSigner = new(
                               signer.Clone(),
                               allowedSigners12?.SelectSingleNode($"ns:AllowedSigner[@SignerId='{signerID}']", codeIntegrityPolicy.NamespaceManager)!,
                               codeIntegrityPolicy.CiSignersNode.SelectSingleNode($"ns:CiSigner[@SignerId='{signerID}']", codeIntegrityPolicy.NamespaceManager)!
                            );

                            // Add the signer class to the main Dictionary
                            uniqueFilePublisherSigners12.Add(uniqueSignerKey, userModeSigner);

                        }

                        // If the signer is already in the HashTable
                        else
                        {
                            // add each of its FileAttribRefs to the existing signer
                            foreach (XmlNode fileAttribRef in signerFileAttribRef)
                            {
                                _ = possibleExistingSignerInfo.Signer.AppendChild(codeIntegrityPolicy.XmlDocument.ImportNode(fileAttribRef, true));

                            }
                        }
                    }
                }

                // If the signer has no FileAttribRefs, it is a Publisher or PCA signer
                else
                {

                    // Determine the Signing Scenario by detecting which product signer contains the <AllowedSigner> node of the current signer in its <AllowedSigners> node
                    XmlNode? signingScenario = codeIntegrityPolicy.KMCI_ProductSignersNode.SelectSingleNode($"ns:AllowedSigners/ns:AllowedSigner[@SignerId='{signerID}']", codeIntegrityPolicy.NamespaceManager);

                    // If the signer is part of Signing Scenario 131 - Kernel Mode
                    if (signingScenario is not null)
                    {

                        // If the signer is not in the dictionary, add it with its necessary details
                        if (!uniquePublisherSigners131.ContainsKey(uniqueSignerKey))
                        {

                            // Create a temp class to store the signer and its details
                            KernelModeSigner kernelModeSigner = new(
                               signer.Clone(),
                               allowedSigners131?.SelectSingleNode($"ns:AllowedSigner[@SignerId='{signerID}']", codeIntegrityPolicy.NamespaceManager)!
                            );

                            // Add the signer class to the main Dictionary
                            uniquePublisherSigners131.Add(uniqueSignerKey, kernelModeSigner);

                        }

                        /*
                        Else: exclude the current Publisher signer for Signing Scenario 131. Only one Publisher signer is allowed with the same TBS, Name, and CertPublisher.
                        */
                    }

                    //  If the signer is part of Signing Scenario 12
                    else
                    {

                        // If the signer is not in the dictionary, add it with its necessary details
                        if (!uniquePublisherSigners12.ContainsKey(uniqueSignerKey))
                        {

                            // Create a temp class to store the signer and its details
                            UserModeSigner userModeSigner = new(
                               signer.Clone(),
                               allowedSigners12?.SelectSingleNode($"ns:AllowedSigner[@SignerId='{signerID}']", codeIntegrityPolicy.NamespaceManager)!,
                               codeIntegrityPolicy.CiSignersNode.SelectSingleNode($"ns:CiSigner[@SignerId='{signerID}']", codeIntegrityPolicy.NamespaceManager)!
                            );

                            // Add the signer class to the main Dictionary
                            uniquePublisherSigners12.Add(uniqueSignerKey, userModeSigner);

                        }

                        /*
                        Else: exclude the current Publisher signer for Signing Scenario 12. Only one Publisher signer is allowed with the same TBS, Name, and CertPublisher.
                        */

                    }
                }
            }


            #region Give each signer a unique GUID-based ID

            foreach (UserModeSigner item in uniqueFilePublisherSigners12.Values)
            {

                // Create a unique ID for each signer
                string guid = Guid.NewGuid().ToString().Replace("-", "", StringComparison.OrdinalIgnoreCase).ToUpperInvariant();

                string uniqueID = $"ID_SIGNER_A_{guid}";

                // Set the ID attribute of the Signer node to the unique ID
                ((XmlElement)item.Signer).SetAttribute("ID", uniqueID);

                // Set the SignerId attribute of the AllowedSigner node to the unique ID
                ((XmlElement)item.AllowedSigner).SetAttribute("SignerId", uniqueID);

                // Set the SignerId attribute of the CiSigner node to the unique ID
                ((XmlElement)item.CiSigner).SetAttribute("SignerId", uniqueID);

            }



            foreach (UserModeSigner item in uniquePublisherSigners12.Values)
            {

                // Create a unique ID for each signer
                string guid = Guid.NewGuid().ToString().Replace("-", "", StringComparison.OrdinalIgnoreCase).ToUpperInvariant();

                string uniqueID = $"ID_SIGNER_B_{guid}";

                // Set the ID attribute of the Signer node to the unique ID
                ((XmlElement)item.Signer).SetAttribute("ID", uniqueID);

                // Set the SignerId attribute of the AllowedSigner node to the unique ID
                ((XmlElement)item.AllowedSigner).SetAttribute("SignerId", uniqueID);

                // Set the SignerId attribute of the CiSigner node to the unique ID
                ((XmlElement)item.CiSigner).SetAttribute("SignerId", uniqueID);

            }


            foreach (KernelModeSigner item in uniquePublisherSigners131.Values)
            {

                // Create a unique ID for each signer
                string guid = Guid.NewGuid().ToString().Replace("-", "", StringComparison.OrdinalIgnoreCase).ToUpperInvariant();

                string uniqueID = $"ID_SIGNER_B_{guid}";

                // Set the ID attribute of the Signer node to the unique ID
                ((XmlElement)item.Signer).SetAttribute("ID", uniqueID);

                // Set the SignerId attribute of the AllowedSigner node to the unique ID
                ((XmlElement)item.AllowedSigner).SetAttribute("SignerId", uniqueID);

            }


            foreach (KernelModeSigner item in uniqueFilePublisherSigners131.Values)
            {

                // Create a unique ID for each signer
                string guid = Guid.NewGuid().ToString().Replace("-", "", StringComparison.OrdinalIgnoreCase).ToUpperInvariant();

                string uniqueID = $"ID_SIGNER_A_{guid}";

                // Set the ID attribute of the Signer node to the unique ID
                ((XmlElement)item.Signer).SetAttribute("ID", uniqueID);

                // Set the SignerId attribute of the AllowedSigner node to the unique ID
                ((XmlElement)item.AllowedSigner).SetAttribute("SignerId", uniqueID);

            }

            #endregion


            // Clear the existing Signers node from any type of Signer
            codeIntegrityPolicy.SignersNode.RemoveAll();

            // Clear the existing AllowedSigners and CiSigners nodes from any type of Signer
            allowedSigners131?.RemoveAll();

            allowedSigners12?.RemoveAll();


            codeIntegrityPolicy.CiSignersNode.RemoveAll();


            #region Repopulate the Signers, AllowedSigners and CiSigners nodes with the unique values

            // Add the unique FilePublisher signers for Signing Scenario 131 back to the Signers node
            foreach (KernelModeSigner item in uniqueFilePublisherSigners131.Values)
            {
                // Add the <Signer> element to the <Signers> node
                _ = codeIntegrityPolicy.SignersNode.AppendChild(item.Signer);

                // Add the <AllowedSigner> nodes to the <AllowedSigners> node
                _ = allowedSigners131?.AppendChild(item.AllowedSigner);
            }

            // Add the unique Publisher signers for Signing Scenario 131 back to the Signers node
            foreach (KernelModeSigner item in uniquePublisherSigners131.Values)
            {
                // Add the <Signer> element to the <Signers> node
                _ = codeIntegrityPolicy.SignersNode.AppendChild(item.Signer);

                // Add the <AllowedSigner> nodes to the <AllowedSigners> node
                _ = allowedSigners131?.AppendChild(item.AllowedSigner);
            }

            // Add the unique FilePublisher signers for Signing Scenario 12 back to the Signers node
            foreach (UserModeSigner item in uniqueFilePublisherSigners12.Values)
            {
                // Add the <Signer> element to the <Signers> node
                _ = codeIntegrityPolicy.SignersNode.AppendChild(item.Signer);

                // Add the <AllowedSigner> nodes to the <AllowedSigners> node
                _ = allowedSigners12?.AppendChild(item.AllowedSigner);

                // Add the <CiSigner> element to the <CiSigners> node
                _ = codeIntegrityPolicy.CiSignersNode.AppendChild(item.CiSigner);
            }

            // Add the unique Publisher signers for Signing Scenario 12 back to the Signers node
            foreach (UserModeSigner item in uniquePublisherSigners12.Values)
            {
                // Add the <Signer> element to the <Signers> node
                _ = codeIntegrityPolicy.SignersNode.AppendChild(item.Signer);

                // Add the <AllowedSigner> nodes to the <AllowedSigners> node
                _ = allowedSigners12?.AppendChild(item.AllowedSigner);

                // Add the <CiSigner> element to the <CiSigners> node
                _ = codeIntegrityPolicy.CiSignersNode.AppendChild(item.CiSigner);
            }
            #endregion

            // Save the changes back to the XML file
            codeIntegrityPolicy.XmlDocument.Save(xmlFilePath);
        }
    }
}
