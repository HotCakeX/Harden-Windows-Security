using System.Collections.Generic;
using System.Linq;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    internal static class RemoveDuplicateFileAttribSemantic
    {
        /// <summary>
        /// A method that deduplicates the <FileAttrib> nodes inside the <FileRules> node.
        /// It successfully detects duplicate <FileAttrib> nodes based on their properties.
        /// For example, if two <FileAttrib> nodes have the same MinimumFileVersion and one of these properties of them are the same (FileName, InternalName, FileDescription, FilePath, and ProductName), they are considered half-duplicates.
        /// In order to be considered fully duplicate, they must also be associated with Signers whose IDs are in the same SigningScenario.
        ///
        /// So for example, if two <FileAttrib> nodes have the same FileName and MinimumFileVersion, but they are associated with 2 different Signers, one in kernel mode and the other in user mode signing scenario, they are not considered duplicates.
        /// After deduplication, the function updates the FileAttribRef RuleID for associated Signers by setting the RuleID of the removed duplicate FileAttrib elements to the RuleID of the unique remaining FileAttrib element.
        ///
        /// This is according to the CI Schema
        ///
        /// </summary>
        /// <param name="xmlFilePath"></param>
        internal static void Remove(string xmlFilePath)
        {

            // Instantiate the policy
            CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);

            // Get all of the <FileAttrib> nodes inside the <FileRules> node
            XmlNodeList? fileAttribNodes = codeIntegrityPolicy.SiPolicyNode.SelectNodes("ns:FileRules//ns:FileAttrib", codeIntegrityPolicy.NamespaceManager);

            if (fileAttribNodes is null)
            {
                Logger.Write("No <FileAttrib> nodes have been found in the <FileRules> node");
                return;
            }

            // A Dictionary to store FileAttrib nodes based on their properties
            Dictionary<string, List<XmlNode>> fileAttribNodeCollection = [];

            // A Dictionary to store each unique FileAttrib key along with its associated unique Signer IDs
            Dictionary<string, HashSet<string>> fileAttribSignerCollection = [];

            // A Dictionary to store each Signer ID (associated with the current FileAttrib node) and its associated <AllowedSigner> node's ID
            Dictionary<string, string> allowedSignerCollection = [];

            // Iterate through each FileAttrib nodes
            foreach (XmlNode fileAttrib in fileAttribNodes)
            {

                // Get the relevant properties of the current <FileAttrib> node
                string fileAttribID = fileAttrib.Attributes!["ID"]!.Value;

                string? MinimumFileVersion = fileAttrib.Attributes?["MinimumFileVersion"]?.Value;
                string? FileName = fileAttrib.Attributes?["FileName"]?.Value;
                string? InternalName = fileAttrib.Attributes?["InternalName"]?.Value;
                string? FileDescription = fileAttrib.Attributes?["FileDescription"]?.Value;
                string? FilePath = fileAttrib.Attributes?["FilePath"]?.Value;
                string? ProductName = fileAttrib.Attributes?["ProductName"]?.Value;


                // Generate a unique key based on relevant properties
                string uniqueKey = $"{MinimumFileVersion}-{FileName}-{InternalName}-{FileDescription}-{FilePath}-{ProductName}";

                // Check if the key already exists in the dictionary
                if (!fileAttribNodeCollection.TryGetValue(uniqueKey, out List<XmlNode>? possibleFileAttrib))
                {
                    // If not, add the key and store the FileAttrib node as a list
                    _ = fileAttribNodeCollection.TryAdd(uniqueKey, [fileAttrib]);
                }

                // If the key already exists, append the current FileAttrib node to the existing list of nodes
                else
                {
                    possibleFileAttrib.Add(fileAttrib);
                }

                // At this point, each <FileAttrib> node in the XML file is identified and grouped together based on their properties

                // Get the Signer ID associated with the current FileAttrib
                XmlNode? signer = codeIntegrityPolicy.SignersNode.SelectSingleNode($"ns:Signer[ns:FileAttribRef/@RuleID='{fileAttribID}']", codeIntegrityPolicy.NamespaceManager);

                string signerID;

                if (signer is not null)
                {
                    signerID = signer.Attributes!["ID"]!.Value;
                }
                else
                {
                    // Signer ID cannot be null!
                    continue;
                }

                // Add the Unique FileAttrib key and its associated Signer ID to the dictionary
                if (!fileAttribSignerCollection.TryGetValue(uniqueKey, out HashSet<string>? possibleFileAttribSigner))
                {
                    // If not, add the key and store the Signer ID as value
                    _ = fileAttribSignerCollection.TryAdd(uniqueKey, [signerID]);
                }

                // If the key already exists, append the Signer ID to the existing HashSet of strings
                else
                {
                    _ = possibleFileAttribSigner.Add(signerID);
                }


                // Get the ID of the <AllowedSigner> node that is associated with the current Signer ID
                // Checks all <SigningScenario> nodes throughout the XML
                XmlNode? allowedSigner = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode($"//ns:SigningScenario[ns:ProductSigners/ns:AllowedSigners/ns:AllowedSigner[@SignerId='{signerID}']]", codeIntegrityPolicy.NamespaceManager);

                if (allowedSigner is null)
                {
                    // each signer must have an <AllowedSigner> node!
                    continue;
                }

                string allowedSignerID = allowedSigner.Attributes!["ID"]!.Value;


                // Add the Signer ID and its associated allowedSigner ID to the dictionary
                if (!allowedSignerCollection.ContainsKey(signerID))
                {
                    _ = allowedSignerCollection.TryAdd(signerID, allowedSignerID);
                }
            }


            // Iterate through the dictionary to find and remove duplicate <FileAttrib> nodes
            foreach (string key in fileAttribNodeCollection.Keys)
            {

                // Only proceed if there are more than one FileAttrib node for this key
                // Indicating that more than 1 <FileAttrib> node with the same exact attributes (except for ID and FriendlyName) exist
                if (fileAttribNodeCollection.TryGetValue(key, out List<XmlNode>? possibleExistingNodes) && possibleExistingNodes.Count == 1)
                {
                    continue;
                }

                if (possibleExistingNodes is null)
                {
                    continue;
                }

                // Get the associated SignerID of each duplicate <FileAttrib> node
                // Each <FileAttrib> node is associated with a <Signer> node and we get that node's ID
                _ = fileAttribSignerCollection.TryGetValue(key, out HashSet<string>? signerIDs);

                if (signerIDs is null)
                {
                    continue;
                }

                // A HashSet to store the unique AllowedSigner IDs associated with the Signer IDs
                HashSet<string> allowedSignerCol = [];

                // Get the unique <AllowedSigner> node IDs associated with the Signer IDs
                // Each <Signer> node associated with each duplicate <FileAttrib> node has an <AllowedSigner> node
                foreach (string id in signerIDs)
                {
                    _ = allowedSignerCollection.TryGetValue(id, out string? possibleSigningScenario);

                    if (possibleSigningScenario is not null)
                    {
                        _ = allowedSignerCol.Add(possibleSigningScenario);
                    }
                }

                // If there are multiple unique AllowedSigner IDs associated with this set of Signer IDs
                if (allowedSignerCol.Count > 1)
                {
                    // Skip deduplication as the Signer IDs are in different Signing scenarios, meaning both User and Kernel nodes are involved so it shouldn't be touched
                    // According to the schema, each signer must have only 1 <AllowedSigner> node in only one SigningScenario.
                    // The same signer cannot belong to kernel Mode and User Mode scenarios at the same time.
                    // This logic is based on that.
                    continue;
                }
                else
                {
                    // Remove duplicates by keeping only the first FileAttrib element
                    XmlNode firstFileAttrib = possibleExistingNodes.First();

                    string? firstFileAttribID = firstFileAttrib.Attributes?["ID"]?.Value;

                    if (firstFileAttribID is null)
                    {
                        continue;
                    }

                    // Iterate through the remaining FileAttrib elements, starting from the 2nd element
                    for (int i = 1; i < possibleExistingNodes.Count; i++)
                    {

                        // Get the duplicate FileAttrib element to remove based on the index
                        XmlNode duplicateFileAttrib = possibleExistingNodes[i];

                        string? duplicateFileAttribID = duplicateFileAttrib?.Attributes?["ID"]?.Value;

                        if (duplicateFileAttribID is null)
                        {
                            continue;
                        }

                        // Update FileAttribRef RuleID for associated Signers
                        foreach (string id in signerIDs)
                        {

                            // Get the Signer element associated with this Signer ID
                            XmlNode? signer = codeIntegrityPolicy.SignersNode.SelectSingleNode($"ns:Signer[@ID='{id}']", codeIntegrityPolicy.NamespaceManager);

                            if (signer is null)
                            {
                                continue;
                            }


                            // Get the FileAttribRef node associated with the duplicate FileAttrib node, from the signer
                            XmlNode? fileAttribRef = signer.SelectSingleNode($"ns:FileAttribRef[@RuleID='{duplicateFileAttribID}']", codeIntegrityPolicy.NamespaceManager);

                            if (fileAttribRef is null)
                            {
                                continue;
                            }

                            // Updating the RuleID of the duplicate <FileAttribRef> of the Signer before removing it and setting it to the RuleID of the unique remaining FileAttrib element

                            XmlNodeList signerAttribs = signer.SelectNodes("ns:FileAttribRef", codeIntegrityPolicy.NamespaceManager)!;

                            List<string> signerAttribsIDs = [];

                            foreach (XmlElement signerAttr in signerAttribs)
                            {
                                signerAttribsIDs.Add(signerAttr.GetAttribute("RuleID", codeIntegrityPolicy.NameSpaceURI));
                            }

                            if (!signerAttribsIDs.Contains(firstFileAttribID))
                            {
                                ((XmlElement)fileAttribRef).SetAttribute("RuleID", firstFileAttribID);
                            }
                        }


                        _ = duplicateFileAttrib?.ParentNode?.RemoveChild(duplicateFileAttrib);
                    }
                }

            }

            codeIntegrityPolicy.XmlDocument.Save(xmlFilePath);

        }

    }

}

