using System;
using System.Collections.Generic;
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
        ///
        /// This is according to the CI Schema
        ///
        /// Any stray <FileAttrib> node is also removed. They are nodes that don't have an associated <FileAttribRef> node in any <Signer> node.er>
        ///
        /// If needed a custom HashSet can be created based on the custom comparer so that between 2 identical fileAttribs, one with lower version will be kept while other one will be removed
        ///
        /// </summary>
        /// <param name="xmlFilePath"></param>
        internal static void Remove(string xmlFilePath)
        {

            // Instantiate the policy
            CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);



            // This method isn't suitable for strict Kernel-Mode policy
            if (codeIntegrityPolicy.UMCI_ProductSignersNode is null)
            {
                throw new InvalidOperationException("RemoveDuplicateFileAttribSemantic.Remove method isn't suitable for strict Kernel-Mode policy");
            }



            // Get all of the <FileAttrib> nodes inside the <FileRules> node
            XmlNodeList? fileAttribNodes = codeIntegrityPolicy.SiPolicyNode.SelectNodes("ns:FileRules//ns:FileAttrib", codeIntegrityPolicy.NamespaceManager);

            if (fileAttribNodes is null)
            {
                Logger.Write("No <FileAttrib> nodes have been found in the <FileRules> node");
                return;
            }

            // To store each <FileAttrib> nodes and its associated details for Kernel-Mode
            HashSet<FileAttrib> kernelModeFileAttribs = new(new FileAttribComparer());

            // To store each <FileAttrib> nodes and its associated details for User-Mode
            HashSet<FileAttrib> userModeFileAttribs = new(new FileAttribComparer());


            // Iterate over each <FileAttrib> node
            foreach (XmlNode item in fileAttribNodes)
            {
                // Get the ID
                string ID = item.Attributes!["ID"]!.Value;

                // Get the <Signer> node that contains the <FileAttribRef> node with the same RuleID as the ID of the current <FileAttrib> node in the loop
                XmlNode signer = codeIntegrityPolicy.SignersNode.SelectSingleNode($"ns:Signer[ns:FileAttribRef/@RuleID='{ID}']", codeIntegrityPolicy.NamespaceManager)!;

                // Get the Signer's ID
                string signerID = signer.Attributes!["ID"]!.Value;

                // Get the <FileAttribRef> from the signer that is associated with the current <FileAttrib> node
                XmlNode? fileAttribRefNode = signer.SelectSingleNode($"ns:FileAttribRef[@RuleID='{ID}']", codeIntegrityPolicy.NamespaceManager);

                if (fileAttribRefNode is null)
                {
                    // It's a stray <FileAttrib> node so don't include it in any HashSet, which will essentially mean we will not include it in the final XML file
                    continue;
                }

                // Try to get the <AllowedSigner> node in both SigningScenarios, give us the node itself and tells us which scenario this FileAttrib belongs to (through its Signer association).
                XmlNode? UMCI = codeIntegrityPolicy.UMCI_ProductSignersNode.SelectSingleNode($"ns:AllowedSigners/ns:AllowedSigner[@SignerId='{signerID}']", codeIntegrityPolicy.NamespaceManager);
                XmlNode? KMCI = codeIntegrityPolicy.KMCI_ProductSignersNode.SelectSingleNode($"ns:AllowedSigners/ns:AllowedSigner[@SignerId='{signerID}']", codeIntegrityPolicy.NamespaceManager);

                if (UMCI is null && KMCI is null)
                {
                    continue;
                }

                // Get attributes of the current <FileAttrib> node
                string? MinimumFileVersion = item.Attributes?["MinimumFileVersion"]?.Value;
                string? FileName = item.Attributes?["FileName"]?.Value;
                string? InternalName = item.Attributes?["InternalName"]?.Value;
                string? FileDescription = item.Attributes?["FileDescription"]?.Value;
                string? FilePath = item.Attributes?["FilePath"]?.Value;
                string? ProductName = item.Attributes?["ProductName"]?.Value;

                FileAttrib fileAttrib = new()
                {
                    Node = item,
                    Signer = signer,
                    AllowedSigner = UMCI ?? KMCI!,
                    FileAttribRef = fileAttribRefNode,
                    Id = ID,
                    MinimumFileVersion = MinimumFileVersion,
                    FileDescription = FileDescription,
                    FileName = FileName,
                    InternalName = InternalName,
                    FilePath = FilePath,
                    ProductName = ProductName
                };


                // If the current <FileAttrib> node belongs to User-Mode Signing Scenario
                if (UMCI is not null)
                {
                    // If the <FileAttrib> node is a duplicate one based on the custom comparer, then not only we don't include it in the final XML file
                    // We should also remove its associated <FileAttribRef> node from the <Signer> node
                    if (!userModeFileAttribs.Add(fileAttrib))
                    {
                        _ = fileAttrib.FileAttribRef.ParentNode?.RemoveChild(fileAttrib.FileAttribRef);
                    }
                }
                // If the current <FileAttrib> node belongs to Kernel-Mode Signing Scenario
                else
                {
                    // If the <FileAttrib> node is a duplicate one based on the custom comparer, then not only we don't include it in the final XML file
                    // We should also remove its associated <FileAttribRef> node from the <Signer> node
                    if (!kernelModeFileAttribs.Add(fileAttrib))
                    {
                        _ = fileAttrib.FileAttribRef.ParentNode?.RemoveChild(fileAttrib.FileAttribRef);
                    }
                }
            }


            // Remove all <FileAttrib> nodes inside the <FileRules> node
            foreach (XmlNode node in fileAttribNodes)
            {
                // Remove each node from its parent
                _ = node.ParentNode?.RemoveChild(node);
            }

            // Add the <FileAttrib> nodes back to the <FileRules> node
            if (kernelModeFileAttribs.Count > 0)
            {
                foreach (FileAttrib item in kernelModeFileAttribs)
                {
                    // Add the node back to the parent
                    _ = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:FileRules", codeIntegrityPolicy.NamespaceManager)!.AppendChild(item.Node);
                }
            }
            if (userModeFileAttribs.Count > 0)
            {
                foreach (FileAttrib item in userModeFileAttribs)
                {
                    // Add the node back to the parent
                    _ = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:FileRules", codeIntegrityPolicy.NamespaceManager)!.AppendChild(item.Node);
                }
            }

            // Save the changes to the XML file
            codeIntegrityPolicy.XmlDocument.Save(xmlFilePath);

        }

    }

}

