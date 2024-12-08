using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;

namespace AppControlManager.SiPolicyIntel
{
    public static class SiPolicyProcessor
    {
        /// <summary>
        /// Processes an XML file to remove duplicate FileAttrib elements and updates Signer FileAttribRef elements to use the retained FileAttrib ID.
        /// It also removes duplicate FileAttribRef elements for each signer.
        /// </summary>
        /// <param name="filePath">The path to the XML file.</param>
        public static void ProcessSiPolicyXml(string filePath)
        {
            // Load the XML document from the file specified by filePath
            XDocument xmlDoc = XDocument.Load(filePath);

            // Define the XML namespace used in the XML document
            XNamespace ns = "urn:schemas-microsoft-com:sipolicy";

            // Step 1: Remove duplicate <FileAttrib> elements

            // Get a list of all <FileAttrib> elements from the XML file
            List<XElement> fileAttribs = xmlDoc.Descendants(ns + "FileAttrib").ToList();

            // Group <FileAttrib> elements by their attribute values (except the "ID" attribute) - anonymous type
            var groupedFileAttribs = fileAttribs
                .GroupBy(fa => new
                {
                    FriendlyName = fa.Attribute("FriendlyName")?.Value,
                    FileName = fa.Attribute("FileName")?.Value,
                    InternalName = fa.Attribute("InternalName")?.Value,
                    FileDescription = fa.Attribute("FileDescription")?.Value,
                    ProductName = fa.Attribute("ProductName")?.Value,
                    PackageFamilyName = fa.Attribute("PackageFamilyName")?.Value,
                    PackageVersion = fa.Attribute("PackageVersion")?.Value,
                    MinimumFileVersion = fa.Attribute("MinimumFileVersion")?.Value,
                    MaximumFileVersion = fa.Attribute("MaximumFileVersion")?.Value,
                    Hash = fa.Attribute("Hash")?.Value,
                    AppIDs = fa.Attribute("AppIDs")?.Value,
                    FilePath = fa.Attribute("FilePath")?.Value
                })
                .Where(g => g.Count() > 1) // Only keep groups with more than one duplicate <FileAttrib>
                .ToList();

            // Iterate over each group of duplicate <FileAttrib> elements
            foreach (var group in groupedFileAttribs)
            {
                // Get the list of all <FileAttrib> elements in the current group
                List<XElement> fileAttribList = [.. group];

                // Keep the first <FileAttrib> element in the group (we will keep this one)
                XElement fileAttribToKeep = fileAttribList.First();

                // Get the ID of the <FileAttrib> that we will keep
                string? idToKeep = fileAttribToKeep.Attribute("ID")?.Value;

                // Remove all other <FileAttrib> elements in the group except the one we are keeping
                foreach (XElement fileAttribToRemove in fileAttribList.Skip(1))
                {
                    fileAttribToRemove.Remove();
                }

                // Get a list of IDs of the <FileAttrib> elements that were removed
                List<string?> fileAttribIdsToReplace = fileAttribList.Skip(1).Select(fa => fa.Attribute("ID")?.Value).ToList();

                if (!string.IsNullOrEmpty(idToKeep) && fileAttribIdsToReplace.Count > 0)
                {
                    // Get all <FileAttribRef> elements that reference the removed <FileAttrib> elements
                    IEnumerable<XElement> fileAttribRefs = xmlDoc.Descendants(ns + "FileAttribRef")
                        .Where(refElem => fileAttribIdsToReplace.Contains(refElem.Attribute("RuleID")?.Value));

                    // Update each <FileAttribRef> to use the ID of the retained <FileAttrib> 
                    foreach (XElement refElem in fileAttribRefs)
                    {
                        refElem.SetAttributeValue("RuleID", idToKeep);
                    }
                }
            }

            // Step 2: Remove duplicate <FileAttribRef> elements within each <Signer>

            // Get a list of all <Signer> elements in the XML document
            List<XElement> signers = xmlDoc.Descendants(ns + "Signer").ToList();

            // Loop over each <Signer> element
            foreach (var signer in signers)
            {
                // Keep track of RuleID values that we have seen for <FileAttribRef> elements under this signer
                var seenRuleIds = new HashSet<string>();

                // Get a list of <FileAttribRef> elements under the current <Signer>
                var fileAttribRefs = signer.Elements(ns + "FileAttribRef").ToList();

                // Loop over each <FileAttribRef> for the current <Signer>
                foreach (XElement fileAttribRef in fileAttribRefs)
                {
                    // Get the RuleID attribute from the current <FileAttribRef> element
                    string? ruleId = fileAttribRef.Attribute("RuleID")?.Value;

                    // If RuleID is not empty
                    if (!string.IsNullOrEmpty(ruleId))
                    {
                        // If we have already seen this RuleID, remove this <FileAttribRef> (it's a duplicate)
                        if (!seenRuleIds.Add(ruleId)) // Add() returns false if the RuleID is already in the set
                        {
                            fileAttribRef.Remove();
                        }
                    }
                }
            }

            // Save the modified XML back to the file at the specified filePath
            xmlDoc.Save(filePath);
        }
    }
}
