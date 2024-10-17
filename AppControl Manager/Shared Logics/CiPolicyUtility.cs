using System;
using System.IO;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    public static class CiPolicyUtility
    {
        /// <summary>
        /// Copies the rules from one CI policy XML file to another.
        /// </summary>
        /// <param name="sourceFilePath">The source CI policy XML file path.</param>
        /// <param name="destinationFilePath">The destination CI policy XML file path.</param>
        public static void CopyCiRules(string sourceFilePath, string destinationFilePath)
        {
            // Validate file paths
            if (string.IsNullOrWhiteSpace(sourceFilePath))
            {
                throw new ArgumentException("Source file path cannot be null or empty.", nameof(sourceFilePath));
            }
            if (string.IsNullOrWhiteSpace(destinationFilePath))
            {
                throw new ArgumentException("Destination file path cannot be null or empty.", nameof(destinationFilePath));
            }
            if (!File.Exists(sourceFilePath))
            {
                throw new FileNotFoundException("Source file not found.", sourceFilePath);
            }
            if (!File.Exists(destinationFilePath))
            {
                throw new FileNotFoundException("Destination file not found.", destinationFilePath);
            }

            // Load the XML files as XmlDocument objects
            XmlDocument sourceXmlDoc = new();
            sourceXmlDoc.Load(sourceFilePath);

            XmlDocument destinationXmlDoc = new();
            destinationXmlDoc.Load(destinationFilePath);

            // Create an XmlNamespaceManager to handle the default namespace
            XmlNamespaceManager nsmgr = new(sourceXmlDoc.NameTable);
            nsmgr.AddNamespace("ns", "urn:schemas-microsoft-com:sipolicy");

            // Select the Rules node in the source XML document
            XmlNode? sourceRulesNode = sourceXmlDoc.SelectSingleNode("/ns:SiPolicy/ns:Rules", nsmgr) ?? throw new InvalidOperationException("The <Rules> node was not found in the source XML file.");

            // Select the SiPolicy node in the destination XML document
            XmlNode? destinationSiPolicyNode = destinationXmlDoc.SelectSingleNode("/ns:SiPolicy", nsmgr) ?? throw new InvalidOperationException("The <SiPolicy> node was not found in the destination XML file.");

            // Select the existing Rules node in the destination XML document
            XmlNode? destinationRulesNode = destinationSiPolicyNode.SelectSingleNode("ns:Rules", nsmgr) ?? throw new InvalidOperationException("The <Rules> node was not found in the destination XML file.");

            // Replace the rules block in destinationXmlDoc with the rules block in sourceXmlDoc
            // Use the ImportNode method to create a copy of the rules node from $SourceFileContent
            // The second parameter ($true) indicates a deep clone, meaning that the node and its descendants are copied
            // https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmldocument.importnode
            XmlNode importedRulesNode = destinationXmlDoc.ImportNode(sourceRulesNode, true);
            _ = destinationSiPolicyNode.ReplaceChild(importedRulesNode, destinationRulesNode);

            destinationXmlDoc.Save(destinationFilePath);
        }
    }
}
