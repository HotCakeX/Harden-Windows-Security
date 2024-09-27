using System;
using System.Collections.Generic;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    public class XmlFilePathExtractor
    {
        public static HashSet<string> GetFilePaths(string xmlFilePath)
        {
            // Initialize HashSet with StringComparer.OrdinalIgnoreCase to ensure case-insensitive, ordinal comparison
            HashSet<string> filePaths = new(StringComparer.OrdinalIgnoreCase);

            XmlDocument doc = new();
            doc.Load(xmlFilePath);

            // Create and configure XmlNamespaceManager
            XmlNamespaceManager nsmgr = new(doc.NameTable);
            nsmgr.AddNamespace("ns", "urn:schemas-microsoft-com:sipolicy");

            // Select all nodes with the "Allow" tag
            XmlNodeList? allowNodes = doc.SelectNodes("//ns:Allow", nsmgr);

            if (allowNodes != null)
            {

                foreach (XmlNode node in allowNodes)
                {
                    // Ensure node.Attributes is not null
                    if (node.Attributes != null && node.Attributes["FilePath"] != null)
                    {
                        // Add the file path to the HashSet
                        _ = filePaths.Add(node.Attributes["FilePath"]!.Value);
                    }
                }
            }

            return filePaths;
        }
    }
}
