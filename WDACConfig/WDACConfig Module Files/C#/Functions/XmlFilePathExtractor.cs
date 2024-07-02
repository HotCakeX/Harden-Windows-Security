using System;
using System.Collections.Generic;
using System.IO;
using System.Xml;
namespace WDACConfig
{
    public class XmlFilePathExtractor
    {
        public static HashSet<string> GetFilePaths(string xmlFilePath)
        {
            HashSet<string> filePaths = new HashSet<string>();

            XmlDocument doc = new XmlDocument();
            doc.Load(xmlFilePath);
            XmlNamespaceManager nsmgr = new XmlNamespaceManager(doc.NameTable);
            nsmgr.AddNamespace("ns", "urn:schemas-microsoft-com:sipolicy");

            XmlNodeList allowNodes = doc.SelectNodes("//ns:Allow", nsmgr);
            foreach (XmlNode node in allowNodes)
            {
                if (node.Attributes["FilePath"] != null)
                {
                    filePaths.Add(node.Attributes["FilePath"].Value);
                }
            }

            return filePaths;
        }
    }
}
