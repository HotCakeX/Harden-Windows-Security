using System.Collections.Generic;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    public static class Macros
    {
        /// <summary>
        /// This method can backup the Macros node from an XML file by outputting them for storage in a variable.
        /// </summary>
        /// <param name="xmlFilePath"></param>
        /// <returns></returns>
        public static XmlNode? Backup(string xmlFilePath)
        {
            // Instantiate the policy
            CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);

            // Find the Macros node
            XmlNode? Macros = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:Macros", codeIntegrityPolicy.NamespaceManager);

            if (Macros is not null)
            {
                return Macros.Clone();
            }

            return null;
        }

        /// <summary>
        /// This method can backup the Macros node from multiple XML file by outputting them for storage in a variable.
        /// </summary>
        /// <param name="xmlFilePath"></param>
        /// <returns></returns>
        public static List<XmlNode>? Backup(List<string> xmlFilePath)
        {
            // A list to store <Macros> nodes
            List<XmlNode> macroNodes = [];

            foreach (string file in xmlFilePath)
            {
                // Instantiate the policy
                CodeIntegrityPolicy codeIntegrityPolicy = new(file, null);

                // Find the Macros node
                XmlNode? Macros = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:Macros", codeIntegrityPolicy.NamespaceManager);

                if (Macros is not null)
                {
                    macroNodes.Add(Macros.Clone());
                }
            }

            if (macroNodes.Count > 0)
            {
                return macroNodes;
            }

            return null;
        }


        /// <summary>
        /// This method can restore a single Macro node to a single policy file from the backups variable.
        /// Each valid CI policy XML file only contains a single Macros node.
        /// </summary>
        /// <param name="xmlFilePath"></param>
        /// <param name="macroNode"></param>
        public static void Restore(string xmlFilePath, XmlNode? macroNode)
        {
            // Instantiate the policy
            CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);

            if (macroNode is not null)
            {
                Logger.Write($"Restoring {macroNode.ChildNodes.Count} Macros.");
            }
            else
            {
                Logger.Write("No Macros node to restore.");
                return;
            }

            // Find the Macros node
            XmlNode? CurrentMacros = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:Macros", codeIntegrityPolicy.NamespaceManager);

            // Remove the Macros node if it exists
            if (CurrentMacros is not null)
            {
                _ = codeIntegrityPolicy.XmlDocument.DocumentElement?.RemoveChild(CurrentMacros);
            }

            // Create a new Macros node
            XmlNode newMacrosNode = codeIntegrityPolicy.XmlDocument.CreateElement("Macros", codeIntegrityPolicy.NameSpaceURI);

            // Combine all Macro nodes into the new Macros node
            foreach (XmlNode node in macroNode.ChildNodes)
            {
                XmlNode importedMacroNode = codeIntegrityPolicy.XmlDocument.ImportNode(node, true);

                _ = newMacrosNode.AppendChild(importedMacroNode);
            }

            // Append the new Macros node to the XML file
            _ = codeIntegrityPolicy.XmlDocument.DocumentElement?.AppendChild(newMacrosNode);

            // Save the modified XML back to the file
            codeIntegrityPolicy.XmlDocument.Save(xmlFilePath);
        }





        /// <summary>
        /// This method can restore the Macros nodes to a single policy file from the backups variable.
        /// Each valid CI policy XML file only contains a single Macros node.
        /// </summary>
        /// <param name="xmlFilePath"></param>
        /// <param name="macroNodes"></param>
        public static void Restore(string xmlFilePath, List<XmlNode>? macroNodes)
        {
            // Instantiate the policy
            CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);

            if (macroNodes is not null)
            {
                Logger.Write($"Restoring {macroNodes.Count} Macros nodes.");
            }
            else
            {
                Logger.Write("No Macros nodes to restore.");
                return;
            }

            // Find the Macros node
            XmlNode? CurrentMacros = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:Macros", codeIntegrityPolicy.NamespaceManager);

            // Remove the Macros node if it exists
            if (CurrentMacros is not null)
            {
                _ = codeIntegrityPolicy.XmlDocument.DocumentElement?.RemoveChild(CurrentMacros);
            }

            // Create a new Macros node
            XmlNode newMacrosNode = codeIntegrityPolicy.XmlDocument.CreateElement("Macros", codeIntegrityPolicy.NameSpaceURI);

            foreach (XmlNode node in macroNodes)
            {
                foreach (XmlNode childNode in node.ChildNodes)
                {
                    XmlNode importedMacroNode = codeIntegrityPolicy.XmlDocument.ImportNode(childNode, true);

                    _ = newMacrosNode.AppendChild(importedMacroNode);
                }
            }

            // Append the new Macros node to the XML file
            _ = codeIntegrityPolicy.XmlDocument.DocumentElement?.AppendChild(newMacrosNode);

            // Save the modified XML back to the file
            codeIntegrityPolicy.XmlDocument.Save(xmlFilePath);
        }
    }
}
