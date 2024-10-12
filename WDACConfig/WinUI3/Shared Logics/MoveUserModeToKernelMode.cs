using System;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    public static class MoveUserModeToKernelMode
    {
        /// <summary>
        /// Moves all User mode AllowedSigners in the User mode signing scenario to the Kernel mode signing scenario and then
        /// deletes the entire User mode signing scenario block
        /// This is used during the creation of Strict Kernel-mode WDAC policy for complete BYOVD protection scenario.
        /// It doesn't consider <FileRulesRef> node in the SigningScenario 12 when deleting it because for kernel-mode policy everything is signed and we don't deal with unsigned files.
        /// </summary>
        /// <param name="filePath">The path to the XML file</param>
        /// <exception cref="Exception"></exception>
        public static void Move(string filePath)
        {
            try
            {
                // Create an XmlDocument object
                XmlDocument xml = new();

                // Load the XML file
                xml.Load(filePath);

                // Create an XmlNameSpaceManager object
                XmlNamespaceManager nsManager = new(xml.NameTable);
                // Define namespace
                nsManager.AddNamespace("sip", "urn:schemas-microsoft-com:sipolicy");

                // Get all SigningScenario nodes in the XML file
                XmlNodeList? signingScenarios = xml.SelectNodes("//sip:SigningScenario", nsManager);

                // Variables to store SigningScenario nodes with specific values 12 and 131
                XmlNode? signingScenario12 = null;
                XmlNode? signingScenario131 = null;

                // If there is no SigningScenarios block in the XML then exit the method
                if (signingScenarios == null)
                {
                    return;
                }

                // Find SigningScenario nodes with Value 12 and 131
                foreach (XmlNode signingScenario in signingScenarios)
                {
                    string? valueAttr = signingScenario.Attributes?["Value"]?.Value;

                    if (string.Equals(valueAttr, "12", StringComparison.OrdinalIgnoreCase))
                    {
                        signingScenario12 = signingScenario;
                    }
                    else if (string.Equals(valueAttr, "131", StringComparison.OrdinalIgnoreCase))
                    {
                        signingScenario131 = signingScenario;
                    }
                }

                // If both SigningScenario nodes were found
                if (signingScenario12 != null && signingScenario131 != null)
                {
                    // Get AllowedSigners from SigningScenario with Value 12
                    XmlNode? allowedSigners12 = signingScenario12.SelectSingleNode("./sip:ProductSigners/sip:AllowedSigners", nsManager);

                    // If AllowedSigners node exists in SigningScenario 12 and has child nodes
                    if (allowedSigners12 != null && allowedSigners12.HasChildNodes)
                    {
                        // Loop through each child node of AllowedSigners in SigningScenario 12
                        foreach (XmlNode allowedSignerNode in allowedSigners12.ChildNodes)
                        {
                            // Ensure we're only working with XmlElement nodes and not comments or anything else

                            // This line is a pattern matching statement:
                            // allowedSignerNode is the current node from the foreach loop.
                            // The is keyword checks if allowedSignerNode is of type XmlElement.
                            // If the check is successful, allowedSigner is created as a new variable within the scope of the if block, and it is assigned the value of allowedSignerNode.
                            // Essentially, allowedSigner is created implicitly as part of the pattern matching expression.

                            if (allowedSignerNode is XmlElement allowedSigner)
                            {
                                // Create a new AllowedSigner node
                                XmlNode newAllowedSigner = xml.CreateElement("AllowedSigner", "urn:schemas-microsoft-com:sipolicy");

                                // Create a SignerId attribute for the new AllowedSigner node
                                XmlAttribute newSignerIdAttr = xml.CreateAttribute("SignerId");

                                // Set the value of the new SignerId attribute to the value of the existing SignerId attribute
                                newSignerIdAttr.Value = allowedSigner.Attributes["SignerId"]!.Value;

                                // Append the new SignerId attribute to the new AllowedSigner node
                                _ = newAllowedSigner.Attributes!.Append(newSignerIdAttr);

                                // Find the AllowedSigners node in SigningScenario 131
                                XmlNode? allowedSigners131 = signingScenario131.SelectSingleNode("./sip:ProductSigners/sip:AllowedSigners", nsManager);

                                // If the AllowedSigners node exists in SigningScenario 131
                                if (allowedSigners131 != null)
                                {
                                    // Append the new AllowedSigner node to the AllowedSigners node in SigningScenario 131
                                    _ = allowedSigners131.AppendChild(newAllowedSigner);
                                }
                            }
                        }

                        // Remove SigningScenario with Value 12 completely after moving all of its AllowedSigners to SigningScenario with the value of 131
                        _ = (signingScenario12.ParentNode?.RemoveChild(signingScenario12));
                    }
                }

                // Save the modified XML document back to the file
                xml.Save(filePath);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"An error occurred: {ex.Message}", ex);
            }
        }
    }
}
