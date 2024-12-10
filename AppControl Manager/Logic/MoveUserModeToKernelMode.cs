using AppControlManager.Logging;
using System;
using System.Xml;

namespace AppControlManager
{
    public static class MoveUserModeToKernelMode
    {
        /// <summary>
        /// Moves all User mode AllowedSigners in the User mode signing scenario to the Kernel mode signing scenario and then
        /// deletes the entire User mode signing scenario block
        /// This is used during the creation of Strict Kernel-mode App Control policy for complete BYOVD protection scenario.
        /// It doesn't consider <FileRulesRef> node in the SigningScenario 12 when deleting it because for kernel-mode policy everything is signed and we don't deal with unsigned files.
        /// </summary>
        /// <param name="filePath">The path to the XML file</param>
        /// <exception cref="Exception"></exception>
        public static void Move(string filePath)
        {

            // Instantiate the policy
            CodeIntegrityPolicy codeIntegrityPolicy = new(filePath, null);

            // Get AllowedSigners from SigningScenario with Value 12
            XmlNode? allowedSigners12 = codeIntegrityPolicy.UMCI_SigningScenarioNode?.SelectSingleNode("./ns:ProductSigners/ns:AllowedSigners", codeIntegrityPolicy.NamespaceManager);

            // If AllowedSigners node exists in SigningScenario 12 and has child nodes
            if (allowedSigners12 is not null && allowedSigners12.HasChildNodes)
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
                        XmlNode newAllowedSigner = codeIntegrityPolicy.XmlDocument.CreateElement("AllowedSigner", "urn:schemas-microsoft-com:sipolicy");

                        // Create a SignerId attribute for the new AllowedSigner node
                        XmlAttribute newSignerIdAttr = codeIntegrityPolicy.XmlDocument.CreateAttribute("SignerId");

                        // Set the value of the new SignerId attribute to the value of the existing SignerId attribute
                        newSignerIdAttr.Value = allowedSigner.Attributes["SignerId"]!.Value;

                        // Append the new SignerId attribute to the new AllowedSigner node
                        _ = newAllowedSigner.Attributes!.Append(newSignerIdAttr);

                        // Find the AllowedSigners node in SigningScenario 131
                        XmlNode? allowedSigners131 = codeIntegrityPolicy.KMCI_SigningScenarioNode?.SelectSingleNode("./ns:ProductSigners/ns:AllowedSigners", codeIntegrityPolicy.NamespaceManager);

                        // If the AllowedSigners node exists in SigningScenario 131
                        if (allowedSigners131 is not null)
                        {
                            // Append the new AllowedSigner node to the AllowedSigners node in SigningScenario 131
                            _ = allowedSigners131.AppendChild(newAllowedSigner);
                        }
                        else
                        {
                            Logger.Write("MoveUserModeToKernelMode: Allowed Signers in Kernel Mode Signing Scenario was null, did not move UMCI rules to KMCI.");
                        }
                    }
                }

                // Remove SigningScenario with Value 12 completely after moving all of its AllowedSigners to SigningScenario with the value of 131
                _ = (codeIntegrityPolicy.UMCI_SigningScenarioNode?.ParentNode?.RemoveChild(codeIntegrityPolicy.UMCI_SigningScenarioNode));
            }

            // Save the modified XML document back to the file
            codeIntegrityPolicy.XmlDocument.Save(filePath);

        }
    }
}
