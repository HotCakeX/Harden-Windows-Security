using System;

namespace AppControlManager.Others;

internal static class RemoveUserModeSS
{
	/// <summary>
	/// Removes the User-mode signing scenario block completely
	/// </summary>
	/// <param name="filePath">The path to the XML file</param>
	/// <exception cref="Exception"></exception>
	internal static void Remove(string filePath)
	{
		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(filePath, null);

		// Remove SigningScenario with Value 12 completely
		_ = (codeIntegrityPolicy.UMCI_SigningScenarioNode?.ParentNode?.RemoveChild(codeIntegrityPolicy.UMCI_SigningScenarioNode));

		// Save the modified XML document back to the file
		codeIntegrityPolicy.XmlDocument.Save(filePath);
	}
}
