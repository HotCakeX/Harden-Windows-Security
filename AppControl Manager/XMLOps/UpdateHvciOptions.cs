using System;
using System.Xml;
using AppControlManager.Main;
using AppControlManager.Others;

namespace AppControlManager.XMLOps;

internal static class UpdateHvciOptions
{
	/// <summary>
	/// Sets the HVCI option to Strict or (2) in a policy XML file
	/// It checks if <HvciOptions> node exists, and if its value is anything other than 2, it sets it to 2.
	/// If <HvciOptions> node does not exists, it creates and inserts it after the <CiSigners> node.
	/// </summary>
	/// <param name="filePath"></param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void Update(string filePath)
	{
		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(filePath, null);

		// Select the HvciOptions node
		XmlNode? hvciOptionsNode = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:HvciOptions", codeIntegrityPolicy.NamespaceManager);

		// If HvciOptions node exists
		if (hvciOptionsNode is not null)
		{
			// Ensure the value is "2"
			if (hvciOptionsNode.InnerText != "2")
			{
				hvciOptionsNode.InnerText = "2";
			}
		}
		else
		{
			// Create the HvciOptions node if it doesn't exist
			hvciOptionsNode = codeIntegrityPolicy.XmlDocument.CreateElement("HvciOptions", codeIntegrityPolicy.NameSpaceURI);
			hvciOptionsNode.InnerText = "2";

			// Insert it after CiSigners node
			_ = codeIntegrityPolicy.SiPolicyNode.InsertAfter(hvciOptionsNode, codeIntegrityPolicy.CiSignersNode);

		}

		// Save the modified XML document
		codeIntegrityPolicy.XmlDocument.Save(filePath);

		// Validate the XML file at the end
		if (!CiPolicyTest.TestCiPolicy(filePath))
		{
			throw new InvalidOperationException("UpdateHvciOptions: The XML file created at the end is not compliant with the CI policy schema");
		}

		Logger.Write($"Successfully set the HVCI in the policy file '{filePath}' to Strict.");
	}
}
