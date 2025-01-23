using System.Collections.Generic;
using System.Xml;
using AppControlManager.Others;

namespace AppControlManager.XMLOps;

internal static class ClearCiPolicySemantic
{
	/// <summary>
	/// Clears the CI Policy XML file from all nodes except the base nodes
	/// According to the CI Schema
	/// </summary>
	/// <param name="xmlFilePath"></param>
	internal static void Clear(string xmlFilePath)
	{
		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);

		#region Defining the Nodes to keep and clear, according to the CI Schema

		List<XmlNode> baseNodes = [];
		baseNodes.Add(codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:EKUs", codeIntegrityPolicy.NamespaceManager)!);
		baseNodes.Add(codeIntegrityPolicy.FileRulesNode);
		baseNodes.Add(codeIntegrityPolicy.SignersNode);

		baseNodes.Add(codeIntegrityPolicy.UMCI_ProductSignersNode);
		baseNodes.Add(codeIntegrityPolicy.KMCI_ProductSignersNode);

		baseNodes.Add(codeIntegrityPolicy.UMCI_ProductSigners_FileRulesRef_Node);
		baseNodes.Add(codeIntegrityPolicy.KMCI_ProductSigners_FileRulesRef_Node);

		XmlNode? updatePolicySigners = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:UpdatePolicySigners", codeIntegrityPolicy.NamespaceManager);

		if (updatePolicySigners is not null)
		{
			baseNodes.Add(updatePolicySigners);
		}
		baseNodes.Add(codeIntegrityPolicy.CiSignersNode);

		#endregion

		// Remove <Macros> node completely since it can't be left empty and it's not a base node
		XmlNode? macros = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:Macros", codeIntegrityPolicy.NamespaceManager);
		if (macros is not null)
		{
			_ = codeIntegrityPolicy.SiPolicyNode.RemoveChild(macros);
		}

		// Loop over each base node
		foreach (XmlNode node in baseNodes)
		{
			// Remove all child nodes
			while (node.HasChildNodes)
			{
				_ = node.RemoveChild(node.FirstChild!);
			}

			// Set the node/element to be serialized in the short tag format
			// https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmlelement.isempty
			if (node is XmlElement element)
			{
				element.IsEmpty = true;
			}
		}

		CodeIntegrityPolicy.Save(codeIntegrityPolicy.XmlDocument, xmlFilePath);
	}
}
