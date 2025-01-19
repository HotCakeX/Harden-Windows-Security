using System;
using System.Collections.Generic;
using System.Xml;
using AppControlManager.Others;

namespace AppControlManager.XMLOps;

internal class NewFilePathRules
{

	/// <summary>
	/// Create a new Allow FilePath rule (including Wildcards) in the XML file
	/// </summary>
	/// <param name="xmlFilePath"></param>
	/// <param name="data"></param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void CreateAllow(string xmlFilePath, List<FilePathCreator> data)
	{

		if (data.Count is 0)
		{
			Logger.Write($"NewFilePathRules: no FilePath rules detected to create rules for.");
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);

		Logger.Write($"NewHashLevelRules: There are {data.Count} Hash rules to be added to the XML file '{xmlFilePath}'");

		#region

		// Find FileRulesRef node in each ProductSigners node
		XmlNode? UMCI_ProductSigners_FileRulesRef_Node = codeIntegrityPolicy.UMCI_ProductSignersNode?.SelectSingleNode("ns:FileRulesRef", codeIntegrityPolicy.NamespaceManager);
		XmlNode? KMCI_ProductSigners_FileRulesRef_Node = codeIntegrityPolicy.KMCI_ProductSignersNode?.SelectSingleNode("ns:FileRulesRef", codeIntegrityPolicy.NamespaceManager);

		// Check if FileRulesRef node exists, if not, create it
		if (UMCI_ProductSigners_FileRulesRef_Node is null)
		{
			XmlElement UMCI_FileRulesRefNew = codeIntegrityPolicy.XmlDocument.CreateElement("FileRulesRef", codeIntegrityPolicy.NameSpaceURI);
			_ = codeIntegrityPolicy.UMCI_ProductSignersNode?.AppendChild(UMCI_FileRulesRefNew);

			UMCI_ProductSigners_FileRulesRef_Node = codeIntegrityPolicy.UMCI_ProductSignersNode?.SelectSingleNode("ns:FileRulesRef", codeIntegrityPolicy.NamespaceManager);
		}

		if (UMCI_ProductSigners_FileRulesRef_Node is null)
		{
			throw new InvalidOperationException("UMCI Product Signers FileRulesRef node not found despite creating it");
		}

		// Check if FileRulesRef node exists, if not, create it
		if (KMCI_ProductSigners_FileRulesRef_Node is null)
		{
			XmlElement KMCI_FileRulesRefNew = codeIntegrityPolicy.XmlDocument.CreateElement("FileRulesRef", codeIntegrityPolicy.NameSpaceURI);
			_ = codeIntegrityPolicy.KMCI_ProductSignersNode?.AppendChild(KMCI_FileRulesRefNew);
			KMCI_ProductSigners_FileRulesRef_Node = codeIntegrityPolicy.KMCI_ProductSignersNode?.SelectSingleNode("ns:FileRulesRef", codeIntegrityPolicy.NamespaceManager);
		}

		if (KMCI_ProductSigners_FileRulesRef_Node is null)
		{
			throw new InvalidOperationException("KMCI Product Signers FileRulesRef node not found despite creating it");
		}

		#endregion

		// Find the FileRules node
		XmlNode fileRulesNode = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:FileRules", codeIntegrityPolicy.NamespaceManager)!;

		// Loop through each item and create a new FilePath rule for it
		foreach (FilePathCreator item in data)
		{
			string guid = SiPolicyIntel.GUIDGenerator.GenerateUniqueGUIDToUpper();

			// Create a unique ID for the rule
			string allowRuleID = $"ID_ALLOW_A_{guid}";

			// Create a new Allow FilePath rule
			XmlElement newFileRule = codeIntegrityPolicy.XmlDocument.CreateElement("Allow", codeIntegrityPolicy.NameSpaceURI);
			newFileRule.SetAttribute("ID", allowRuleID);
			newFileRule.SetAttribute("FriendlyName", $"{item.FilePath} FileRule");
			newFileRule.SetAttribute("MinimumFileVersion", item.MinimumFileVersion);
			newFileRule.SetAttribute("FilePath", item.FilePath);
			// Add the new node to the FileRules node
			_ = fileRulesNode.AppendChild(newFileRule);


			// For User-Mode files
			if (item.SiSigningScenario == 1)
			{
				// Create FileRuleRef inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
				XmlElement NewUMCIFileRuleRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", codeIntegrityPolicy.NameSpaceURI);
				NewUMCIFileRuleRefNode.SetAttribute("RuleID", allowRuleID);
				_ = UMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewUMCIFileRuleRefNode);
			}

			// For Kernel-Mode files
			else if (item.SiSigningScenario == 0)
			{
				// Create FileRuleRef inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="131">
				XmlElement NewKMCIFileRuleRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", codeIntegrityPolicy.NameSpaceURI);
				NewKMCIFileRuleRefNode.SetAttribute("RuleID", allowRuleID);
				_ = KMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewKMCIFileRuleRefNode);
			}
		}

		codeIntegrityPolicy.XmlDocument.Save(xmlFilePath);
	}



	/// <summary>
	/// Creates a new Deny FilePath rule (including Wildcards) in the XML file
	/// </summary>
	/// <param name="xmlFilePath"></param>
	/// <param name="data"></param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void CreateDeny(string xmlFilePath, List<FilePathCreator> data)
	{

		if (data.Count is 0)
		{
			Logger.Write($"NewFilePathRules: no FilePath rules detected to create rules for.");
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);

		Logger.Write($"NewHashLevelRules: There are {data.Count} Hash rules to be added to the XML file '{xmlFilePath}'");

		#region

		// Find FileRulesRef node in each ProductSigners node
		XmlNode? UMCI_ProductSigners_FileRulesRef_Node = codeIntegrityPolicy.UMCI_ProductSignersNode?.SelectSingleNode("ns:FileRulesRef", codeIntegrityPolicy.NamespaceManager);
		XmlNode? KMCI_ProductSigners_FileRulesRef_Node = codeIntegrityPolicy.KMCI_ProductSignersNode?.SelectSingleNode("ns:FileRulesRef", codeIntegrityPolicy.NamespaceManager);

		// Check if FileRulesRef node exists, if not, create it
		if (UMCI_ProductSigners_FileRulesRef_Node is null)
		{
			XmlElement UMCI_FileRulesRefNew = codeIntegrityPolicy.XmlDocument.CreateElement("FileRulesRef", codeIntegrityPolicy.NameSpaceURI);
			_ = codeIntegrityPolicy.UMCI_ProductSignersNode?.AppendChild(UMCI_FileRulesRefNew);

			UMCI_ProductSigners_FileRulesRef_Node = codeIntegrityPolicy.UMCI_ProductSignersNode?.SelectSingleNode("ns:FileRulesRef", codeIntegrityPolicy.NamespaceManager);
		}

		if (UMCI_ProductSigners_FileRulesRef_Node is null)
		{
			throw new InvalidOperationException("UMCI Product Signers FileRulesRef node not found despite creating it");
		}

		// Check if FileRulesRef node exists, if not, create it
		if (KMCI_ProductSigners_FileRulesRef_Node is null)
		{
			XmlElement KMCI_FileRulesRefNew = codeIntegrityPolicy.XmlDocument.CreateElement("FileRulesRef", codeIntegrityPolicy.NameSpaceURI);
			_ = codeIntegrityPolicy.KMCI_ProductSignersNode?.AppendChild(KMCI_FileRulesRefNew);
			KMCI_ProductSigners_FileRulesRef_Node = codeIntegrityPolicy.KMCI_ProductSignersNode?.SelectSingleNode("ns:FileRulesRef", codeIntegrityPolicy.NamespaceManager);
		}

		if (KMCI_ProductSigners_FileRulesRef_Node is null)
		{
			throw new InvalidOperationException("KMCI Product Signers FileRulesRef node not found despite creating it");
		}

		#endregion

		// Find the FileRules node
		XmlNode fileRulesNode = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:FileRules", codeIntegrityPolicy.NamespaceManager)!;

		// Loop through each item and create a new FilePath rule for it
		foreach (FilePathCreator item in data)
		{
			string guid = SiPolicyIntel.GUIDGenerator.GenerateUniqueGUIDToUpper();

			// Create a unique ID for the rule
			string denyRuleID = $"ID_DENY_A_{guid}";

			// Create a new Deny FilePath rule
			XmlElement newFileRule = codeIntegrityPolicy.XmlDocument.CreateElement("Deny", codeIntegrityPolicy.NameSpaceURI);
			newFileRule.SetAttribute("ID", denyRuleID);
			newFileRule.SetAttribute("FriendlyName", $"{item.FilePath} FileRule");
			newFileRule.SetAttribute("MinimumFileVersion", item.MinimumFileVersion);
			newFileRule.SetAttribute("FilePath", item.FilePath);
			// Add the new node to the FileRules node
			_ = fileRulesNode.AppendChild(newFileRule);


			// For User-Mode files
			if (item.SiSigningScenario == 1)
			{
				// Create FileRuleRef inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
				XmlElement NewUMCIFileRuleRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", codeIntegrityPolicy.NameSpaceURI);
				NewUMCIFileRuleRefNode.SetAttribute("RuleID", denyRuleID);
				_ = UMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewUMCIFileRuleRefNode);
			}

			// For Kernel-Mode files
			else if (item.SiSigningScenario == 0)
			{
				// Create FileRuleRef inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="131">
				XmlElement NewKMCIFileRuleRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", codeIntegrityPolicy.NameSpaceURI);
				NewKMCIFileRuleRefNode.SetAttribute("RuleID", denyRuleID);
				_ = KMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewKMCIFileRuleRefNode);
			}
		}

		codeIntegrityPolicy.XmlDocument.Save(xmlFilePath);
	}

}
