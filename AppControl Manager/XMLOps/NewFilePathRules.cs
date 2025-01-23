using System;
using System.Collections.Generic;
using System.Xml;
using AppControlManager.Others;

namespace AppControlManager.XMLOps;

internal static class NewFilePathRules
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
			Logger.Write($"NewFilePathRules: no FilePath rules detected to create allow rules for.");
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);

		Logger.Write($"NewFilePathRules: There are {data.Count} FilePath rules to be added to the XML file '{xmlFilePath}'");

		// Loop through each item and create a new FilePath rule for it
		foreach (FilePathCreator item in data)
		{
			string guid = SiPolicyIntel.GUIDGenerator.GenerateUniqueGUIDToUpper();

			// Create a unique ID for the rule
			string allowRuleID = $"ID_ALLOW_A_{guid}";

			// Create a new Allow FilePath rule
			XmlElement newFileRule = codeIntegrityPolicy.XmlDocument.CreateElement("Allow", codeIntegrityPolicy.NameSpaceURI);
			newFileRule.SetAttribute("ID", allowRuleID);
			newFileRule.SetAttribute("FriendlyName", "File Path Rule");
			newFileRule.SetAttribute("MinimumFileVersion", item.MinimumFileVersion);
			newFileRule.SetAttribute("FilePath", item.FilePath);
			// Add the new node to the FileRules node
			_ = codeIntegrityPolicy.FileRulesNode.AppendChild(newFileRule);


			// For User-Mode files
			if (item.SiSigningScenario is 1)
			{
				// Create FileRuleRef inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
				XmlElement NewUMCIFileRuleRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", codeIntegrityPolicy.NameSpaceURI);
				NewUMCIFileRuleRefNode.SetAttribute("RuleID", allowRuleID);
				_ = codeIntegrityPolicy.UMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewUMCIFileRuleRefNode);
			}

			// For Kernel-Mode files
			else if (item.SiSigningScenario is 0)
			{
				// Create FileRuleRef inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="131">
				XmlElement NewKMCIFileRuleRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", codeIntegrityPolicy.NameSpaceURI);
				NewKMCIFileRuleRefNode.SetAttribute("RuleID", allowRuleID);
				_ = codeIntegrityPolicy.KMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewKMCIFileRuleRefNode);
			}
		}

		CodeIntegrityPolicy.Save(codeIntegrityPolicy.XmlDocument, xmlFilePath);
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
			Logger.Write($"NewFilePathRules: no FilePath rules detected to create deny rules for.");
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);

		Logger.Write($"NewFilePathRules: There are {data.Count} FilePath rules to be added to the XML file '{xmlFilePath}'");

		// Loop through each item and create a new FilePath rule for it
		foreach (FilePathCreator item in data)
		{
			string guid = SiPolicyIntel.GUIDGenerator.GenerateUniqueGUIDToUpper();

			// Create a unique ID for the rule
			string denyRuleID = $"ID_DENY_A_{guid}";

			// Create a new Deny FilePath rule
			XmlElement newFileRule = codeIntegrityPolicy.XmlDocument.CreateElement("Deny", codeIntegrityPolicy.NameSpaceURI);
			newFileRule.SetAttribute("ID", denyRuleID);
			newFileRule.SetAttribute("FriendlyName", "File Path Rule");
			newFileRule.SetAttribute("FilePath", item.FilePath);
			// Add the new node to the FileRules node
			_ = codeIntegrityPolicy.FileRulesNode.AppendChild(newFileRule);


			// For User-Mode files
			if (item.SiSigningScenario is 1)
			{
				// Create FileRuleRef inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
				XmlElement NewUMCIFileRuleRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", codeIntegrityPolicy.NameSpaceURI);
				NewUMCIFileRuleRefNode.SetAttribute("RuleID", denyRuleID);
				_ = codeIntegrityPolicy.UMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewUMCIFileRuleRefNode);
			}

			// For Kernel-Mode files
			else if (item.SiSigningScenario is 0)
			{
				// Create FileRuleRef inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="131">
				XmlElement NewKMCIFileRuleRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", codeIntegrityPolicy.NameSpaceURI);
				NewKMCIFileRuleRefNode.SetAttribute("RuleID", denyRuleID);
				_ = codeIntegrityPolicy.KMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewKMCIFileRuleRefNode);
			}
		}

		CodeIntegrityPolicy.Save(codeIntegrityPolicy.XmlDocument, xmlFilePath);
	}

}
