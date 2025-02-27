using System;
using System.Collections.Generic;
using System.Xml;
using AppControlManager.Others;

namespace AppControlManager.XMLOps;

internal static class NewFilePathRules
{

	/// <summary>
	/// Create a new Allow FilePath rule (including Wildcards) in the XML file
	/// Rules will only be created for User-Mode files as Kernel-mode drivers do not support FilePath rules
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
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath);

		Logger.Write($"NewFilePathRules: There are {data.Count} FilePath rules to be added to the XML file '{xmlFilePath}'");

		// Loop through each item and create a new FilePath rule for it
		foreach (FilePathCreator item in data)
		{
			string guid = SiPolicyIntel.GUIDGenerator.GenerateUniqueGUIDToUpper();

			// Create a unique ID for the rule
			string allowRuleID = $"ID_ALLOW_A_{guid}";

			// Create a new Allow FilePath rule
			XmlElement newFileRule = codeIntegrityPolicy.XmlDocument.CreateElement("Allow", GlobalVars.SiPolicyNamespace);
			newFileRule.SetAttribute("ID", allowRuleID);
			newFileRule.SetAttribute("FriendlyName", "File Path Rule Type");
			newFileRule.SetAttribute("MinimumFileVersion", item.MinimumFileVersion);
			newFileRule.SetAttribute("FilePath", item.FilePath);
			// Add the new node to the FileRules node
			_ = codeIntegrityPolicy.FileRulesNode.AppendChild(newFileRule);

			// For User-Mode files only as FilePath rules are not applicable to Kernel-Mode drivers
			if (item.SiSigningScenario is 1)
			{
				// Create FileRuleRef inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
				XmlElement NewUMCIFileRuleRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", GlobalVars.SiPolicyNamespace);
				NewUMCIFileRuleRefNode.SetAttribute("RuleID", allowRuleID);
				_ = codeIntegrityPolicy.UMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewUMCIFileRuleRefNode);
			}
			else
			{
				Logger.Write($"The following file is Kernel-Mode driver that doesn't support FilePath rules: {item.FilePath}");
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
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath);

		Logger.Write($"NewFilePathRules: There are {data.Count} FilePath rules to be added to the XML file '{xmlFilePath}'");

		// Loop through each item and create a new FilePath rule for it
		foreach (FilePathCreator item in data)
		{
			string guid = SiPolicyIntel.GUIDGenerator.GenerateUniqueGUIDToUpper();

			// Create a unique ID for the rule
			string denyRuleID = $"ID_DENY_A_{guid}";

			// Create a new Deny FilePath rule
			XmlElement newFileRule = codeIntegrityPolicy.XmlDocument.CreateElement("Deny", GlobalVars.SiPolicyNamespace);
			newFileRule.SetAttribute("ID", denyRuleID);
			newFileRule.SetAttribute("FriendlyName", "File Path Rule Type");
			newFileRule.SetAttribute("FilePath", item.FilePath);
			// Add the new node to the FileRules node
			_ = codeIntegrityPolicy.FileRulesNode.AppendChild(newFileRule);

			// For User-Mode files
			if (item.SiSigningScenario is 1)
			{
				// Create FileRuleRef inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
				XmlElement NewUMCIFileRuleRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", GlobalVars.SiPolicyNamespace);
				NewUMCIFileRuleRefNode.SetAttribute("RuleID", denyRuleID);
				_ = codeIntegrityPolicy.UMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewUMCIFileRuleRefNode);
			}
			else
			{
				Logger.Write($"The following file is Kernel-Mode driver that doesn't support FilePath rules: {item.FilePath}");
			}
		}

		CodeIntegrityPolicy.Save(codeIntegrityPolicy.XmlDocument, xmlFilePath);
	}

}
