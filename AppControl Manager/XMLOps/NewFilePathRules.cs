// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

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
			Logger.Write(GlobalVars.GetStr("NoFilePathRulesDetectedAllowMessage"));
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath);

		Logger.Write(string.Format(GlobalVars.GetStr("FilePathRulesToAddMessage"), data.Count, xmlFilePath));

		// Loop through each item and create a new FilePath rule for it
		foreach (FilePathCreator item in data)
		{
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();

			// Create a unique ID for the rule
			string allowRuleID = $"ID_ALLOW_A_{guid}";

			// Create a new Allow FilePath rule
			XmlElement newFileRule = codeIntegrityPolicy.XmlDocument.CreateElement("Allow", GlobalVars.SiPolicyNamespace);
			newFileRule.SetAttribute("ID", allowRuleID);
			newFileRule.SetAttribute("FriendlyName", GlobalVars.GetStr("FilePathRuleTypeFriendlyName"));
			newFileRule.SetAttribute("MinimumFileVersion", item.MinimumFileVersion);
			newFileRule.SetAttribute("FilePath", item.FilePath);
			// Add the new node to the FileRules node
			_ = codeIntegrityPolicy.FileRulesNode.AppendChild(newFileRule);

			// For User-Mode files only as FilePath rules are not applicable to Kernel-Mode drivers
			if (item.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
			{
				// Create FileRuleRef inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
				XmlElement NewUMCIFileRuleRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", GlobalVars.SiPolicyNamespace);
				NewUMCIFileRuleRefNode.SetAttribute("RuleID", allowRuleID);
				_ = codeIntegrityPolicy.UMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewUMCIFileRuleRefNode);
			}
			else
			{
				Logger.Write(string.Format(GlobalVars.GetStr("KernelModeFilePathRuleWarningMessage"), item.FilePath));
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
			Logger.Write(GlobalVars.GetStr("NoFilePathRulesDetectedDenyMessage"));
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath);

		Logger.Write(string.Format(GlobalVars.GetStr("FilePathRulesToAddMessage"), data.Count, xmlFilePath));

		// Loop through each item and create a new FilePath rule for it
		foreach (FilePathCreator item in data)
		{
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();

			// Create a unique ID for the rule
			string denyRuleID = $"ID_DENY_A_{guid}";

			// Create a new Deny FilePath rule
			XmlElement newFileRule = codeIntegrityPolicy.XmlDocument.CreateElement("Deny", GlobalVars.SiPolicyNamespace);
			newFileRule.SetAttribute("ID", denyRuleID);
			newFileRule.SetAttribute("FriendlyName", GlobalVars.GetStr("FilePathRuleTypeFriendlyName"));
			newFileRule.SetAttribute("FilePath", item.FilePath);
			// Add the new node to the FileRules node
			_ = codeIntegrityPolicy.FileRulesNode.AppendChild(newFileRule);

			// For User-Mode files
			if (item.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
			{
				// Create FileRuleRef inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
				XmlElement NewUMCIFileRuleRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", GlobalVars.SiPolicyNamespace);
				NewUMCIFileRuleRefNode.SetAttribute("RuleID", denyRuleID);
				_ = codeIntegrityPolicy.UMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewUMCIFileRuleRefNode);
			}
			else
			{
				Logger.Write(string.Format(GlobalVars.GetStr("KernelModeFilePathRuleWarningMessage"), item.FilePath));
			}
		}

		CodeIntegrityPolicy.Save(codeIntegrityPolicy.XmlDocument, xmlFilePath);
	}

}
