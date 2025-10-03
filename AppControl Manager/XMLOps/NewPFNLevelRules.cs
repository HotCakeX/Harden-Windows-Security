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

internal static class NewPFNLevelRules
{
	/// <summary>
	/// Creates PFN rules and adds them to an App Control policy XML file
	/// </summary>
	/// <param name="xmlFilePath"></param>
	/// <param name="PFNData"></param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void CreateAllow(string xmlFilePath, List<PFNRuleCreator> PFNData)
	{

		if (PFNData.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoPackageFamilyNamesDetectedAllowMessage"));
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath);

		foreach (PFNRuleCreator PFN in PFNData)
		{
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();

			string ID = $"ID_ALLOW_A_{guid}";

			// Create new PackageFamilyName rule
			XmlElement newPFNRule = codeIntegrityPolicy.XmlDocument.CreateElement("Allow", GlobalVars.SiPolicyNamespace);

			// Fill it with the required attributes
			newPFNRule.SetAttribute("ID", ID);
			newPFNRule.SetAttribute("FriendlyName", GlobalVars.GetStr("AllowingPackagedAppFriendlyName"));
			newPFNRule.SetAttribute("MinimumFileVersion", PFN.MinimumFileVersion);
			newPFNRule.SetAttribute("PackageFamilyName", PFN.PackageFamilyName);

			// Add the new element which is a node to the FileRules node
			_ = codeIntegrityPolicy.FileRulesNode.AppendChild(newPFNRule);

			// Create FileRuleRef for the PFN inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
			XmlElement newUMCIFileRuleRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", GlobalVars.SiPolicyNamespace);
			newUMCIFileRuleRefNode.SetAttribute("RuleID", ID);
			_ = codeIntegrityPolicy.UMCI_ProductSigners_FileRulesRef_Node.AppendChild(newUMCIFileRuleRefNode);
		}

		CodeIntegrityPolicy.Save(codeIntegrityPolicy.XmlDocument, xmlFilePath);
	}


	/// <summary>
	/// Creates PFN rules and adds them to an App Control policy XML file
	/// </summary>
	/// <param name="xmlFilePath"></param>
	/// <param name="PFNData"></param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void CreateDeny(string xmlFilePath, List<PFNRuleCreator> PFNData)
	{

		if (PFNData.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoPackageFamilyNamesDetectedDenyMessage"));
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath);

		foreach (PFNRuleCreator PFN in PFNData)
		{
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();

			string ID = $"ID_DENY_A_{guid}";

			// Create new PackageFamilyName rule
			XmlElement newPFNRule = codeIntegrityPolicy.XmlDocument.CreateElement("Deny", GlobalVars.SiPolicyNamespace);

			// Fill it with the required attributes
			newPFNRule.SetAttribute("ID", ID);
			newPFNRule.SetAttribute("FriendlyName", GlobalVars.GetStr("DenyingPackagedAppFriendlyName"));
			newPFNRule.SetAttribute("MinimumFileVersion", PFN.MinimumFileVersion);
			newPFNRule.SetAttribute("PackageFamilyName", PFN.PackageFamilyName);

			// Add the new element which is a node to the FileRules node
			_ = codeIntegrityPolicy.FileRulesNode.AppendChild(newPFNRule);

			// Create FileRuleRef for the PFN inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
			XmlElement newUMCIFileRuleRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", GlobalVars.SiPolicyNamespace);
			newUMCIFileRuleRefNode.SetAttribute("RuleID", ID);
			_ = codeIntegrityPolicy.UMCI_ProductSigners_FileRulesRef_Node.AppendChild(newUMCIFileRuleRefNode);
		}

		CodeIntegrityPolicy.Save(codeIntegrityPolicy.XmlDocument, xmlFilePath);
	}

}
