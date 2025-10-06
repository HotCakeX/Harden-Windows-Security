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

internal static class NewHashLevelRules
{
	/// <summary>
	/// Creates new Allow Hash level rules in an XML file
	/// For each hash data, it creates 2 Hash rules, one for Authenticode SHA2-256 and one for SHA1 hash
	/// It also adds the FileRulesRef for each hash to the ProductSigners node of the correct signing scenario(Kernel/User mode)
	/// </summary>
	/// <param name="xmlFilePath"></param>
	/// <param name="hashes"> The Hashes to be used for creating the rules, they are the output of the BuildSignerAndHashObjects Method </param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void CreateAllow(string xmlFilePath, List<HashCreator> hashes)
	{

		if (hashes.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoHashesDetectedAllowMessage"));
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath);

		Logger.Write(string.Format(GlobalVars.GetStr("HashRulesToAddMessage"), hashes.Count, xmlFilePath));

		// Loop through each hash and create a new rule for it
		foreach (HashCreator hash in hashes)
		{
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();

			// Create a unique ID for the rule
			string HashSHA256RuleID = $"ID_ALLOW_A_{guid}";
			string HashSHA1RuleID = $"ID_ALLOW_B_{guid}";

			// Create new Allow Hash rule for Authenticode SHA256
			XmlElement newAuth256HashNode = codeIntegrityPolicy.XmlDocument.CreateElement("Allow", GlobalVars.SiPolicyNamespace);
			newAuth256HashNode.SetAttribute("ID", HashSHA256RuleID);
			newAuth256HashNode.SetAttribute("FriendlyName", string.Format(GlobalVars.GetStr("Sha256HashFriendlyName"), hash.FileName));
			newAuth256HashNode.SetAttribute("Hash", hash.AuthenticodeSHA256);
			// Add the new node to the FileRules node
			_ = codeIntegrityPolicy.FileRulesNode.AppendChild(newAuth256HashNode);

			// Create new Allow Hash rule for Authenticode SHA1
			XmlElement newAuth1HashNode = codeIntegrityPolicy.XmlDocument.CreateElement("Allow", GlobalVars.SiPolicyNamespace);
			newAuth1HashNode.SetAttribute("ID", HashSHA1RuleID);
			newAuth1HashNode.SetAttribute("FriendlyName", string.Format(GlobalVars.GetStr("Sha1HashFriendlyName"), hash.FileName));
			newAuth1HashNode.SetAttribute("Hash", hash.AuthenticodeSHA1);
			// Add the new node to the FileRules node
			_ = codeIntegrityPolicy.FileRulesNode.AppendChild(newAuth1HashNode);

			// For User-Mode files
			if (hash.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
			{
				// Create FileRuleRef for Authenticode SHA256 Hash inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
				XmlElement NewUMCIFileRuleRefNodeFor256 = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", GlobalVars.SiPolicyNamespace);
				NewUMCIFileRuleRefNodeFor256.SetAttribute("RuleID", HashSHA256RuleID);
				_ = codeIntegrityPolicy.UMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewUMCIFileRuleRefNodeFor256);

				// Create FileRuleRef for Authenticode SHA1 Hash inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
				XmlElement NewUMCIFileRuleRefNodeFor1 = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", GlobalVars.SiPolicyNamespace);
				NewUMCIFileRuleRefNodeFor1.SetAttribute("RuleID", HashSHA1RuleID);
				_ = codeIntegrityPolicy.UMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewUMCIFileRuleRefNodeFor1);
			}

			// For Kernel-Mode files
			else if (hash.SiSigningScenario is SiPolicyIntel.SSType.KernelMode)
			{

				// Display a warning if a hash rule for a kernel-mode file is being created and the file is not an MSI
				// Since MDE does not record the Signing information events (Id 8038) for MSI files so we must create Hash based rules for them
				if (!hash.FilePath.EndsWith(".msi", StringComparison.OrdinalIgnoreCase))
				{
					Logger.Write(string.Format(GlobalVars.GetStr("KernelModeHashRuleWarningMessage"), hash.FilePath));
				}

				// Create FileRuleRef for Authenticode SHA256 Hash inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="131">
				XmlElement NewKMCIFileRuleRefNodeFor256 = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", GlobalVars.SiPolicyNamespace);
				NewKMCIFileRuleRefNodeFor256.SetAttribute("RuleID", HashSHA256RuleID);
				_ = codeIntegrityPolicy.KMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewKMCIFileRuleRefNodeFor256);

				// Create FileRuleRef for Authenticode SHA1 Hash inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="131">
				XmlElement NewKMCIFileRuleRefNodeFor1 = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", GlobalVars.SiPolicyNamespace);
				NewKMCIFileRuleRefNodeFor1.SetAttribute("RuleID", HashSHA1RuleID);
				_ = codeIntegrityPolicy.KMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewKMCIFileRuleRefNodeFor1);
			}
		}

		CodeIntegrityPolicy.Save(codeIntegrityPolicy.XmlDocument, xmlFilePath);
	}


	/// <summary>
	/// Creates new Deny Hash level rules in an XML file
	/// For each hash data, it creates 2 Hash rules, one for Authenticode SHA2-256 and one for SHA1 hash
	/// It also adds the FileRulesRef for each hash to the ProductSigners node of the correct signing scenario(Kernel/User mode)
	/// </summary>
	/// <param name="xmlFilePath"></param>
	/// <param name="hashes"> The Hashes to be used for creating the rules, they are the output of the BuildSignerAndHashObjects Method </param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void CreateDeny(string xmlFilePath, List<HashCreator> hashes)
	{

		if (hashes.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoHashesDetectedDenyMessage"));
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath);

		Logger.Write(string.Format(GlobalVars.GetStr("HashRulesToAddMessage"), hashes.Count, xmlFilePath));

		// Loop through each hash and create a new rule for it
		foreach (HashCreator hash in hashes)
		{
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();

			// Create a unique ID for the rule
			string HashSHA256RuleID = $"ID_DENY_A_{guid}";
			string HashSHA1RuleID = $"ID_DENY_B_{guid}";

			// Create new Deny Hash rule for Authenticode SHA256
			XmlElement newAuth256HashNode = codeIntegrityPolicy.XmlDocument.CreateElement("Deny", GlobalVars.SiPolicyNamespace);
			newAuth256HashNode.SetAttribute("ID", HashSHA256RuleID);
			newAuth256HashNode.SetAttribute("FriendlyName", string.Format(GlobalVars.GetStr("Sha256HashFriendlyName"), hash.FileName));
			newAuth256HashNode.SetAttribute("Hash", hash.AuthenticodeSHA256);
			// Add the new node to the FileRules node
			_ = codeIntegrityPolicy.FileRulesNode.AppendChild(newAuth256HashNode);

			// Create new Deny Hash rule for Authenticode SHA1
			XmlElement newAuth1HashNode = codeIntegrityPolicy.XmlDocument.CreateElement("Deny", GlobalVars.SiPolicyNamespace);
			newAuth1HashNode.SetAttribute("ID", HashSHA1RuleID);
			newAuth1HashNode.SetAttribute("FriendlyName", string.Format(GlobalVars.GetStr("Sha1HashFriendlyName"), hash.FileName));
			newAuth1HashNode.SetAttribute("Hash", hash.AuthenticodeSHA1);
			// Add the new node to the FileRules node
			_ = codeIntegrityPolicy.FileRulesNode.AppendChild(newAuth1HashNode);

			// For User-Mode files
			if (hash.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
			{
				// Create FileRuleRef for Authenticode SHA256 Hash inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
				XmlElement NewUMCIFileRuleRefNodeFor256 = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", GlobalVars.SiPolicyNamespace);
				NewUMCIFileRuleRefNodeFor256.SetAttribute("RuleID", HashSHA256RuleID);
				_ = codeIntegrityPolicy.UMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewUMCIFileRuleRefNodeFor256);

				// Create FileRuleRef for Authenticode SHA1 Hash inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
				XmlElement NewUMCIFileRuleRefNodeFor1 = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", GlobalVars.SiPolicyNamespace);
				NewUMCIFileRuleRefNodeFor1.SetAttribute("RuleID", HashSHA1RuleID);
				_ = codeIntegrityPolicy.UMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewUMCIFileRuleRefNodeFor1);
			}

			// For Kernel-Mode files
			else if (hash.SiSigningScenario is SiPolicyIntel.SSType.KernelMode)
			{

				// Display a warning if a hash rule for a kernel-mode file is being created and the file is not an MSI
				// Since MDE does not record the Signing information events (Id 8038) for MSI files so we must create Hash based rules for them
				if (!hash.FilePath.EndsWith(".msi", StringComparison.OrdinalIgnoreCase))
				{
					Logger.Write(string.Format(GlobalVars.GetStr("KernelModeHashRuleWarningMessage"), hash.FilePath));
				}

				// Create FileRuleRef for Authenticode SHA256 Hash inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="131">
				XmlElement NewKMCIFileRuleRefNodeFor256 = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", GlobalVars.SiPolicyNamespace);
				NewKMCIFileRuleRefNodeFor256.SetAttribute("RuleID", HashSHA256RuleID);
				_ = codeIntegrityPolicy.KMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewKMCIFileRuleRefNodeFor256);

				// Create FileRuleRef for Authenticode SHA1 Hash inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="131">
				XmlElement NewKMCIFileRuleRefNodeFor1 = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", GlobalVars.SiPolicyNamespace);
				NewKMCIFileRuleRefNodeFor1.SetAttribute("RuleID", HashSHA1RuleID);
				_ = codeIntegrityPolicy.KMCI_ProductSigners_FileRulesRef_Node.AppendChild(NewKMCIFileRuleRefNodeFor1);
			}
		}

		CodeIntegrityPolicy.Save(codeIntegrityPolicy.XmlDocument, xmlFilePath);
	}

}
