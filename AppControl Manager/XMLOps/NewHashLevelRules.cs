using System;
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
			Logger.Write($"NewHashLevelRules: no Hashes detected to create allow rules for.");
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);

		Logger.Write($"NewHashLevelRules: There are {hashes.Count} Hash rules to be added to the XML file '{xmlFilePath}'");

		// Loop through each hash and create a new rule for it
		foreach (HashCreator hash in hashes)
		{
			string guid = SiPolicyIntel.GUIDGenerator.GenerateUniqueGUIDToUpper();

			// Create a unique ID for the rule
			string HashSHA256RuleID = $"ID_ALLOW_A_{guid}";
			string HashSHA1RuleID = $"ID_ALLOW_B_{guid}";

			// Create new Allow Hash rule for Authenticode SHA256
			XmlElement newAuth256HashNode = codeIntegrityPolicy.XmlDocument.CreateElement("Allow", GlobalVars.SiPolicyNamespace);
			newAuth256HashNode.SetAttribute("ID", HashSHA256RuleID);
			newAuth256HashNode.SetAttribute("FriendlyName", $"{hash.FileName} Hash Sha256");
			newAuth256HashNode.SetAttribute("Hash", hash.AuthenticodeSHA256);
			// Add the new node to the FileRules node
			_ = codeIntegrityPolicy.FileRulesNode.AppendChild(newAuth256HashNode);

			// Create new Allow Hash rule for Authenticode SHA1
			XmlElement newAuth1HashNode = codeIntegrityPolicy.XmlDocument.CreateElement("Allow", GlobalVars.SiPolicyNamespace);
			newAuth1HashNode.SetAttribute("ID", HashSHA1RuleID);
			newAuth1HashNode.SetAttribute("FriendlyName", $"{hash.FileName} Hash Sha1");
			newAuth1HashNode.SetAttribute("Hash", hash.AuthenticodeSHA1);
			// Add the new node to the FileRules node
			_ = codeIntegrityPolicy.FileRulesNode.AppendChild(newAuth1HashNode);

			// For User-Mode files
			if (hash.SiSigningScenario is 1)
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
			else if (hash.SiSigningScenario is 0)
			{

				// Display a warning if a hash rule for a kernel-mode file is being created and the file is not an MSI
				// Since MDE does not record the Signing information events (Id 8038) for MSI files so we must create Hash based rules for them
				if (!hash.FileName.EndsWith(".msi", StringComparison.OrdinalIgnoreCase))
				{
					Logger.Write($"Creating Hash rule for Kernel-Mode file: {hash.FileName}. Kernel-Mode file should be signed!");
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
			Logger.Write($"NewHashLevelRules: no Hashes detected to create deny rules for.");
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);

		Logger.Write($"NewHashLevelRules: There are {hashes.Count} Hash rules to be added to the XML file '{xmlFilePath}'");

		// Loop through each hash and create a new rule for it
		foreach (HashCreator hash in hashes)
		{
			string guid = SiPolicyIntel.GUIDGenerator.GenerateUniqueGUIDToUpper();

			// Create a unique ID for the rule
			string HashSHA256RuleID = $"ID_DENY_A_{guid}";
			string HashSHA1RuleID = $"ID_DENY_B_{guid}";

			// Create new Deny Hash rule for Authenticode SHA256
			XmlElement newAuth256HashNode = codeIntegrityPolicy.XmlDocument.CreateElement("Deny", GlobalVars.SiPolicyNamespace);
			newAuth256HashNode.SetAttribute("ID", HashSHA256RuleID);
			newAuth256HashNode.SetAttribute("FriendlyName", $"{hash.FileName} Hash Sha256");
			newAuth256HashNode.SetAttribute("Hash", hash.AuthenticodeSHA256);
			// Add the new node to the FileRules node
			_ = codeIntegrityPolicy.FileRulesNode.AppendChild(newAuth256HashNode);

			// Create new Deny Hash rule for Authenticode SHA1
			XmlElement newAuth1HashNode = codeIntegrityPolicy.XmlDocument.CreateElement("Deny", GlobalVars.SiPolicyNamespace);
			newAuth1HashNode.SetAttribute("ID", HashSHA1RuleID);
			newAuth1HashNode.SetAttribute("FriendlyName", $"{hash.FileName} Hash Sha1");
			newAuth1HashNode.SetAttribute("Hash", hash.AuthenticodeSHA1);
			// Add the new node to the FileRules node
			_ = codeIntegrityPolicy.FileRulesNode.AppendChild(newAuth1HashNode);

			// For User-Mode files
			if (hash.SiSigningScenario == 1)
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
			else if (hash.SiSigningScenario == 0)
			{

				// Display a warning if a hash rule for a kernel-mode file is being created and the file is not an MSI
				// Since MDE does not record the Signing information events (Id 8038) for MSI files so we must create Hash based rules for them
				if (!hash.FileName.EndsWith(".msi", StringComparison.OrdinalIgnoreCase))
				{
					Logger.Write($"Creating Hash rule for Kernel-Mode file: {hash.FileName}. Kernel-Mode file should be signed!");
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
