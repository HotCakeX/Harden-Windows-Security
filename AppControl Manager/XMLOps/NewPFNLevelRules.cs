using System;
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
	/// <param name="packageFamilyNames"></param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void CreateAllow(string xmlFilePath, List<PFNRuleCreator> PFNData)
	{

		if (PFNData.Count is 0)
		{
			Logger.Write($"NewPFNLevelRules: no PackageFamilyNames detected to create rules for.");
			return;
		}


		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);


		// This method isn't suitable for strict Kernel-Mode policy
		if (codeIntegrityPolicy.UMCI_ProductSignersNode is null)
		{
			throw new InvalidOperationException("NewPFNLevelRules.Create method isn't suitable for strict Kernel-Mode policy");
		}


		// Find the FileRules node
		XmlNode fileRulesNode = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:FileRules", codeIntegrityPolicy.NamespaceManager) ?? throw new InvalidOperationException("file rules node could not be found.");

		// Check if FileRulesRef node exists for User-Mode, if not, create it
		XmlNode? UMCI_FileRulesRefNode = codeIntegrityPolicy.UMCI_ProductSignersNode.SelectSingleNode("ns:FileRulesRef", codeIntegrityPolicy.NamespaceManager);

		if (UMCI_FileRulesRefNode is null)
		{
			XmlElement UMCI_FileRulesRefNew = codeIntegrityPolicy.XmlDocument.CreateElement("FileRulesRef", codeIntegrityPolicy.NameSpaceURI);
			_ = codeIntegrityPolicy.UMCI_ProductSignersNode.AppendChild(UMCI_FileRulesRefNew);
			UMCI_FileRulesRefNode = UMCI_FileRulesRefNew;
		}


		foreach (PFNRuleCreator PFN in PFNData)
		{
			string guid = SiPolicyIntel.GUIDGenerator.GenerateUniqueGUIDToUpper();

			string ID = $"ID_ALLOW_A_{guid}";

			// Create new PackageFamilyName rule
			XmlElement newPFNRule = codeIntegrityPolicy.XmlDocument.CreateElement("Allow", codeIntegrityPolicy.NameSpaceURI);

			// Fill it with the required attributes
			newPFNRule.SetAttribute("ID", ID);
			newPFNRule.SetAttribute("FriendlyName", $"Allowing packaged app by its Family Name: {PFN.PackageFamilyName}");
			newPFNRule.SetAttribute("MinimumFileVersion", PFN.MinimumFileVersion);
			newPFNRule.SetAttribute("PackageFamilyName", PFN.PackageFamilyName);

			// Add the new element which is a node to the FileRules node
			_ = fileRulesNode.AppendChild(newPFNRule);

			// Create FileRuleRef for the PFN inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
			XmlElement newUMCIFileRuleRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", codeIntegrityPolicy.NameSpaceURI);
			newUMCIFileRuleRefNode.SetAttribute("RuleID", ID);
			_ = UMCI_FileRulesRefNode.AppendChild(newUMCIFileRuleRefNode);
		}

		codeIntegrityPolicy.XmlDocument.Save(xmlFilePath);
	}



	/// <summary>
	/// Creates PFN rules and adds them to an App Control policy XML file
	/// </summary>
	/// <param name="xmlFilePath"></param>
	/// <param name="packageFamilyNames"></param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void CreateDeny(string xmlFilePath, List<PFNRuleCreator> PFNData)
	{

		if (PFNData.Count is 0)
		{
			Logger.Write($"NewPFNLevelRules: no PackageFamilyNames detected to create rules for.");
			return;
		}


		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);


		// This method isn't suitable for strict Kernel-Mode policy
		if (codeIntegrityPolicy.UMCI_ProductSignersNode is null)
		{
			throw new InvalidOperationException("NewPFNLevelRules.Create method isn't suitable for strict Kernel-Mode policy");
		}


		// Find the FileRules node
		XmlNode fileRulesNode = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:FileRules", codeIntegrityPolicy.NamespaceManager) ?? throw new InvalidOperationException("file rules node could not be found.");

		// Check if FileRulesRef node exists for User-Mode, if not, create it
		XmlNode? UMCI_FileRulesRefNode = codeIntegrityPolicy.UMCI_ProductSignersNode.SelectSingleNode("ns:FileRulesRef", codeIntegrityPolicy.NamespaceManager);

		if (UMCI_FileRulesRefNode is null)
		{
			XmlElement UMCI_FileRulesRefNew = codeIntegrityPolicy.XmlDocument.CreateElement("FileRulesRef", codeIntegrityPolicy.NameSpaceURI);
			_ = codeIntegrityPolicy.UMCI_ProductSignersNode.AppendChild(UMCI_FileRulesRefNew);
			UMCI_FileRulesRefNode = UMCI_FileRulesRefNew;
		}


		foreach (PFNRuleCreator PFN in PFNData)
		{
			string guid = SiPolicyIntel.GUIDGenerator.GenerateUniqueGUIDToUpper();

			string ID = $"ID_DENY_A_{guid}";

			// Create new PackageFamilyName rule
			XmlElement newPFNRule = codeIntegrityPolicy.XmlDocument.CreateElement("Deny", codeIntegrityPolicy.NameSpaceURI);

			// Fill it with the required attributes
			newPFNRule.SetAttribute("ID", ID);
			newPFNRule.SetAttribute("FriendlyName", $"Denying packaged app by its Family Name: {PFN.PackageFamilyName}");
			newPFNRule.SetAttribute("MinimumFileVersion", PFN.MinimumFileVersion);
			newPFNRule.SetAttribute("PackageFamilyName", PFN.PackageFamilyName);

			// Add the new element which is a node to the FileRules node
			_ = fileRulesNode.AppendChild(newPFNRule);

			// Create FileRuleRef for the PFN inside the <FileRulesRef> -> <ProductSigners> -> <SigningScenario Value="12">
			XmlElement newUMCIFileRuleRefNode = codeIntegrityPolicy.XmlDocument.CreateElement("FileRuleRef", codeIntegrityPolicy.NameSpaceURI);
			newUMCIFileRuleRefNode.SetAttribute("RuleID", ID);
			_ = UMCI_FileRulesRefNode.AppendChild(newUMCIFileRuleRefNode);
		}

		codeIntegrityPolicy.XmlDocument.Save(xmlFilePath);
	}

}
