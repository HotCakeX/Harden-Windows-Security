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

using System.Globalization;
using System.Xml;
using AppControlManager.XMLOps;

namespace AppControlManager.Others;

// This class represents a single Code Integrity XML policy.
// It operates as a 2nd custom XML serializer/deserializer used only by the methods that add rules to the policy.
// Its main purpose is to identify import nodes in the XML, expose them to the calling method and ensure they exist.
internal sealed class CodeIntegrityPolicy
{
	internal XmlDocument XmlDocument { get; }
	internal XmlNamespaceManager NamespaceManager { get; }
	internal XmlNode SiPolicyNode { get; }
	internal XmlNode FileRulesNode { get; }
	internal XmlNode SignersNode { get; }
	internal XmlNode CiSignersNode { get; }
	internal XmlNode EKUsNode { get; }

	internal XmlNode UMCI_SigningScenarioNode { get; }
	internal XmlNode KMCI_SigningScenarioNode { get; }

	internal XmlNode UMCI_ProductSignersNode { get; }
	internal XmlNode KMCI_ProductSignersNode { get; }

	// FileRulesRef nodes for UMCI and KMCI
	internal XmlNode UMCI_ProductSigners_FileRulesRef_Node { get; }
	internal XmlNode KMCI_ProductSigners_FileRulesRef_Node { get; }

	// AllowedSigners nodes for UMCI and KMCI
	internal XmlNode UMCI_ProductSigners_AllowedSigners_Node { get; }
	internal XmlNode KMCI_ProductSigners_AllowedSigners_Node { get; }

	internal XmlNode UMCI_ProductSigners_DeniedSigners_Node { get; }
	internal XmlNode KMCI_ProductSigners_DeniedSigners_Node { get; }

	internal CodeIntegrityPolicy(string xmlFilePath)
	{
		XmlDocument = new XmlDocument();
		XmlDocument.Load(xmlFilePath);

		// Create namespace manager and add the default namespace with a prefix
		NamespaceManager = new XmlNamespaceManager(XmlDocument.NameTable);
		NamespaceManager.AddNamespace("ns", GlobalVars.SiPolicyNamespace);

		// Get SiPolicy node
		SiPolicyNode = XmlDocument.SelectSingleNode("ns:SiPolicy", NamespaceManager)
			?? throw new InvalidOperationException(
				GlobalVars.GetStr("InvalidXmlStructureSiPolicyNodeNotFoundMessage"));

		// Find the Signers Node
		SignersNode = SiPolicyNode.SelectSingleNode("ns:Signers", NamespaceManager)
			?? throw new InvalidOperationException(
				GlobalVars.GetStr("SignersNodeNotFoundMessage"));

		// Find the EKUs Node
		EKUsNode = SiPolicyNode.SelectSingleNode("ns:EKUs", NamespaceManager)
			?? throw new InvalidOperationException(
				GlobalVars.GetStr("EKUsNodeNotFoundMessage"));

		// Find or ensure SigningScenario Node for User Mode
		UMCI_SigningScenarioNode = EnsureUMCISigningScenario();

		// Find or ensure SigningScenario Node for Kernel Mode
		KMCI_SigningScenarioNode = EnsureKMCISigningScenario();

		// Find ProductSigners Node for User Mode
		UMCI_ProductSignersNode = UMCI_SigningScenarioNode.SelectSingleNode("ns:ProductSigners", NamespaceManager)
			?? throw new InvalidOperationException(
				GlobalVars.GetStr("FailedToRetrieveUMCIProductSignersNodeMessage"));

		// Find ProductSigners Node for Kernel Mode
		KMCI_ProductSignersNode = KMCI_SigningScenarioNode.SelectSingleNode("ns:ProductSigners", NamespaceManager)
			?? throw new InvalidOperationException(
				GlobalVars.GetStr("FailedToRetrieveKMCIProductSignersNodeMessage"));

		// Ensure FileRulesRef nodes exist
		UMCI_ProductSigners_FileRulesRef_Node = EnsureFileRulesRefNode(UMCI_ProductSignersNode, "UMCI");
		KMCI_ProductSigners_FileRulesRef_Node = EnsureFileRulesRefNode(KMCI_ProductSignersNode, "KMCI");

		// Ensure AllowedSigners nodes exist
		UMCI_ProductSigners_AllowedSigners_Node = EnsureAllowedSignersNode(UMCI_ProductSignersNode, "UMCI");
		KMCI_ProductSigners_AllowedSigners_Node = EnsureAllowedSignersNode(KMCI_ProductSignersNode, "KMCI");

		// Ensure DeniedSigners nodes exist
		UMCI_ProductSigners_DeniedSigners_Node = EnsureDeniedSignersNode(UMCI_ProductSignersNode, "UMCI");
		KMCI_ProductSigners_DeniedSigners_Node = EnsureDeniedSignersNode(KMCI_ProductSignersNode, "KMCI");

		#region CiSigners Node

		// Find the CiSigners Node
		XmlNode? ciSignersNode = SiPolicyNode.SelectSingleNode("ns:CiSigners", NamespaceManager);
		if (ciSignersNode is null)
		{
			XmlElement newCiSignersNode = XmlDocument.CreateElement("CiSigners", GlobalVars.SiPolicyNamespace);
			_ = SiPolicyNode.AppendChild(newCiSignersNode);

			CiSignersNode = newCiSignersNode;
		}
		else
		{
			CiSignersNode = ciSignersNode;
		}

		#endregion

		#region FileRules node

		XmlNode? fileRulesNode = SiPolicyNode.SelectSingleNode("ns:FileRules", NamespaceManager);
		if (fileRulesNode is null)
		{
			XmlElement newFileRulesNode = XmlDocument.CreateElement("FileRules", GlobalVars.SiPolicyNamespace);
			_ = SiPolicyNode.AppendChild(newFileRulesNode);

			FileRulesNode = newFileRulesNode;
		}
		else
		{
			FileRulesNode = fileRulesNode;
		}

		#endregion
	}

	private XmlNode EnsureFileRulesRefNode(XmlNode parentNode, string mode)
	{
		// Find the FileRulesRef node
		XmlNode? fileRulesRefNode = parentNode.SelectSingleNode("ns:FileRulesRef", NamespaceManager);

		// If it doesn't exist, create it
		if (fileRulesRefNode is null)
		{
			XmlElement newFileRulesRefNode = XmlDocument.CreateElement("FileRulesRef", GlobalVars.SiPolicyNamespace);
			_ = parentNode.AppendChild(newFileRulesRefNode);

			fileRulesRefNode = parentNode.SelectSingleNode("ns:FileRulesRef", NamespaceManager);

			if (fileRulesRefNode is null)
			{
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.GetStr("FileRulesRefNodeNotFoundDespiteCreationMessage"),
						mode));
			}
		}

		return fileRulesRefNode;
	}

	private XmlNode EnsureAllowedSignersNode(XmlNode parentNode, string mode)
	{
		// Find the AllowedSigners node
		XmlNode? allowedSignersNode = parentNode.SelectSingleNode("ns:AllowedSigners", NamespaceManager);

		// If it doesn't exist, create it
		if (allowedSignersNode is null)
		{
			XmlElement newAllowedSignersNode = XmlDocument.CreateElement("AllowedSigners", GlobalVars.SiPolicyNamespace);
			_ = parentNode.AppendChild(newAllowedSignersNode);

			allowedSignersNode = parentNode.SelectSingleNode("ns:AllowedSigners", NamespaceManager);

			if (allowedSignersNode is null)
			{
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.GetStr("AllowedSignersNodeNotFoundDespiteCreationMessage"),
						mode));
			}
		}

		return allowedSignersNode;
	}

	private XmlNode EnsureDeniedSignersNode(XmlNode parentNode, string mode)
	{
		// Find the DeniedSigners node
		XmlNode? deniedSignersNode = parentNode.SelectSingleNode("ns:DeniedSigners", NamespaceManager);

		// If it doesn't exist, create it
		if (deniedSignersNode is null)
		{
			XmlElement newDeniedSignersNode = XmlDocument.CreateElement("DeniedSigners", GlobalVars.SiPolicyNamespace);
			_ = parentNode.AppendChild(newDeniedSignersNode);

			deniedSignersNode = parentNode.SelectSingleNode("ns:DeniedSigners", NamespaceManager);

			if (deniedSignersNode is null)
			{
				throw new InvalidOperationException(
					string.Format(
						GlobalVars.GetStr("DeniedSignersNodeNotFoundDespiteCreationMessage"),
						mode));
			}
		}

		return deniedSignersNode;
	}

	/// <summary>
	/// Creates the Signing Scenarios node or each Signing Scenario and their respective Product Signers
	/// </summary>
	/// <param name="scenarioValue"></param>
	/// <param name="scenarioId"></param>
	/// <returns></returns>
	private XmlNode EnsureSigningScenario(uint scenarioValue, string scenarioId)
	{
		// Find or create the SigningScenarios node
		XmlNode? signingScenariosNode = SiPolicyNode.SelectSingleNode("ns:SigningScenarios", NamespaceManager);

		if (signingScenariosNode is null)
		{
			XmlElement newSigningScenariosNode = XmlDocument.CreateElement("SigningScenarios", GlobalVars.SiPolicyNamespace);
			signingScenariosNode = SiPolicyNode.AppendChild(newSigningScenariosNode);
		}

		// Find the specific SigningScenario node
		XmlNode? signingScenarioNode = signingScenariosNode!.SelectSingleNode($"ns:SigningScenario[@Value='{scenarioValue}']", NamespaceManager);

		if (signingScenarioNode is null)
		{
			// Create the SigningScenario node
			XmlElement newSigningScenarioNode = XmlDocument.CreateElement("SigningScenario", GlobalVars.SiPolicyNamespace);
			newSigningScenarioNode.SetAttribute("Value", scenarioValue.ToString(CultureInfo.InvariantCulture));
			newSigningScenarioNode.SetAttribute("ID", scenarioId);
			newSigningScenarioNode.SetAttribute("FriendlyName", scenarioValue is 12 ? "User Mode Signing Scenario" : "Kernel Mode Signing Scenario");

			// Append the new SigningScenario node to the SigningScenarios node
			signingScenarioNode = signingScenariosNode.AppendChild(newSigningScenarioNode);

			// Create and append the ProductSigners node
			XmlElement newProductSignersNode = XmlDocument.CreateElement("ProductSigners", GlobalVars.SiPolicyNamespace);
			_ = signingScenarioNode!.AppendChild(newProductSignersNode);
		}

		return signingScenarioNode;
	}

	private XmlNode EnsureUMCISigningScenario()
	{
		// Value="12" is for User Mode Signing Scenario
		return EnsureSigningScenario(12, "ID_SIGNINGSCENARIO_UMCI");
	}

	private XmlNode EnsureKMCISigningScenario()
	{
		// Value="131" is for Kernel Mode Signing Scenario
		return EnsureSigningScenario(131, "ID_SIGNINGSCENARIO_KMCI");
	}

	/// <summary>
	/// Saves the XML object to a file and removes any unused nodes that would cause errors if left without members
	/// </summary>
	/// <param name="XMLObject"></param>
	/// <param name="XMLFilePath"></param>
	internal static void Save(XmlDocument XMLObject, string XMLFilePath)
	{
		XMLObject.Save(XMLFilePath);
		CloseEmptyXmlNodesSemantic.Close(XMLFilePath);
	}
}
