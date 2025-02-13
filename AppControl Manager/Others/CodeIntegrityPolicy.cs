using System;
using System.Collections.Generic;
using System.Globalization;
using System.Xml;
using AppControlManager.XMLOps;

namespace AppControlManager.Others;

// This class represents a single Code Integrity XML policy.
// It operates as a custom XML serializer/deserializer.
// It Makes sure PolicyType attribute, BasePolicyID node and PolicyID nodes exist and remove PolicyTypeID node if it exists

internal sealed class CodeIntegrityPolicy
{

	internal XmlDocument XmlDocument { get; }
	internal XmlNamespaceManager NamespaceManager { get; }

	internal XmlNode SiPolicyNode { get; }

	// These items must only be read and not assigned
	// Their assignments in other methods must happen through their respective nodes exposed by the instantiated class
	internal string PolicyType { get; }

	internal string PolicyID { get; }
	internal string BasePolicyID { get; }

	internal XmlNode PolicyIDNode { get; }
	internal XmlNode BasePolicyIDNode { get; }

	internal List<string>? Rules { get; }

	internal XmlNode FileRulesNode { get; }

	internal XmlNode SignersNode { get; }

	internal XmlNode CiSignersNode { get; }

	internal XmlNode VersionExNode { get; }

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

	internal CodeIntegrityPolicy(string? xmlFilePath, XmlDocument? xmlDocument)
	{
		if (xmlFilePath is not null)
		{
			XmlDocument = new XmlDocument();
			XmlDocument.Load(xmlFilePath);
		}
		else if (xmlDocument is not null)
		{
			XmlDocument = xmlDocument;
		}
		else
		{
			throw new InvalidOperationException("Either xmlFilePath or xmlDocument must be provided");
		}

		// Create namespace manager and add the default namespace with a prefix
		NamespaceManager = new XmlNamespaceManager(XmlDocument.NameTable);
		NamespaceManager.AddNamespace("ns", GlobalVars.SiPolicyNamespace);

		// Get SiPolicy node
		SiPolicyNode = XmlDocument.SelectSingleNode("ns:SiPolicy", NamespaceManager)
			?? throw new InvalidOperationException("Invalid XML structure, SiPolicy node not found");

		// Find the Signers Node
		SignersNode = SiPolicyNode.SelectSingleNode("ns:Signers", NamespaceManager)
			?? throw new InvalidOperationException("Signers node not found");

		// Find or ensure SigningScenario Node for User Mode
		UMCI_SigningScenarioNode = EnsureUMCISigningScenario();

		// Find or ensure SigningScenario Node for Kernel Mode
		KMCI_SigningScenarioNode = EnsureKMCISigningScenario();

		// Find or ensure ProductSigners Node for User Mode
		UMCI_ProductSignersNode = UMCI_SigningScenarioNode.SelectSingleNode("ns:ProductSigners", NamespaceManager)
			?? throw new InvalidOperationException("Failed to create or retrieve UMCI_ProductSignersNode");

		// Find or ensure ProductSigners Node for Kernel Mode
		KMCI_ProductSignersNode = KMCI_SigningScenarioNode.SelectSingleNode("ns:ProductSigners", NamespaceManager)
			?? throw new InvalidOperationException("Failed to create or retrieve KMCI_ProductSignersNode");

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


		#region PolicyType Attribute

		// If PolicyType attribute does not exist in the SiPolicyNode then add it and set it to Base policy
		string? policyType = SiPolicyNode.Attributes?["PolicyType"]?.Value;

		if (policyType is null)
		{
			// Create PolicyType attribute and set it to "Base Policy"
			XmlAttribute newPolicyTypeAttribute = XmlDocument.CreateAttribute("PolicyType");
			newPolicyTypeAttribute.Value = "Base Policy";
			_ = SiPolicyNode.Attributes!.Append(newPolicyTypeAttribute);

			PolicyType = newPolicyTypeAttribute.Value;
		}
		else
		{
			PolicyType = policyType;
		}

		#endregion

		// Generate a new GUID
		Guid newRandomGUID = Guid.CreateVersion7();

		// Convert it to string
		string newRandomGUIDString = $"{{{newRandomGUID.ToString().ToUpperInvariant()}}}";

		#region BasePolicyID

		XmlNode? basePolicyIDNode = SiPolicyNode.SelectSingleNode("ns:BasePolicyID", NamespaceManager);

		if (basePolicyIDNode is null)
		{
			// Create the node
			XmlElement newBasePolicyIDNode = XmlDocument.CreateElement("BasePolicyID", GlobalVars.SiPolicyNamespace);

			// Set its value to match PolicyID because we are making it a Base policy when the node doesn't exist
			newBasePolicyIDNode.InnerText = newRandomGUIDString;

			// Append the new BasePolicyID node to the SiPolicy node
			_ = SiPolicyNode.AppendChild(newBasePolicyIDNode);

			BasePolicyIDNode = newBasePolicyIDNode;

			BasePolicyID = newRandomGUIDString;
		}
		else
		{
			BasePolicyIDNode = basePolicyIDNode;

			BasePolicyID = basePolicyIDNode.InnerText;
		}

		#endregion

		#region PolicyID

		XmlNode? policyIDNode = SiPolicyNode.SelectSingleNode("ns:PolicyID", NamespaceManager);

		if (policyIDNode is null)
		{
			// Create the node
			XmlElement newPolicyIDNode = XmlDocument.CreateElement("PolicyID", GlobalVars.SiPolicyNamespace);

			// Set its value to match PolicyID because this is a Base policy
			newPolicyIDNode.InnerText = newRandomGUIDString;

			// Append the new BasePolicyID node to the SiPolicy node
			_ = SiPolicyNode.AppendChild(newPolicyIDNode);

			PolicyIDNode = newPolicyIDNode;

			PolicyID = newRandomGUIDString;
		}
		else
		{
			PolicyIDNode = policyIDNode;

			PolicyID = policyIDNode.InnerText;
		}

		#endregion

		#region PolicyTypeID

		XmlNode? policyTypeIDNode = SiPolicyNode.SelectSingleNode("ns:PolicyTypeID", NamespaceManager);

		// Don't need this if it exists, usually exists in Microsoft Recommended block rules
		if (policyTypeIDNode is not null)
		{
			// Remove the policyTypeIDNode from its parent (siPolicyNode)
			_ = SiPolicyNode.RemoveChild(policyTypeIDNode);
		}

		#endregion

		#region VersionEx

		VersionExNode = SiPolicyNode.SelectSingleNode("ns:VersionEx", NamespaceManager) ?? throw new InvalidOperationException($"VersionEx was not found.");

		#endregion

		#region Rules
		Rules = LoadRules();
		#endregion
	}


	private List<string>? LoadRules()
	{
		XmlNode? rulesNode = SiPolicyNode.SelectSingleNode("ns:Rules", NamespaceManager);

		if (rulesNode is null)
		{
			return null;
		}

		List<string> rulesList = [];

		XmlNodeList? ruleOptions = rulesNode.SelectNodes("ns:Rule/ns:Option", NamespaceManager);

		if (ruleOptions is not null)
		{
			foreach (XmlNode ruleNode in ruleOptions)
			{
				if (!string.IsNullOrWhiteSpace(ruleNode.InnerText))
				{
					rulesList.Add(ruleNode.InnerText);
				}
			}
		}

		return rulesList.Count > 0 ? rulesList : null;
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
				throw new InvalidOperationException($"{mode} Product Signers FileRulesRef node not found despite creating it.");
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
				throw new InvalidOperationException($"{mode} Product Signers AllowedSigners node not found despite creating it.");
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
				throw new InvalidOperationException($"{mode} Product Signers DeniedSigners node not found despite creating it.");
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
