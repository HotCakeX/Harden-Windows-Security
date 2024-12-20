using System;
using System.Xml;
using AppControlManager.Logging;

namespace AppControlManager.XMLOps;

internal static class SetCiPolicyInfo
{
	/// <summary>
	/// Configures a XML Code Integrity policy by modifying its details.
	/// When it comes to PolicyID, the only time it is modified is through random GUID generation.
	/// The BasePolicyID however can be modified by supplying a XML file, or providing the GUID directory, or through GUID random generation.
	/// If the policy doesn't have a <Settings> node with a <Setting> node inside of it for PolicyName, it will be created. This is regardless of whether the policyName parameter was provided or not.
	/// </summary>
	/// <param name="filePath">Path to the XML policy file to modify</param>
	///
	/// <param name="resetPolicyID">
	/// Will assign a random GUID for the PolicyID and BasePolicyID of the selected XML file.
	/// If this parameter is specified along with basePolicyID, first both policyID and BasePolicyID will reset and then basePolicyID will be applied to the policy.
	/// Which is the same behavior as Set-CIPolicyIdInfo cmdlet.
	/// </param>
	///
	/// <param name="policyName">The policy name to set for the selected XML policy file</param>
	///
	/// <param name="basePolicyID">
	/// The BasePolicyID to set for the selected XML policy file.
	/// It doesn't need to have curly brackets. They will be added automatically by the method.
	/// It is the same as the -SupplementsBasePolicyID parameter of the Set-CIPolicyIdInfo cmdlet.
	/// It will change the type of the policy to a Supplemental Policy type.
	/// </param>
	///
	/// <param name="basePolicyToSupplementPath">
	/// The path to a XML file. The PolicyID of the file will be extracted and applied to the BasePolicyID of the XML file selected in the filePath parameter.
	/// </param>
	///
	/// <returns> Returns the final policy ID of the XML policy. It will have curly brackets. </returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static string Set(string filePath, bool? resetPolicyID, string? policyName, string? basePolicyID, string? basePolicyToSupplementPath)
	{

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(filePath, null);

		XmlNode? SettingsNode = codeIntegrityPolicy.SiPolicyNode.SelectSingleNode("ns:Settings", codeIntegrityPolicy.NamespaceManager);
		XmlNodeList? SettingNodes;
		string? CurrentPolicyName;

		string PolicyType = codeIntegrityPolicy.SiPolicyNode.Attributes?["PolicyType"]?.Value!;

		#region PolicyName Processing

		// Check if Settings node exists, if not, create it
		if (SettingsNode is null)
		{
			SettingsNode = codeIntegrityPolicy.XmlDocument.CreateElement("Settings", codeIntegrityPolicy.NameSpaceURI);
			_ = codeIntegrityPolicy.SiPolicyNode.AppendChild(SettingsNode);
		}

		// Get the list of Setting nodes
		SettingNodes = SettingsNode.SelectNodes("ns:Setting", codeIntegrityPolicy.NamespaceManager);

		// Find the specific Setting node with ValueName="Name" and extract its string value or create it if not found

		// nameSettingNode that will be used to assign the policy name
		XmlNode? nameSettingNode = null;

		if (SettingNodes is not null)
		{
			foreach (XmlNode setting in SettingNodes)
			{
				// Check if the "ValueName" attribute is present and equals "Name"
				if (string.Equals(setting.Attributes?["ValueName"]?.Value, "Name", StringComparison.OrdinalIgnoreCase))
				{
					nameSettingNode = setting;
					break;
				}
			}
		}

		// If the Setting node with ValueName="Name" does not exist, create it
		if (nameSettingNode is null)
		{
			nameSettingNode = codeIntegrityPolicy.XmlDocument.CreateElement("Setting", codeIntegrityPolicy.NameSpaceURI);

			XmlAttribute providerAttr = codeIntegrityPolicy.XmlDocument.CreateAttribute("Provider");
			providerAttr.Value = "PolicyInfo";
			_ = nameSettingNode.Attributes!.Append(providerAttr);

			XmlAttribute keyAttr = codeIntegrityPolicy.XmlDocument.CreateAttribute("Key");
			keyAttr.Value = "Information";
			_ = nameSettingNode.Attributes.Append(keyAttr);

			XmlAttribute valueNameAttr = codeIntegrityPolicy.XmlDocument.CreateAttribute("ValueName");
			valueNameAttr.Value = "Name";
			_ = nameSettingNode.Attributes.Append(valueNameAttr);

			// Append the new Setting node to Settings
			_ = SettingsNode.AppendChild(nameSettingNode);
		}

		// Now check if the Value node with the inner String node exists, and create if not
		XmlNode? valueNode = nameSettingNode.SelectSingleNode("ns:Value/ns:String", codeIntegrityPolicy.NamespaceManager);

		if (valueNode is null)
		{
			// Create Value node
			XmlNode newValueNode = codeIntegrityPolicy.XmlDocument.CreateElement("Value", codeIntegrityPolicy.NameSpaceURI);
			XmlNode newStringNode = codeIntegrityPolicy.XmlDocument.CreateElement("String", codeIntegrityPolicy.NameSpaceURI);

			_ = newValueNode.AppendChild(newStringNode);
			_ = nameSettingNode.AppendChild(newValueNode);

			valueNode = newStringNode;
		}

		// Update the policy name or assign default value if not provided
		if (!string.IsNullOrWhiteSpace(policyName))
		{
			valueNode.InnerText = policyName;
			CurrentPolicyName = policyName;
		}
		else
		{
			// If policyName was not provided, retain the current name
			CurrentPolicyName = valueNode.InnerText;
		}

		#endregion


		#region resetPolicyID processing

		// If the resetPolicyID is true, then assign a new GUID to the PolicyID and BasePolicyID
		if (resetPolicyID == true)
		{
			// Generate a new GUID
			Guid newRandomGUID = Guid.CreateVersion7();

			// Convert it to string
			string newRandomGUIDString = $"{{{newRandomGUID.ToString().ToUpperInvariant()}}}";

			codeIntegrityPolicy.PolicyIDNode.InnerText = newRandomGUIDString;
			codeIntegrityPolicy.BasePolicyIDNode.InnerText = newRandomGUIDString;
		}

		#endregion


		#region basePolicyID processing

		if (!string.IsNullOrWhiteSpace(basePolicyID))
		{

			basePolicyID = basePolicyID.Trim('{', '}');

			// Make sure the input parameter is a valid GUID, doesn't need to have curly brackets, just a GUID string with correct length and format
			if (!Guid.TryParse(basePolicyID, out _))
			{
				throw new ArgumentException($"The provided string '{basePolicyID}' is not a valid GUID format.");
			}

			string tempVar = $"{{{basePolicyID.ToUpperInvariant()}}}";

			// Set the BasePolicyID of the policy file to the user provided one
			codeIntegrityPolicy.BasePolicyIDNode.InnerText = tempVar;
		}

		#endregion


		#region basePolicyToSupplementPath processing

		if (!string.IsNullOrWhiteSpace(basePolicyToSupplementPath))
		{

			XmlDocument xmlDocument2 = new();
			xmlDocument2.Load(basePolicyToSupplementPath);

			// Create namespace manager and add the default namespace with a prefix
			XmlNamespaceManager namespaceManager2 = new(xmlDocument2.NameTable);
			namespaceManager2.AddNamespace("ns", codeIntegrityPolicy.NameSpaceURI);

			// Get SiPolicy node
			XmlNode siPolicyNode2 = xmlDocument2.SelectSingleNode("ns:SiPolicy", namespaceManager2)
				?? throw new InvalidOperationException("Invalid XML structure, SiPolicy node not found");

			// Get the PolicyID node which is an immediate node under SiPolicy node
			XmlNode CurrentPolicyIDNode2 = siPolicyNode2.SelectSingleNode("ns:PolicyID", namespaceManager2) ?? throw new InvalidOperationException($"PolicyID was not found in {basePolicyToSupplementPath}");

			// Set the BasePolicyID of the policy file to the PolicyID of the method's 1st parameter XML file
			codeIntegrityPolicy.BasePolicyIDNode.InnerText = CurrentPolicyIDNode2.InnerText;
		}

		#endregion


		#region Checking Policy Type

		if (string.Equals(PolicyType, "Supplemental Policy", StringComparison.OrdinalIgnoreCase))
		{
			if (string.Equals(codeIntegrityPolicy.BasePolicyIDNode.InnerText, codeIntegrityPolicy.PolicyIDNode.InnerText, StringComparison.OrdinalIgnoreCase))
			{
				Logger.Write("The selected XML policy file is a Supplemental policy but its BasePolicyID and PolicyID are the same, indicating it is a Base policy, changing the type.");


				codeIntegrityPolicy.SiPolicyNode.Attributes!["PolicyType"]!.Value = "Base Policy";
				// Set this variable to the updated type for the type check that happens later
				PolicyType = "Base Policy";
			}
		}

		if (string.Equals(PolicyType, "Base Policy", StringComparison.OrdinalIgnoreCase))
		{
			if (!string.Equals(codeIntegrityPolicy.BasePolicyIDNode.InnerText, codeIntegrityPolicy.PolicyIDNode.InnerText, StringComparison.OrdinalIgnoreCase))
			{
				Logger.Write("The selected XML policy file is a Base policy but its BasePolicyID and PolicyID are not the same, indicating it is a Supplemental policy, changing the type.");


				codeIntegrityPolicy.SiPolicyNode.Attributes!["PolicyType"]!.Value = "Supplemental Policy";
				// Set this variable to the updated type for the type check that happens later
				PolicyType = "Supplemental Policy";
			}
		}

		#endregion


		// Save the changes to the XML file
		codeIntegrityPolicy.XmlDocument.Save(filePath);

		// Validate the XML file at the end
		if (!(bool)CiPolicyTest.TestCiPolicy(filePath, null)!)
		{
			throw new InvalidOperationException("SetCiPolicyInfo.Set: The XML file created at the end is not compliant with the CI policy schema");
		}

		Logger.Write($"Successfully configured the policy at '{filePath}'. Now it has the Name '{CurrentPolicyName}', Type '{PolicyType}', BasePolicyID '{codeIntegrityPolicy.BasePolicyIDNode.InnerText}' and PolicyID '{codeIntegrityPolicy.PolicyIDNode.InnerText}'.");

		return codeIntegrityPolicy.PolicyIDNode.InnerText;
	}


	/// <summary>
	/// An overload of the Set method, responsible for setting the version number in the policy
	/// </summary>
	/// <param name="filePath"></param>
	/// <param name="version"></param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void Set(string filePath, Version version)
	{

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(filePath, null);

		// save the current XML policy version to a variable prior to modifying it
		string OriginalXMLPolicyVersion = codeIntegrityPolicy.VersionExNode.InnerText;

		// Set the user provided version to the policy
		codeIntegrityPolicy.VersionExNode.InnerText = version.ToString();

		// Save the changes to the XML file
		codeIntegrityPolicy.XmlDocument.Save(filePath);

		// Validate the XML file at the end
		if (!(bool)CiPolicyTest.TestCiPolicy(filePath, null)!)
		{
			throw new InvalidOperationException("SetCiPolicyInfo.Set: The XML file created at the end is not compliant with the CI policy schema");
		}

		Logger.Write($"Successfully set the version of the policy file at '{filePath}' from '{OriginalXMLPolicyVersion}' to '{version}'.");

	}
}
