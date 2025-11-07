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

using System.Collections.Frozen;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Xml;
using AppControlManager.Main;

namespace AppControlManager.SiPolicy;

internal static class CustomDeserialization
{

	/// <summary>
	/// Deserializes a security policy from either a file path or an XML document into a SiPolicy object.
	/// </summary>
	/// <param name="filePath">Specifies the location of the XML file to load the policy from.</param>
	/// <param name="Xml">Provides an XML document to deserialize the policy if the file path is not used.</param>
	/// <returns>Returns a SiPolicy object populated with data from the provided XML.</returns>
	/// <exception cref="InvalidOperationException">Thrown when neither a valid file path nor an XML document is provided for deserialization.</exception>
	internal static SiPolicy DeserializeSiPolicy(string? filePath, XmlDocument? Xml)
	{

		XmlElement? root;

		if (!string.IsNullOrEmpty(filePath))
		{
			XmlDocument xmlDoc = new();
			xmlDoc.Load(filePath);
			root = xmlDoc.DocumentElement
				   ?? throw new InvalidOperationException(
					   GlobalVars.GetStr("InvalidXmlMissingRootElementValidationError"));

			// Make sure the policy file is valid
			CiPolicyTest.TestCiPolicy(filePath);
		}
		else if (Xml is not null)
		{
			root = Xml.DocumentElement
				   ?? throw new InvalidOperationException(
					   GlobalVars.GetStr("InvalidXmlMissingRootElementValidationError"));
		}
		else
		{
			throw new InvalidOperationException(
				GlobalVars.GetStr("FilePathOrXmlRequiredMessage"));
		}

		SiPolicy policy = new();

		// Friendly Name
		if (root.HasAttribute("FriendlyName"))
			policy.FriendlyName = root.GetAttribute("FriendlyName");

		// Policy Type - if missing, Base policy type is assigned
		policy.PolicyTypeSpecified = true;
		policy.PolicyType = root.HasAttribute("PolicyType") ? ConvertStringToPolicyType(root.GetAttribute("PolicyType")) : PolicyType.BasePolicy;

		// Generate a new GUID
		Guid newRandomGUID = Guid.CreateVersion7();
		// Convert it to string
		string newRandomGUIDString = $"{{{newRandomGUID.ToString().ToUpperInvariant()}}}";

		// Read basic text elements
		string version = GetElementText(root, "VersionEx");
		policy.VersionEx = string.IsNullOrEmpty(version) ? "1.0.0.0" : version;

		string policyID = GetElementText(root, "PolicyID");
		policy.PolicyID = string.IsNullOrEmpty(policyID) ? newRandomGUIDString : policyID;

		string basePolicyID = GetElementText(root, "BasePolicyID");
		policy.BasePolicyID = string.IsNullOrEmpty(basePolicyID) ? newRandomGUIDString : basePolicyID;

		string platformID = GetElementText(root, "PlatformID");
		policy.PlatformID = string.IsNullOrEmpty(platformID) ? "{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}" : platformID;

		if (string.IsNullOrEmpty(policy.PolicyID) || string.IsNullOrEmpty(policy.BasePolicyID))
		{
			throw new InvalidOperationException(GlobalVars.GetStr("NeedBothIDsValidationError"));
		}

		if (
			(policy.PolicyType is PolicyType.BasePolicy && !string.Equals(policy.PolicyID, policy.BasePolicyID, StringComparison.OrdinalIgnoreCase)) ||
			(policy.PolicyType is not PolicyType.BasePolicy && string.Equals(policy.PolicyID, policy.BasePolicyID, StringComparison.OrdinalIgnoreCase))
			)
		{
			throw new InvalidOperationException(GlobalVars.GetStr("IDsMismatchValidationError"));
		}

		// PolicyTypeID used to be for old version of WDAC policies that didn't have support for Supplemental policies.
		// Now policies have BasePolicyID and PolicyID values instead.
		// A policy cannot have a PolicyTypeID and also have PolicyID or BasePolicyID. In such situations, the value of the PolicyTypeID must be used for both PolicyID and BasePolicyID. These situations only happen when parsing very old WDAC policies.
		policy.PolicyTypeID = null;

		// Deserialize Rules
		// Make sure it exists even empty
		policy.Rules = [];
		HashSet<OptionType> policyRules = [];
		XmlElement? rulesElement = root["Rules", GlobalVars.SiPolicyNamespace];
		if (rulesElement is not null)
		{
			List<RuleType> rules = [];
			foreach (XmlElement ruleElem in rulesElement.ChildNodes.OfType<XmlElement>())
			{
				string optionText = GetElementText(ruleElem, "Option");
				OptionType opt = ConvertStringToOptionType(optionText);

				if (!policyRules.Add(opt))
				{
					throw new InvalidOperationException($"{GlobalVars.GetStr("DuplicateRuleOptionValidationError")}: {opt}");
				}

				RuleType rule = new() { Item = opt };
				rules.Add(rule);
			}
			policy.Rules = [.. rules];
		}

		if (policy.PolicyType is PolicyType.SupplementalPolicy && policyRules.Contains(OptionType.EnabledAllowSupplementalPolicies))
		{
			throw new InvalidOperationException(string.Format(GlobalVars.GetStr("SupplementalPolicyWithInvalidRuleOption"), PolicyType.SupplementalPolicy, OptionType.EnabledAllowSupplementalPolicies, PolicyType.BasePolicy));
		}

		// Deserialize EKUs
		// Make sure it exists even empty
		policy.EKUs = [];

		HashSet<string> EKUIDsCol = [];

		XmlElement? ekusElement = root["EKUs", GlobalVars.SiPolicyNamespace];
		if (ekusElement is not null)
		{
			List<EKU> ekus = [];
			foreach (XmlElement ekuElem in ekusElement.ChildNodes.OfType<XmlElement>())
			{
				EKU eku = new();
				if (ekuElem.HasAttribute("ID"))
					eku.ID = ekuElem.GetAttribute("ID");
				if (ekuElem.HasAttribute("FriendlyName"))
					eku.FriendlyName = ekuElem.GetAttribute("FriendlyName");
				if (ekuElem.HasAttribute("Value"))
					eku.Value = ConvertHexStringToByteArray(ekuElem.GetAttribute("Value"));
				ekus.Add(eku);

				if (!EKUIDsCol.Add(eku.ID))
				{
					throw new InvalidOperationException($"{GlobalVars.GetStr("DuplicateEKUIDsValidationError")}: {eku.ID}");
				}
			}
			policy.EKUs = [.. ekus];
		}

		// Deserialize FileRules
		// Make sure it exists even empty
		policy.FileRules = [];

		HashSet<string> AllowRulesIDsCol = [];
		HashSet<string> DenyRulesIDsCol = [];
		HashSet<string> FileAttribRulesIDsCol = [];
		HashSet<string> FileRulesIDsCol = [];

		XmlElement? fileRulesElement = root["FileRules", GlobalVars.SiPolicyNamespace];
		if (fileRulesElement is not null)
		{
			List<object> fileRules = [];
			foreach (XmlElement ruleElem in fileRulesElement.ChildNodes.OfType<XmlElement>())
			{
				switch (ruleElem.LocalName)
				{
					case "Allow":
						fileRules.Add(DeserializeAllow(ruleElem, AllowRulesIDsCol));
						break;
					case "Deny":
						fileRules.Add(DeserializeDeny(ruleElem, DenyRulesIDsCol));
						break;
					case "FileAttrib":
						fileRules.Add(DeserializeFileAttrib(ruleElem, FileAttribRulesIDsCol));
						break;
					case "FileRule":
						fileRules.Add(DeserializeFileRule(ruleElem, FileRulesIDsCol));
						break;
					default:
						break;
				}
			}
			policy.FileRules = [.. fileRules];
		}

		// Deserialize Signers
		// Make sure it exists even empty
		policy.Signers = [];

		HashSet<string> SignersIDsCol = [];

		XmlElement? signersElement = root["Signers", GlobalVars.SiPolicyNamespace];
		if (signersElement is not null)
		{
			List<Signer> signers = [];
			foreach (XmlElement signerElem in signersElement.ChildNodes.OfType<XmlElement>())
			{
				signers.Add(DeserializeSigner(signerElem, SignersIDsCol));
			}
			policy.Signers = [.. signers];
		}

		// Deserialize SigningScenarios
		// Make sure it exists even empty
		policy.SigningScenarios = [];

		// Used to store the SigningScenarios IDs to ensure they are unique.
		HashSet<string> SigningScenariosIDs = [];

		XmlElement? signingScenariosElement = root["SigningScenarios", GlobalVars.SiPolicyNamespace];
		if (signingScenariosElement is not null)
		{
			List<SigningScenario> scenarios = [];
			foreach (XmlElement scenarioElem in signingScenariosElement.ChildNodes.OfType<XmlElement>())
			{
				SigningScenario signingScenario = DeserializeSigningScenario(scenarioElem, SigningScenariosIDs);

				if (policy.PolicyType is PolicyType.AppIDTaggingPolicy)
				{
					if (signingScenario.Value != 12)
					{
						throw new InvalidOperationException(string.Format(GlobalVars.GetStr("AppIDTaggingPolicyInvalidSigningScenarioID"), PolicyType.AppIDTaggingPolicy, signingScenario.Value));
					}

					if (signingScenario.AppIDTags is null || signingScenario.AppIDTags.AppIDTag is null || signingScenario.AppIDTags.AppIDTag.Length == 0)
					{
						throw new InvalidOperationException(string.Format(GlobalVars.GetStr("AppIDTaggingPolicyMissingAppIDTags"), PolicyType.AppIDTaggingPolicy));
					}
				}

				scenarios.Add(signingScenario);
			}
			policy.SigningScenarios = [.. scenarios];
		}

		// Deserialize UpdatePolicySigners
		// Make sure it exists even empty
		policy.UpdatePolicySigners = [];
		XmlElement? upsElement = root["UpdatePolicySigners", GlobalVars.SiPolicyNamespace];
		if (upsElement is not null)
		{
			List<UpdatePolicySigner> upsList = [];
			foreach (XmlElement upsChild in upsElement.ChildNodes.OfType<XmlElement>())
			{
				UpdatePolicySigner ups = new();
				if (upsChild.HasAttribute("SignerId"))
					ups.SignerId = upsChild.GetAttribute("SignerId");
				upsList.Add(ups);
			}
			policy.UpdatePolicySigners = [.. upsList];
		}

		// If policy requires to be Signed
		if (!policyRules.Contains(OptionType.EnabledUnsignedSystemIntegrityPolicy) && policy.UpdatePolicySigners.Length == 0)
		{
			throw new InvalidOperationException(string.Format(GlobalVars.GetStr("PolicyNeedsSigningButNoUpdateSigner"), OptionType.EnabledUnsignedSystemIntegrityPolicy));
		}

		// Deserialize CiSigners
		// Make sure it exists even empty
		policy.CiSigners = [];
		XmlElement? ciElement = root["CiSigners", GlobalVars.SiPolicyNamespace];
		if (ciElement is not null)
		{
			List<CiSigner> ciList = [];
			foreach (XmlElement ciChild in ciElement.ChildNodes.OfType<XmlElement>())
			{
				CiSigner ci = new();
				if (ciChild.HasAttribute("SignerId"))
					ci.SignerId = ciChild.GetAttribute("SignerId");
				ciList.Add(ci);
			}
			policy.CiSigners = [.. ciList];
		}

		// Deserialize HvciOptions
		string hvciText = GetElementText(root, "HvciOptions");
		if (!string.IsNullOrEmpty(hvciText))
		{
			policy.HvciOptions = uint.Parse(hvciText, CultureInfo.InvariantCulture);
			policy.HvciOptionsSpecified = true;
		}

		// Deserialize Settings
		// Make sure it exists even empty
		policy.Settings = [];
		XmlElement? settingsElem = root["Settings", GlobalVars.SiPolicyNamespace];
		if (settingsElem is not null)
		{
			List<Setting> settings = [];
			foreach (XmlElement settingElem in settingsElem.ChildNodes.OfType<XmlElement>())
			{
				settings.Add(DeserializeSetting(settingElem));
			}
			policy.Settings = [.. settings];
		}

		if (policy.Settings.Length > ushort.MaxValue)
		{
			throw new InvalidOperationException(string.Format(GlobalVars.GetStr("SettingsAndAppIDTagsCountExceeded"), ushort.MaxValue));
		}

		// Deserialize Macros
		// Make sure it exists even empty
		policy.Macros = [];

		HashSet<string> MacrosIDsCol = [];

		XmlElement? macrosElem = root["Macros", GlobalVars.SiPolicyNamespace];
		if (macrosElem is not null)
		{
			List<MacrosMacro> macros = [];
			foreach (XmlElement macroElem in macrosElem.ChildNodes.OfType<XmlElement>())
			{
				MacrosMacro macro = new();
				if (macroElem.HasAttribute("Id"))
					macro.Id = macroElem.GetAttribute("Id");
				if (macroElem.HasAttribute("Value"))
					macro.Value = macroElem.GetAttribute("Value");
				macros.Add(macro);

				if (!MacrosIDsCol.Add(macro.Id))
				{
					throw new InvalidOperationException($"{GlobalVars.GetStr("DuplicateMacroIDsValidationError")}: {macro.Id}");
				}
			}
			policy.Macros = [.. macros];
		}

		// Deserialize SupplementalPolicySigners
		// Make sure it exists even empty
		policy.SupplementalPolicySigners = [];
		XmlElement? suppElem = root["SupplementalPolicySigners", GlobalVars.SiPolicyNamespace];
		if (suppElem is not null)
		{
			List<SupplementalPolicySigner> spsList = [];
			foreach (XmlElement spsElem in suppElem.ChildNodes.OfType<XmlElement>())
			{
				SupplementalPolicySigner sps = new();
				if (spsElem.HasAttribute("SignerId"))
					sps.SignerId = spsElem.GetAttribute("SignerId");
				spsList.Add(sps);
			}
			policy.SupplementalPolicySigners = [.. spsList];
		}

		if (policy.PolicyType is PolicyType.SupplementalPolicy && policy.SupplementalPolicySigners.Length != 0)
		{
			throw new InvalidOperationException(string.Format(GlobalVars.GetStr("SupplementalPolicyWithSupplementalSigners"), PolicyType.SupplementalPolicy));
		}

		// If it's supposed to be a Signed Base policy
		if (policy.PolicyType is PolicyType.BasePolicy && !policyRules.Contains(OptionType.EnabledUnsignedSystemIntegrityPolicy))
		{
			// If it allows for Supplemental policies but no Supplemental policy Signers have been specified
			if (policyRules.Contains(OptionType.EnabledAllowSupplementalPolicies) && policy.SupplementalPolicySigners.Length == 0)
			{
				// If policy ID is not "{5951A96A-E0B5-4D3D-8FB8-3E5B61030784}" which is for S-Mode in Windows.
				// https://learn.microsoft.com/windows/security/application-security/application-control/app-control-for-business/operations/inbox-appcontrol-policies
				if (!string.Equals(policy.PolicyID, "{5951A96A-E0B5-4D3D-8FB8-3E5B61030784}", StringComparison.OrdinalIgnoreCase))
				{
					throw new InvalidOperationException(GlobalVars.GetStr("MissingSupPolSignersValidationError"));
				}
			}
		}

		// Deserialize AppSettings
		XmlElement? appSettingsElem = root["AppSettings", GlobalVars.SiPolicyNamespace];
		if (appSettingsElem is not null)
		{
			AppSettingRegion appSettingRegion = new();
			List<AppRoot> apps = [];
			foreach (XmlElement appElem in appSettingsElem.ChildNodes.OfType<XmlElement>())
			{
				apps.Add(DeserializeAppRoot(appElem));
			}
			appSettingRegion.App = [.. apps];
			policy.AppSettings = appSettingRegion;
		}

		return policy;
	}

	// Helper to get the inner text of an element.
	private static string GetElementText(XmlElement parent, string localName)
	{
		XmlElement? elem = parent[localName, GlobalVars.SiPolicyNamespace];
		return elem is not null ? elem.InnerText : string.Empty;
	}

	// Convert a hex string (without delimiters) to a byte array.
	private static byte[] ConvertHexStringToByteArray(string hex)
	{
		if (string.IsNullOrEmpty(hex))
			return [];
		int length = hex.Length;
		byte[] bytes = new byte[length / 2];
		for (int i = 0; i < length; i += 2)
			bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
		return bytes;
	}


	private static readonly FrozenDictionary<string, OptionType> PolicyRuleOptionsActual = new Dictionary<string, OptionType>
	{
		{ "Enabled:UMCI", OptionType.EnabledUMCI },
		{ "Enabled:Boot Menu Protection", OptionType.EnabledBootMenuProtection },
		{ "Required:WHQL", OptionType.RequiredWHQL },
		{ "Enabled:Audit Mode", OptionType.EnabledAuditMode },
		{ "Disabled:Flight Signing", OptionType.DisabledFlightSigning },
		{ "Enabled:Inherit Default Policy", OptionType.EnabledInheritDefaultPolicy },
		{ "Enabled:Unsigned System Integrity Policy", OptionType.EnabledUnsignedSystemIntegrityPolicy },
		{ "Required:EV Signers", OptionType.RequiredEVSigners },
		{ "Enabled:Advanced Boot Options Menu", OptionType.EnabledAdvancedBootOptionsMenu },
		{ "Enabled:Boot Audit On Failure", OptionType.EnabledBootAuditOnFailure },
		{ "Disabled:Script Enforcement", OptionType.DisabledScriptEnforcement },
		{ "Required:Enforce Store Applications", OptionType.RequiredEnforceStoreApplications },
		{ "Enabled:Managed Installer", OptionType.EnabledManagedInstaller },
		{ "Enabled:Intelligent Security Graph Authorization", OptionType.EnabledIntelligentSecurityGraphAuthorization },
		{ "Enabled:Invalidate EAs on Reboot", OptionType.EnabledInvalidateEAsonReboot },
		{ "Enabled:Update Policy No Reboot", OptionType.EnabledUpdatePolicyNoReboot },
		{ "Enabled:Allow Supplemental Policies", OptionType.EnabledAllowSupplementalPolicies },
		{ "Disabled:Runtime FilePath Rule Protection", OptionType.DisabledRuntimeFilePathRuleProtection },
		{ "Enabled:Dynamic Code Security", OptionType.EnabledDynamicCodeSecurity },
		{ "Enabled:Revoked Expired As Unsigned", OptionType.EnabledRevokedExpiredAsUnsigned },
		{ "Enabled:Developer Mode Dynamic Code Trust", OptionType.EnabledDeveloperModeDynamicCodeTrust },
		{ "Enabled:Secure Setting Policy", OptionType.EnabledSecureSettingPolicy },
		{ "Enabled:Conditional Windows Lockdown Policy", OptionType.EnabledConditionalWindowsLockdownPolicy }
	}.ToFrozenDictionary(StringComparer.Ordinal);

	// Conversion methods for enums.
	internal static OptionType ConvertStringToOptionType(string s)
	{
		return PolicyRuleOptionsActual[s];
	}

	private static PolicyType ConvertStringToPolicyType(string s)
	{
		return s switch
		{
			"Base Policy" => PolicyType.BasePolicy,
			"Supplemental Policy" => PolicyType.SupplementalPolicy,
			"AppID Tagging Policy" => PolicyType.AppIDTaggingPolicy,
			_ => throw new InvalidOperationException("Unknown PolicyType: " + s)
		};
	}

	private static CertEnumType ConvertStringToCertEnumType(string s)
	{
		return s switch
		{
			"TBS" => CertEnumType.TBS,
			"Wellknown" => CertEnumType.Wellknown,
			_ => throw new InvalidOperationException("Unknown CertEnumType: " + s)
		};
	}

	private static RuleTypeType ConvertStringToRuleTypeType(string s)
	{
		return s switch
		{
			"Match" => RuleTypeType.Match,
			"Exclude" => RuleTypeType.Exclude,
			"Attribute" => RuleTypeType.Attribute,
			_ => throw new InvalidOperationException("Unknown RuleTypeType: " + s)
		};
	}

	// Deserialization methods for nested types

	private static Allow DeserializeAllow(XmlElement elem, HashSet<string> IDsCollection)
	{
		Allow allow = new();
		string idValue = elem.GetAttribute("ID");
		allow.ID = string.IsNullOrWhiteSpace(idValue) ? null : idValue;
		string friendlyNameValue = elem.GetAttribute("FriendlyName");
		allow.FriendlyName = string.IsNullOrWhiteSpace(friendlyNameValue) ? null : friendlyNameValue;
		string fileNameValue = elem.GetAttribute("FileName");
		allow.FileName = string.IsNullOrWhiteSpace(fileNameValue) ? null : fileNameValue;
		string internalNameValue = elem.GetAttribute("InternalName");
		allow.InternalName = string.IsNullOrWhiteSpace(internalNameValue) ? null : internalNameValue;
		string fileDescriptionValue = elem.GetAttribute("FileDescription");
		allow.FileDescription = string.IsNullOrWhiteSpace(fileDescriptionValue) ? null : fileDescriptionValue;
		string productNameValue = elem.GetAttribute("ProductName");
		allow.ProductName = string.IsNullOrWhiteSpace(productNameValue) ? null : productNameValue;
		string packageFamilyNameValue = elem.GetAttribute("PackageFamilyName");
		allow.PackageFamilyName = string.IsNullOrWhiteSpace(packageFamilyNameValue) ? null : packageFamilyNameValue;
		string packageVersionValue = elem.GetAttribute("PackageVersion");
		allow.PackageVersion = string.IsNullOrWhiteSpace(packageVersionValue) ? null : packageVersionValue;
		string minimumFileVersionValue = elem.GetAttribute("MinimumFileVersion");
		allow.MinimumFileVersion = string.IsNullOrWhiteSpace(minimumFileVersionValue) ? null : minimumFileVersionValue;
		string maximumFileVersionValue = elem.GetAttribute("MaximumFileVersion");
		allow.MaximumFileVersion = string.IsNullOrWhiteSpace(maximumFileVersionValue) ? null : maximumFileVersionValue;
		string hashValue = elem.GetAttribute("Hash");
		allow.Hash = string.IsNullOrWhiteSpace(hashValue) ? null : ConvertHexStringToByteArray(hashValue);
		string appIDsValue = elem.GetAttribute("AppIDs");
		allow.AppIDs = string.IsNullOrWhiteSpace(appIDsValue) ? null : appIDsValue;
		string filePathValue = elem.GetAttribute("FilePath");
		allow.FilePath = string.IsNullOrWhiteSpace(filePathValue) ? null : filePathValue;

		if (allow.ID is null)
		{
			throw new InvalidOperationException(GlobalVars.GetStr("AllowRuleNoIDValidationError"));
		}

		if (!IDsCollection.Add(allow.ID))
		{
			throw new InvalidOperationException($"{GlobalVars.GetStr("AllowRuleDupIDValidationError")}: {allow.ID}");
		}

		bool HashExists = allow.Hash is not null;

		bool APropertyExists = allow.FileName is not null
						 || allow.PackageFamilyName is not null
						 || allow.PackageVersion is not null
						 || allow.InternalName is not null
						 || allow.ProductName is not null
						 || allow.MinimumFileVersion is not null
						 || allow.MaximumFileVersion is not null
						 || allow.FileDescription is not null
						 || allow.FilePath is not null;

		bool NoPropertyExists = allow.FileName is null
						&& allow.FileDescription is null
						&& allow.PackageFamilyName is null
						&& allow.InternalName is null
						&& allow.ProductName is null
						&& allow.FilePath is null;

		if (HashExists)
		{
			if (APropertyExists)
			{
				throw new InvalidOperationException($"The Allow rule with the ID {allow.ID} has Hash property but also has other file properties, making it invalid.");
			}
		}
		else if (NoPropertyExists)
		{
			throw new InvalidOperationException($"The Allow rule with the ID {allow.ID} neither has Hash nor does it have any other file properties, making it invalid.");
		}

		ValidateVersionRange(allow.MinimumFileVersion, allow.MaximumFileVersion, allow.ID);

		return allow;
	}

	private static Deny DeserializeDeny(XmlElement elem, HashSet<string> IDsCollection)
	{
		Deny deny = new();
		string idValue = elem.GetAttribute("ID");
		deny.ID = string.IsNullOrWhiteSpace(idValue) ? null : idValue;
		string friendlyNameValue = elem.GetAttribute("FriendlyName");
		deny.FriendlyName = string.IsNullOrWhiteSpace(friendlyNameValue) ? null : friendlyNameValue;
		string fileNameValue = elem.GetAttribute("FileName");
		deny.FileName = string.IsNullOrWhiteSpace(fileNameValue) ? null : fileNameValue;
		string internalNameValue = elem.GetAttribute("InternalName");
		deny.InternalName = string.IsNullOrWhiteSpace(internalNameValue) ? null : internalNameValue;
		string fileDescriptionValue = elem.GetAttribute("FileDescription");
		deny.FileDescription = string.IsNullOrWhiteSpace(fileDescriptionValue) ? null : fileDescriptionValue;
		string productNameValue = elem.GetAttribute("ProductName");
		deny.ProductName = string.IsNullOrWhiteSpace(productNameValue) ? null : productNameValue;
		string packageFamilyNameValue = elem.GetAttribute("PackageFamilyName");
		deny.PackageFamilyName = string.IsNullOrWhiteSpace(packageFamilyNameValue) ? null : packageFamilyNameValue;
		string packageVersionValue = elem.GetAttribute("PackageVersion");
		deny.PackageVersion = string.IsNullOrWhiteSpace(packageVersionValue) ? null : packageVersionValue;
		string minimumFileVersionValue = elem.GetAttribute("MinimumFileVersion");
		deny.MinimumFileVersion = string.IsNullOrWhiteSpace(minimumFileVersionValue) ? null : minimumFileVersionValue;
		string maximumFileVersionValue = elem.GetAttribute("MaximumFileVersion");
		deny.MaximumFileVersion = string.IsNullOrWhiteSpace(maximumFileVersionValue) ? null : maximumFileVersionValue;
		string hashValue = elem.GetAttribute("Hash");
		deny.Hash = string.IsNullOrWhiteSpace(hashValue) ? null : ConvertHexStringToByteArray(hashValue);
		string appIDsValue = elem.GetAttribute("AppIDs");
		deny.AppIDs = string.IsNullOrWhiteSpace(appIDsValue) ? null : appIDsValue;
		string filePathValue = elem.GetAttribute("FilePath");
		deny.FilePath = string.IsNullOrWhiteSpace(filePathValue) ? null : filePathValue;

		if (deny.ID is null)
		{
			throw new InvalidOperationException(
				GlobalVars.GetStr("DenyRuleNoIDValidationError"));
		}

		if (!IDsCollection.Add(deny.ID))
		{
			throw new InvalidOperationException(string.Format(
				GlobalVars.GetStr("DenyRuleDupIDValidationError"),
				deny.ID));
		}

		bool HashExists = deny.Hash is not null;

		bool APropertyExists = deny.FileName is not null
							 || deny.FileDescription is not null
							 || deny.PackageFamilyName is not null
							 || deny.InternalName is not null
							 || deny.ProductName is not null
							 || deny.PackageVersion is not null
							 || deny.MinimumFileVersion is not null
							 || deny.MaximumFileVersion is not null
							 || deny.FilePath is not null;

		bool NoPropertyExists = deny.FileName is null
							&& deny.PackageFamilyName is null
							&& deny.FileDescription is null
							&& deny.InternalName is null
							&& deny.ProductName is null
							&& deny.FilePath is null;

		if (HashExists)
		{
			if (APropertyExists)
			{
				throw new InvalidOperationException(string.Format(
					GlobalVars.GetStr("DenyRuleHashWithOtherPropsError"),
					deny.ID));
			}
		}
		else if (NoPropertyExists)
		{
			throw new InvalidOperationException(string.Format(
				GlobalVars.GetStr("DenyRuleNoPropsError"),
				deny.ID));
		}

		ValidateVersionRange(deny.MinimumFileVersion, deny.MaximumFileVersion, deny.ID);

		return deny;
	}

	private static FileAttrib DeserializeFileAttrib(XmlElement elem, HashSet<string> IDsCollection)
	{
		FileAttrib fa = new();
		string idValue = elem.GetAttribute("ID");
		fa.ID = string.IsNullOrWhiteSpace(idValue) ? null : idValue;
		string friendlyNameValue = elem.GetAttribute("FriendlyName");
		fa.FriendlyName = string.IsNullOrWhiteSpace(friendlyNameValue) ? null : friendlyNameValue;
		string fileNameValue = elem.GetAttribute("FileName");
		fa.FileName = string.IsNullOrWhiteSpace(fileNameValue) ? null : fileNameValue;
		string internalNameValue = elem.GetAttribute("InternalName");
		fa.InternalName = string.IsNullOrWhiteSpace(internalNameValue) ? null : internalNameValue;
		string fileDescriptionValue = elem.GetAttribute("FileDescription");
		fa.FileDescription = string.IsNullOrWhiteSpace(fileDescriptionValue) ? null : fileDescriptionValue;
		string productNameValue = elem.GetAttribute("ProductName");
		fa.ProductName = string.IsNullOrWhiteSpace(productNameValue) ? null : productNameValue;
		string packageFamilyNameValue = elem.GetAttribute("PackageFamilyName");
		fa.PackageFamilyName = string.IsNullOrWhiteSpace(packageFamilyNameValue) ? null : packageFamilyNameValue;
		string packageVersionValue = elem.GetAttribute("PackageVersion");
		fa.PackageVersion = string.IsNullOrWhiteSpace(packageVersionValue) ? null : packageVersionValue;
		string minimumFileVersionValue = elem.GetAttribute("MinimumFileVersion");
		fa.MinimumFileVersion = string.IsNullOrWhiteSpace(minimumFileVersionValue) ? null : minimumFileVersionValue;
		string maximumFileVersionValue = elem.GetAttribute("MaximumFileVersion");
		fa.MaximumFileVersion = string.IsNullOrWhiteSpace(maximumFileVersionValue) ? null : maximumFileVersionValue;
		string hashValue = elem.GetAttribute("Hash");
		fa.Hash = string.IsNullOrWhiteSpace(hashValue) ? null : ConvertHexStringToByteArray(hashValue);
		string appIDsValue = elem.GetAttribute("AppIDs");
		fa.AppIDs = string.IsNullOrWhiteSpace(appIDsValue) ? null : appIDsValue;
		string filePathValue = elem.GetAttribute("FilePath");
		fa.FilePath = string.IsNullOrWhiteSpace(filePathValue) ? null : filePathValue;

		if (fa.ID is null)
		{
			throw new InvalidOperationException(
				GlobalVars.GetStr("FileAttribNoIDValidationError"));
		}

		if (!IDsCollection.Add(fa.ID))
		{
			throw new InvalidOperationException(string.Format(
				GlobalVars.GetStr("FileAttribDupIDValidationError"),
				fa.ID));
		}

		bool HashExists = fa.Hash is not null;

		bool APropertyExists = fa.FileName is not null
							|| fa.FileDescription is not null
							|| fa.PackageFamilyName is not null
							|| fa.MinimumFileVersion is not null
							|| fa.MaximumFileVersion is not null
							|| fa.ProductName is not null
							|| fa.PackageVersion is not null
							|| fa.FilePath is not null
							|| fa.InternalName is not null;

		bool NoPropertyExists = fa.FilePath is null
							&& fa.FileName is null
							&& fa.InternalName is null
							&& fa.FileDescription is null
							&& fa.PackageFamilyName is null
							&& fa.ProductName is null;

		if (HashExists)
		{
			if (APropertyExists)
			{
				throw new InvalidOperationException(string.Format(
					GlobalVars.GetStr("FileAttribHashWithOtherPropsError"),
					fa.ID));
			}
		}
		else if (NoPropertyExists)
		{
			throw new InvalidOperationException(string.Format(
				GlobalVars.GetStr("FileAttribNoPropsError"),
				fa.ID));
		}

		ValidateVersionRange(fa.MinimumFileVersion, fa.MaximumFileVersion, fa.ID);

		return fa;
	}

	private static FileRule DeserializeFileRule(XmlElement elem, HashSet<string> IDsCollection)
	{
		FileRule fr = new();
		string idValue = elem.GetAttribute("ID");
		fr.ID = string.IsNullOrWhiteSpace(idValue) ? null : idValue;
		string friendlyNameValue = elem.GetAttribute("FriendlyName");
		fr.FriendlyName = string.IsNullOrWhiteSpace(friendlyNameValue) ? null : friendlyNameValue;
		string fileNameValue = elem.GetAttribute("FileName");
		fr.FileName = string.IsNullOrWhiteSpace(fileNameValue) ? null : fileNameValue;
		string internalNameValue = elem.GetAttribute("InternalName");
		fr.InternalName = string.IsNullOrWhiteSpace(internalNameValue) ? null : internalNameValue;
		string fileDescriptionValue = elem.GetAttribute("FileDescription");
		fr.FileDescription = string.IsNullOrWhiteSpace(fileDescriptionValue) ? null : fileDescriptionValue;
		string productNameValue = elem.GetAttribute("ProductName");
		fr.ProductName = string.IsNullOrWhiteSpace(productNameValue) ? null : productNameValue;
		string packageFamilyNameValue = elem.GetAttribute("PackageFamilyName");
		fr.PackageFamilyName = string.IsNullOrWhiteSpace(packageFamilyNameValue) ? null : packageFamilyNameValue;
		string packageVersionValue = elem.GetAttribute("PackageVersion");
		fr.PackageVersion = string.IsNullOrWhiteSpace(packageVersionValue) ? null : packageVersionValue;
		string minimumFileVersionValue = elem.GetAttribute("MinimumFileVersion");
		fr.MinimumFileVersion = string.IsNullOrWhiteSpace(minimumFileVersionValue) ? null : minimumFileVersionValue;
		string maximumFileVersionValue = elem.GetAttribute("MaximumFileVersion");
		fr.MaximumFileVersion = string.IsNullOrWhiteSpace(maximumFileVersionValue) ? null : maximumFileVersionValue;
		string hashValue = elem.GetAttribute("Hash");
		fr.Hash = string.IsNullOrWhiteSpace(hashValue) ? null : ConvertHexStringToByteArray(hashValue);
		string appIDsValue = elem.GetAttribute("AppIDs");
		fr.AppIDs = string.IsNullOrWhiteSpace(appIDsValue) ? null : appIDsValue;
		string filePathValue = elem.GetAttribute("FilePath");
		fr.FilePath = string.IsNullOrWhiteSpace(filePathValue) ? null : filePathValue;
		if (elem.HasAttribute("Type"))
			fr.Type = ConvertStringToRuleTypeType(elem.GetAttribute("Type"));

		if (fr.ID is null)
		{
			throw new InvalidOperationException(GlobalVars.GetStr("FileRuleNoIDValidationError"));
		}

		if (!IDsCollection.Add(fr.ID))
		{
			throw new InvalidOperationException($"{GlobalVars.GetStr("FileRuleDupIDValidationError")}: {fr.ID}");
		}

		return fr;
	}

	private static Signer DeserializeSigner(XmlElement elem, HashSet<string> IDsCollection)
	{
		Signer signer = new();
		if (elem.HasAttribute("ID"))
			signer.ID = elem.GetAttribute("ID");

		if (signer.ID is null)
		{
			throw new InvalidOperationException(GlobalVars.GetStr("SignerNoIDValidationError"));
		}

		if (!IDsCollection.Add(signer.ID))
		{
			throw new InvalidOperationException($"{GlobalVars.GetStr("SignerDupIDValidationError")}: {signer.ID}");
		}

		if (elem.HasAttribute("Name"))
			signer.Name = elem.GetAttribute("Name");

		if (elem.HasAttribute("SignTimeAfter"))
		{
			signer.SignTimeAfter = DateTime.Parse(elem.GetAttribute("SignTimeAfter"), null, DateTimeStyles.RoundtripKind);
			signer.SignTimeAfterSpecified = true;
		}

		XmlElement? certRootElem = elem["CertRoot", GlobalVars.SiPolicyNamespace];
		if (certRootElem is not null)
		{
			CertRoot cr = new();
			if (certRootElem.HasAttribute("Type"))
				cr.Type = ConvertStringToCertEnumType(certRootElem.GetAttribute("Type"));
			if (certRootElem.HasAttribute("Value"))
				cr.Value = ConvertHexStringToByteArray(certRootElem.GetAttribute("Value"));

			if (cr.Type is not CertEnumType.TBS and not CertEnumType.Wellknown)
			{
				throw new InvalidOperationException(
					GlobalVars.GetStr("InvalidCertRootTypeError"));
			}

			signer.CertRoot = cr;
		}
		else
		{
			throw new InvalidOperationException(string.Format(
				GlobalVars.GetStr("SignerNoCertRootError"),
				signer.ID));
		}

		XmlNodeList certEkuNodes = elem.GetElementsByTagName("CertEKU", GlobalVars.SiPolicyNamespace);
		if (certEkuNodes.Count > 0)
		{
			List<CertEKU> ekus = [];
			foreach (XmlElement ekuElem in certEkuNodes.OfType<XmlElement>())
			{
				CertEKU certEku = new();
				if (ekuElem.HasAttribute("ID"))
					certEku.ID = ekuElem.GetAttribute("ID");
				ekus.Add(certEku);
			}
			signer.CertEKU = [.. ekus];
		}

		XmlElement? certIssuerElem = elem["CertIssuer", GlobalVars.SiPolicyNamespace];
		if (certIssuerElem is not null)
		{
			CertIssuer ci = new();
			if (certIssuerElem.HasAttribute("Value"))
				ci.Value = certIssuerElem.GetAttribute("Value");
			signer.CertIssuer = ci;
		}

		XmlElement? certPublisherElem = elem["CertPublisher", GlobalVars.SiPolicyNamespace];
		if (certPublisherElem is not null)
		{
			CertPublisher cp = new();
			if (certPublisherElem.HasAttribute("Value"))
				cp.Value = certPublisherElem.GetAttribute("Value");
			signer.CertPublisher = cp;
		}

		XmlElement? certOemIDElem = elem["CertOemID", GlobalVars.SiPolicyNamespace];
		if (certOemIDElem is not null)
		{
			CertOemID co = new();
			if (certOemIDElem.HasAttribute("Value"))
				co.Value = certOemIDElem.GetAttribute("Value");
			signer.CertOemID = co;
		}

		XmlNodeList farNodes = elem.GetElementsByTagName("FileAttribRef", GlobalVars.SiPolicyNamespace);
		if (farNodes.Count > 0)
		{
			List<FileAttribRef> fars = [];
			foreach (XmlElement farElem in farNodes.OfType<XmlElement>())
			{
				FileAttribRef far = new();
				if (farElem.HasAttribute("RuleID"))
					far.RuleID = farElem.GetAttribute("RuleID");
				fars.Add(far);
			}
			signer.FileAttribRef = [.. fars];
		}

		return signer;
	}

	private static SigningScenario DeserializeSigningScenario(XmlElement elem, HashSet<string> IDsCollection)
	{
		SigningScenario scenario = new();
		if (elem.HasAttribute("ID"))
			scenario.ID = elem.GetAttribute("ID");

		if (scenario.ID is null)
		{
			throw new InvalidOperationException(GlobalVars.GetStr("SigningScenarioNoIDValidationError"));
		}

		if (!IDsCollection.Add(scenario.ID))
		{
			throw new InvalidOperationException($"{GlobalVars.GetStr("SigningScenarioDupIDValidationError")}: {scenario.ID}");
		}

		if (elem.HasAttribute("FriendlyName"))
			scenario.FriendlyName = elem.GetAttribute("FriendlyName");

		if (elem.HasAttribute("Value"))
			scenario.Value = byte.Parse(elem.GetAttribute("Value"), CultureInfo.InvariantCulture);
		if (scenario.Value == 0)
		{
			throw new InvalidOperationException($"The SigningScenario with the ID {scenario.ID} has a value of 0, making it invalid.");
		}

		if (elem.HasAttribute("InheritedScenarios"))
			scenario.InheritedScenarios = elem.GetAttribute("InheritedScenarios");
		if (elem.HasAttribute("MinimumHashAlgorithm"))
		{
			scenario.MinimumHashAlgorithm = ushort.Parse(elem.GetAttribute("MinimumHashAlgorithm"), CultureInfo.InvariantCulture);
			scenario.MinimumHashAlgorithmSpecified = true;
		}

		// Make sure it exists even empty - Without a ProductSigners in a SigningScenario it would be invalid.
		scenario.ProductSigners = new ProductSigners();
		XmlElement? prodSignersElem = elem["ProductSigners", GlobalVars.SiPolicyNamespace];
		if (prodSignersElem is not null)
			scenario.ProductSigners = DeserializeProductSigners(prodSignersElem);

		XmlElement? testSignersElem = elem["TestSigners", GlobalVars.SiPolicyNamespace];
		if (testSignersElem is not null)
			scenario.TestSigners = DeserializeTestSigners(testSignersElem);

		XmlElement? testSigningSignersElem = elem["TestSigningSigners", GlobalVars.SiPolicyNamespace];
		if (testSigningSignersElem is not null)
			scenario.TestSigningSigners = DeserializeTestSigningSigners(testSigningSignersElem);

		XmlElement? appIDTagsElem = elem["AppIDTags", GlobalVars.SiPolicyNamespace];
		if (appIDTagsElem is not null)
		{
			if (scenario.Value != 12)
			{
				throw new InvalidOperationException("AppIDTags were found in a SigningScenario that is not User-Mode, they only belong to the User-Mode SigningScenario with the value 12 at the moment.");
			}

			scenario.AppIDTags = DeserializeAppIDTags(appIDTagsElem);
		}

		return scenario;
	}

	private static ProductSigners DeserializeProductSigners(XmlElement elem)
	{
		ProductSigners ps = new();
		XmlElement? allowedElem = elem["AllowedSigners", GlobalVars.SiPolicyNamespace];
		if (allowedElem is not null)
		{
			AllowedSigners allowed = new();
			if (allowedElem.HasAttribute("Workaround"))
				allowed.Workaround = allowedElem.GetAttribute("Workaround");
			List<AllowedSigner> asList = [];
			foreach (XmlElement aSignerElem in allowedElem.GetElementsByTagName("AllowedSigner"))
			{
				AllowedSigner aSigner = new();
				if (aSignerElem.HasAttribute("SignerId"))
					aSigner.SignerId = aSignerElem.GetAttribute("SignerId");
				XmlNodeList edrNodes = aSignerElem.GetElementsByTagName("ExceptDenyRule", GlobalVars.SiPolicyNamespace);
				if (edrNodes.Count > 0)
				{
					List<ExceptDenyRule> rules = [];
					foreach (XmlElement ruleElem in edrNodes.OfType<XmlElement>())
					{
						ExceptDenyRule rule = new();
						if (ruleElem.HasAttribute("DenyRuleID"))
							rule.DenyRuleID = ruleElem.GetAttribute("DenyRuleID");
						rules.Add(rule);
					}
					aSigner.ExceptDenyRule = [.. rules];
				}
				asList.Add(aSigner);
			}
			allowed.AllowedSigner = [.. asList];
			ps.AllowedSigners = allowed;
		}
		XmlElement? deniedElem = elem["DeniedSigners", GlobalVars.SiPolicyNamespace];
		if (deniedElem is not null)
		{
			DeniedSigners denied = new();
			if (deniedElem.HasAttribute("Workaround"))
				denied.Workaround = deniedElem.GetAttribute("Workaround");
			List<DeniedSigner> dsList = [];
			foreach (XmlElement dSignerElem in deniedElem.GetElementsByTagName("DeniedSigner"))
			{
				DeniedSigner dSigner = new();
				if (dSignerElem.HasAttribute("SignerId"))
					dSigner.SignerId = dSignerElem.GetAttribute("SignerId");
				XmlNodeList earNodes = dSignerElem.GetElementsByTagName("ExceptAllowRule", GlobalVars.SiPolicyNamespace);
				if (earNodes.Count > 0)
				{
					List<ExceptAllowRule> rules = [];
					foreach (XmlElement ruleElem in earNodes.OfType<XmlElement>())
					{
						ExceptAllowRule rule = new();
						if (ruleElem.HasAttribute("AllowRuleID"))
							rule.AllowRuleID = ruleElem.GetAttribute("AllowRuleID");
						rules.Add(rule);
					}
					dSigner.ExceptAllowRule = [.. rules];
				}
				dsList.Add(dSigner);
			}
			denied.DeniedSigner = [.. dsList];
			ps.DeniedSigners = denied;
		}
		XmlElement? fileRulesRefElem = elem["FileRulesRef", GlobalVars.SiPolicyNamespace];
		if (fileRulesRefElem is not null)
		{
			FileRulesRef frr = new();
			if (fileRulesRefElem.HasAttribute("Workaround"))
				frr.Workaround = fileRulesRefElem.GetAttribute("Workaround");
			List<FileRuleRef> frrList = [];
			foreach (XmlElement frElem in fileRulesRefElem.GetElementsByTagName("FileRuleRef"))
			{
				FileRuleRef frRef = new();
				if (frElem.HasAttribute("RuleID"))
					frRef.RuleID = frElem.GetAttribute("RuleID");
				frrList.Add(frRef);
			}
			frr.FileRuleRef = [.. frrList];
			ps.FileRulesRef = frr;
		}
		return ps;
	}

	private static TestSigners DeserializeTestSigners(XmlElement elem)
	{
		TestSigners ts = new();
		XmlElement? allowedElem = elem["AllowedSigners", GlobalVars.SiPolicyNamespace];
		if (allowedElem is not null)
		{
			AllowedSigners allowed = new();
			if (allowedElem.HasAttribute("Workaround"))
				allowed.Workaround = allowedElem.GetAttribute("Workaround");
			List<AllowedSigner> asList = [];
			foreach (XmlElement aSignerElem in allowedElem.GetElementsByTagName("AllowedSigner"))
			{
				AllowedSigner aSigner = new();
				if (aSignerElem.HasAttribute("SignerId"))
					aSigner.SignerId = aSignerElem.GetAttribute("SignerId");
				XmlNodeList edrNodes = aSignerElem.GetElementsByTagName("ExceptDenyRule", GlobalVars.SiPolicyNamespace);
				if (edrNodes.Count > 0)
				{
					List<ExceptDenyRule> rules = [];
					foreach (XmlElement ruleElem in edrNodes.OfType<XmlElement>())
					{
						ExceptDenyRule rule = new();
						if (ruleElem.HasAttribute("DenyRuleID"))
							rule.DenyRuleID = ruleElem.GetAttribute("DenyRuleID");
						rules.Add(rule);
					}
					aSigner.ExceptDenyRule = [.. rules];
				}
				asList.Add(aSigner);
			}
			allowed.AllowedSigner = [.. asList];
			ts.AllowedSigners = allowed;
		}
		XmlElement? deniedElem = elem["DeniedSigners", GlobalVars.SiPolicyNamespace];
		if (deniedElem is not null)
		{
			DeniedSigners denied = new();
			if (deniedElem.HasAttribute("Workaround"))
				denied.Workaround = deniedElem.GetAttribute("Workaround");
			List<DeniedSigner> dsList = [];
			foreach (XmlElement dSignerElem in deniedElem.GetElementsByTagName("DeniedSigner"))
			{
				DeniedSigner dSigner = new();
				if (dSignerElem.HasAttribute("SignerId"))
					dSigner.SignerId = dSignerElem.GetAttribute("SignerId");
				XmlNodeList earNodes = dSignerElem.GetElementsByTagName("ExceptAllowRule", GlobalVars.SiPolicyNamespace);
				if (earNodes.Count > 0)
				{
					List<ExceptAllowRule> rules = [];
					foreach (XmlElement ruleElem in earNodes.OfType<XmlElement>())
					{
						ExceptAllowRule rule = new();
						if (ruleElem.HasAttribute("AllowRuleID"))
							rule.AllowRuleID = ruleElem.GetAttribute("AllowRuleID");
						rules.Add(rule);
					}
					dSigner.ExceptAllowRule = [.. rules];
				}
				dsList.Add(dSigner);
			}
			denied.DeniedSigner = [.. dsList];
			ts.DeniedSigners = denied;
		}
		XmlElement? fileRulesRefElem = elem["FileRulesRef", GlobalVars.SiPolicyNamespace];
		if (fileRulesRefElem is not null)
		{
			FileRulesRef frr = new();
			if (fileRulesRefElem.HasAttribute("Workaround"))
				frr.Workaround = fileRulesRefElem.GetAttribute("Workaround");
			List<FileRuleRef> frrList = [];
			foreach (XmlElement frElem in fileRulesRefElem.GetElementsByTagName("FileRuleRef"))
			{
				FileRuleRef frRef = new();
				if (frElem.HasAttribute("RuleID"))
					frRef.RuleID = frElem.GetAttribute("RuleID");
				frrList.Add(frRef);
			}
			frr.FileRuleRef = [.. frrList];
			ts.FileRulesRef = frr;
		}
		return ts;
	}

	private static TestSigningSigners DeserializeTestSigningSigners(XmlElement elem)
	{
		TestSigningSigners tss = new();
		XmlElement? allowedElem = elem["AllowedSigners", GlobalVars.SiPolicyNamespace];
		if (allowedElem is not null)
		{
			AllowedSigners allowed = new();
			if (allowedElem.HasAttribute("Workaround"))
				allowed.Workaround = allowedElem.GetAttribute("Workaround");
			List<AllowedSigner> asList = [];
			foreach (XmlElement aSignerElem in allowedElem.GetElementsByTagName("AllowedSigner"))
			{
				AllowedSigner aSigner = new();
				if (aSignerElem.HasAttribute("SignerId"))
					aSigner.SignerId = aSignerElem.GetAttribute("SignerId");
				XmlNodeList edrNodes = aSignerElem.GetElementsByTagName("ExceptDenyRule", GlobalVars.SiPolicyNamespace);
				if (edrNodes.Count > 0)
				{
					List<ExceptDenyRule> rules = [];
					foreach (XmlElement ruleElem in edrNodes.OfType<XmlElement>())
					{
						ExceptDenyRule rule = new();
						if (ruleElem.HasAttribute("DenyRuleID"))
							rule.DenyRuleID = ruleElem.GetAttribute("DenyRuleID");
						rules.Add(rule);
					}
					aSigner.ExceptDenyRule = [.. rules];
				}
				asList.Add(aSigner);
			}
			allowed.AllowedSigner = [.. asList];
			tss.AllowedSigners = allowed;
		}
		XmlElement? deniedElem = elem["DeniedSigners", GlobalVars.SiPolicyNamespace];
		if (deniedElem is not null)
		{
			DeniedSigners denied = new();
			if (deniedElem.HasAttribute("Workaround"))
				denied.Workaround = deniedElem.GetAttribute("Workaround");
			List<DeniedSigner> dsList = [];
			foreach (XmlElement dSignerElem in deniedElem.GetElementsByTagName("DeniedSigner"))
			{
				DeniedSigner dSigner = new();
				if (dSignerElem.HasAttribute("SignerId"))
					dSigner.SignerId = dSignerElem.GetAttribute("SignerId");
				XmlNodeList earNodes = dSignerElem.GetElementsByTagName("ExceptAllowRule", GlobalVars.SiPolicyNamespace);
				if (earNodes.Count > 0)
				{
					List<ExceptAllowRule> rules = [];
					foreach (XmlElement ruleElem in earNodes.OfType<XmlElement>())
					{
						ExceptAllowRule rule = new();
						if (ruleElem.HasAttribute("AllowRuleID"))
							rule.AllowRuleID = ruleElem.GetAttribute("AllowRuleID");
						rules.Add(rule);
					}
					dSigner.ExceptAllowRule = [.. rules];
				}
				dsList.Add(dSigner);
			}
			denied.DeniedSigner = [.. dsList];
			tss.DeniedSigners = denied;
		}
		XmlElement? fileRulesRefElem = elem["FileRulesRef", GlobalVars.SiPolicyNamespace];
		if (fileRulesRefElem is not null)
		{
			FileRulesRef frr = new();
			if (fileRulesRefElem.HasAttribute("Workaround"))
				frr.Workaround = fileRulesRefElem.GetAttribute("Workaround");
			List<FileRuleRef> frrList = [];
			foreach (XmlElement frElem in fileRulesRefElem.GetElementsByTagName("FileRuleRef"))
			{
				FileRuleRef frRef = new();
				if (frElem.HasAttribute("RuleID"))
					frRef.RuleID = frElem.GetAttribute("RuleID");
				frrList.Add(frRef);
			}
			frr.FileRuleRef = [.. frrList];
			tss.FileRulesRef = frr;
		}
		return tss;
	}

	private static AppRoot DeserializeAppRoot(XmlElement elem)
	{
		AppRoot app = new();
		if (elem.HasAttribute("Manifest"))
			app.Manifest = elem.GetAttribute("Manifest");
		List<AppSetting> settings = [];
		foreach (XmlElement settingElem in elem.ChildNodes.OfType<XmlElement>())
		{
			settings.Add(DeserializeAppSetting(settingElem));
		}
		app.Setting = [.. settings];
		return app;
	}

	private static AppSetting DeserializeAppSetting(XmlElement elem)
	{
		AppSetting appSetting = new();
		if (elem.HasAttribute("Name"))
			appSetting.Name = elem.GetAttribute("Name");
		List<string> values = [];
		foreach (XmlElement valueElem in elem.GetElementsByTagName("Value"))
		{
			values.Add(valueElem.InnerText);
		}
		appSetting.Value = [.. values];
		return appSetting;
	}

	private static Setting DeserializeSetting(XmlElement elem)
	{
		Setting setting = new();
		if (elem.HasAttribute("Provider"))
			setting.Provider = elem.GetAttribute("Provider");

		if (elem.HasAttribute("Key"))
			setting.Key = elem.GetAttribute("Key");

		if (elem.HasAttribute("ValueName"))
			setting.ValueName = elem.GetAttribute("ValueName");

		XmlElement? valueElem = elem["Value", GlobalVars.SiPolicyNamespace];
		if (valueElem is not null)
		{
			if (valueElem["Binary", GlobalVars.SiPolicyNamespace] is not null)
			{
				SettingValueType sv = new()
				{
					Item = ConvertHexStringToByteArray(GetElementText(valueElem, "Binary"))
				};
				setting.Value = sv;
			}
			else if (valueElem["Boolean", GlobalVars.SiPolicyNamespace] is not null)
			{
				SettingValueType sv = new()
				{
					Item = bool.Parse(GetElementText(valueElem, "Boolean"))
				};
				setting.Value = sv;
			}
			else if (valueElem["DWord", GlobalVars.SiPolicyNamespace] is not null)
			{
				SettingValueType sv = new()
				{
					Item = uint.Parse(GetElementText(valueElem, "DWord"), CultureInfo.InvariantCulture)
				};
				setting.Value = sv;
			}
			else if (valueElem["String", GlobalVars.SiPolicyNamespace] is not null)
			{
				SettingValueType sv = new()
				{
					Item = GetElementText(valueElem, "String")
				};
				setting.Value = sv;
			}
			else
			{
				throw new InvalidOperationException(
					GlobalVars.GetStr("PolicySettingInvalidValueElementMessage"));
			}
		}

		if (string.IsNullOrEmpty(setting.Key) || string.IsNullOrEmpty(setting.Provider) || string.IsNullOrEmpty(setting.ValueName))
		{
			throw new InvalidOperationException(
				GlobalVars.GetStr("PolicySettingMissingProviderKeyValueNameMessage"));
		}

		return setting;
	}


	private static AppIDTags DeserializeAppIDTags(XmlElement elem)
	{
		AppIDTags appIDTags = new();

		// Read the EnforceDLL attribute if present
		if (elem.HasAttribute("EnforceDLL"))
		{
			string enforceDLLStr = elem.GetAttribute("EnforceDLL");
			if (bool.TryParse(enforceDLLStr, out bool enforceDLL))
			{
				appIDTags.EnforceDLL = enforceDLL;
				appIDTags.EnforceDLLSpecified = true;
			}
		}

		// Parse the AppIDTag child elements
		XmlNodeList appIDTagNodes = elem.GetElementsByTagName("AppIDTag");
		List<AppIDTag> tags = [];
		foreach (XmlElement tagElem in appIDTagNodes)
		{
			AppIDTag tag = new();
			if (tagElem.HasAttribute("Key"))
				tag.Key = tagElem.GetAttribute("Key");
			if (tagElem.HasAttribute("Value"))
				tag.Value = tagElem.GetAttribute("Value");
			tags.Add(tag);
		}
		appIDTags.AppIDTag = [.. tags];

		return appIDTags;
	}

	/// <summary>
	/// If both <paramref name="minimumVersion"/> and <paramref name="maximumVersion"/> are non-null
	/// and non-empty, parses them and ensures minimum ≤ maximum.  Otherwise, returns immediately.
	/// </summary>
	/// <param name="minimumVersion">The lower bound version string (nullable).</param>
	/// <param name="maximumVersion">The upper bound version string (nullable).</param>
	/// <param name="id">An identifier to include in any exception message.</param>
	/// <exception cref="ArgumentException">
	///     Thrown if either version string cannot be parsed when both are provided.
	/// </exception>
	/// <exception cref="ArgumentOutOfRangeException">
	///     Thrown if the parsed minimum version is greater than the parsed maximum version.
	/// </exception>
	private static void ValidateVersionRange(string? minimumVersion, string? maximumVersion, string id)
	{
		// If either version is null or empty, do nothing.
		if (string.IsNullOrEmpty(minimumVersion) || string.IsNullOrEmpty(maximumVersion))
			return;

		// At this point both are non-null/non-empty, so attempt to parse:
		if (!Version.TryParse(minimumVersion, out var minVer))
			throw new ArgumentException(
				string.Format(
					GlobalVars.GetStr("ValidateVersionRangeInvalidMinVersionMessage"),
					id,
					minimumVersion),
				nameof(minimumVersion));

		if (!Version.TryParse(maximumVersion, out var maxVer))
			throw new ArgumentException(
				string.Format(
					GlobalVars.GetStr("ValidateVersionRangeInvalidMaxVersionMessage"),
					id,
					maximumVersion),
				nameof(maximumVersion));

		// Compare and throw if out of order:
		if (minVer > maxVer)
			throw new ArgumentOutOfRangeException(
				nameof(minimumVersion),
				minVer,
				string.Format(
					GlobalVars.GetStr("ValidateVersionRangeMinGreaterThanMaxMessage"),
					id,
					minVer,
					maxVer));
	}

}
