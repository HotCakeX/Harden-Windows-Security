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
		else
		{
			root = Xml is not null
				? Xml.DocumentElement
				   ?? throw new InvalidOperationException(
					   GlobalVars.GetStr("InvalidXmlMissingRootElementValidationError"))
				: throw new InvalidOperationException(
				GlobalVars.GetStr("FilePathOrXmlRequiredMessage"));
		}

		// Friendly Name
		string? friendlyName = root.HasAttribute("FriendlyName") ? root.GetAttribute("FriendlyName") : null;

		// Policy Type - if missing, Base policy type is assigned
		PolicyType policyType = root.HasAttribute("PolicyType") ? ConvertStringToPolicyType(root.GetAttribute("PolicyType")) : PolicyType.BasePolicy;

		// Generate a new GUID
		Guid newRandomGUID = Guid.CreateVersion7();
		// Convert it to string
		string newRandomGUIDString = $"{{{newRandomGUID.ToString().ToUpperInvariant()}}}";

		// Read basic text elements
		string versionText = GetElementText(root, "VersionEx");
		string versionEx = string.IsNullOrEmpty(versionText) ? "1.0.0.0" : versionText;

		string policyIDText = GetElementText(root, "PolicyID");
		string policyID = string.IsNullOrEmpty(policyIDText) ? newRandomGUIDString : policyIDText;

		string basePolicyIDText = GetElementText(root, "BasePolicyID");
		string basePolicyID = string.IsNullOrEmpty(basePolicyIDText) ? newRandomGUIDString : basePolicyIDText;

		string platformIDText = GetElementText(root, "PlatformID");
		string platformID = string.IsNullOrEmpty(platformIDText) ? "{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}" : platformIDText;

		if (string.IsNullOrEmpty(policyID) || string.IsNullOrEmpty(basePolicyID))
		{
			throw new InvalidOperationException(GlobalVars.GetStr("NeedBothIDsValidationError"));
		}

		if (
			(policyType is PolicyType.BasePolicy or PolicyType.AppIDTaggingPolicy && !string.Equals(policyID, basePolicyID, StringComparison.OrdinalIgnoreCase)) ||
			(policyType is PolicyType.SupplementalPolicy && string.Equals(policyID, basePolicyID, StringComparison.OrdinalIgnoreCase))
			)
		{
			throw new InvalidOperationException(GlobalVars.GetStr("IDsMismatchValidationError"));
		}

		// Deserialize Rules
		// Make sure it exists even empty
		List<RuleType> rules = [];
		HashSet<OptionType> policyRules = [];
		XmlElement? rulesElement = root["Rules", GlobalVars.SiPolicyNamespace];
		if (rulesElement is not null)
		{
			foreach (XmlNode node in rulesElement.ChildNodes)
			{
				if (node is XmlElement ruleElem)
				{
					string optionText = GetElementText(ruleElem, "Option");
					OptionType opt = ConvertStringToOptionType(optionText);

					if (!policyRules.Add(opt))
					{
						throw new InvalidOperationException($"{GlobalVars.GetStr("DuplicateRuleOptionValidationError")}: {opt}");
					}

					rules.Add(new RuleType(item: opt));
				}
			}
		}

		if (policyType is PolicyType.SupplementalPolicy && policyRules.Contains(OptionType.EnabledAllowSupplementalPolicies))
		{
			throw new InvalidOperationException(string.Format(GlobalVars.GetStr("SupplementalPolicyWithInvalidRuleOption"), PolicyType.SupplementalPolicy, OptionType.EnabledAllowSupplementalPolicies, PolicyType.BasePolicy));
		}

		SiPolicy policy = new(versionEx, platformID, policyID, basePolicyID, rules, policyType)
		{
			FriendlyName = friendlyName,

			// PolicyTypeID used to be for old version of WDAC policies that didn't have support for Supplemental policies.
			// Now policies have BasePolicyID and PolicyID values instead.
			// A policy cannot have a PolicyTypeID and also have PolicyID or BasePolicyID. In such situations, the value of the PolicyTypeID must be used for both PolicyID and BasePolicyID.
			// These situations only happen when parsing very old WDAC policies.
			PolicyTypeID = null,
			// Deserialize EKUs
			// Make sure it exists even empty
			EKUs = []
		};

		HashSet<string> EKUIDsCol = [];

		XmlElement? ekusElement = root["EKUs", GlobalVars.SiPolicyNamespace];
		if (ekusElement is not null)
		{
			List<EKU> ekus = [];
			foreach (XmlNode node in ekusElement.ChildNodes)
			{
				if (node is XmlElement ekuElem)
				{
					string? ekuFriendlyName = null;
					if (ekuElem.HasAttribute("FriendlyName"))
						ekuFriendlyName = ekuElem.GetAttribute("FriendlyName");

					string id = ekuElem.GetAttribute("ID");

					ekus.Add(new EKU(
						id: id,
						value: ConvertHexStringToByteArray(ekuElem.GetAttribute("Value")),
						friendlyName: ekuFriendlyName
						));

					if (!EKUIDsCol.Add(id))
					{
						throw new InvalidOperationException($"{GlobalVars.GetStr("DuplicateEKUIDsValidationError")}: {id}");
					}
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
			foreach (XmlNode node in fileRulesElement.ChildNodes)
			{
				if (node is XmlElement ruleElem)
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
			}
			policy.FileRules = fileRules;
		}

		// Deserialize Signers
		XmlElement? signersElement = root["Signers", GlobalVars.SiPolicyNamespace];
		if (signersElement is not null)
		{
			HashSet<string> SignersIDsCol = [];
			List<Signer> signers = [];
			foreach (XmlNode node in signersElement.ChildNodes)
			{
				if (node is XmlElement signerElem)
				{
					signers.Add(DeserializeSigner(signerElem, SignersIDsCol));
				}
			}
			policy.Signers = signers;
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
			foreach (XmlNode node in signingScenariosElement.ChildNodes)
			{
				if (node is XmlElement scenarioElem)
				{
					SigningScenario signingScenario = DeserializeSigningScenario(scenarioElem, SigningScenariosIDs);

					if (policy.PolicyType is PolicyType.AppIDTaggingPolicy)
					{
						if (signingScenario.Value != 12)
						{
							throw new InvalidOperationException(string.Format(GlobalVars.GetStr("AppIDTaggingPolicyInvalidSigningScenarioID"), PolicyType.AppIDTaggingPolicy, signingScenario.Value));
						}

						if (signingScenario.AppIDTags is null || signingScenario.AppIDTags.AppIDTag is null || signingScenario.AppIDTags.AppIDTag.Count == 0)
						{
							throw new InvalidOperationException(string.Format(GlobalVars.GetStr("AppIDTaggingPolicyMissingAppIDTags"), PolicyType.AppIDTaggingPolicy));
						}
					}

					scenarios.Add(signingScenario);
				}
			}
			policy.SigningScenarios = scenarios;
		}

		// Deserialize UpdatePolicySigners
		// Make sure it exists even empty
		policy.UpdatePolicySigners = [];
		XmlElement? upsElement = root["UpdatePolicySigners", GlobalVars.SiPolicyNamespace];
		if (upsElement is not null)
		{
			List<UpdatePolicySigner> upsList = [];
			foreach (XmlNode node in upsElement.ChildNodes)
			{
				if (node is XmlElement upsChild)
				{
					upsList.Add(new UpdatePolicySigner(signerID: upsChild.GetAttribute("SignerId")));
				}
			}
			policy.UpdatePolicySigners = upsList;
		}

		// If policy requires to be Signed
		if (!policyRules.Contains(OptionType.EnabledUnsignedSystemIntegrityPolicy) && policy.UpdatePolicySigners.Count == 0)
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
			foreach (XmlNode node in ciElement.ChildNodes)
			{
				if (node is XmlElement ciChild)
				{
					ciList.Add(new CiSigner(signerID: ciChild.GetAttribute("SignerId")));
				}
			}
			policy.CiSigners = ciList;
		}

		// Deserialize HvciOptions
		string hvciText = GetElementText(root, "HvciOptions");
		if (!string.IsNullOrEmpty(hvciText))
		{
			policy.HvciOptions = uint.Parse(hvciText, CultureInfo.InvariantCulture);
		}

		// Deserialize Settings
		// Make sure it exists even empty
		policy.Settings = [];
		XmlElement? settingsElem = root["Settings", GlobalVars.SiPolicyNamespace];
		if (settingsElem is not null)
		{
			List<Setting> settings = [];
			foreach (XmlNode node in settingsElem.ChildNodes)
			{
				if (node is XmlElement settingElem)
				{
					settings.Add(DeserializeSetting(settingElem));
				}
			}
			policy.Settings = settings;
		}

		if (policy.Settings.Count > ushort.MaxValue)
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
			foreach (XmlNode node in macrosElem.ChildNodes)
			{
				if (node is XmlElement macroElem)
				{
					string id = macroElem.GetAttribute("Id");
					string value = macroElem.GetAttribute("Value");
					MacrosMacro macro = new(id, value);
					macros.Add(macro);

					if (!MacrosIDsCol.Add(macro.Id))
					{
						throw new InvalidOperationException($"{GlobalVars.GetStr("DuplicateMacroIDsValidationError")}: {macro.Id}");
					}
				}
			}
			policy.Macros = macros;
		}

		// Deserialize SupplementalPolicySigners
		// Make sure it exists even empty
		policy.SupplementalPolicySigners = [];
		XmlElement? suppElem = root["SupplementalPolicySigners", GlobalVars.SiPolicyNamespace];
		if (suppElem is not null)
		{
			List<SupplementalPolicySigner> spsList = [];
			foreach (XmlNode node in suppElem.ChildNodes)
			{
				if (node is XmlElement spsElem)
				{
					spsList.Add(new SupplementalPolicySigner(signerID: spsElem.GetAttribute("SignerId")));
				}
			}
			policy.SupplementalPolicySigners = spsList;
		}

		if (policy.PolicyType is PolicyType.SupplementalPolicy && policy.SupplementalPolicySigners.Count != 0)
		{
			throw new InvalidOperationException(string.Format(GlobalVars.GetStr("SupplementalPolicyWithSupplementalSigners"), PolicyType.SupplementalPolicy));
		}

		// If it's supposed to be a Signed Base policy
		if (policy.PolicyType is PolicyType.BasePolicy && !policyRules.Contains(OptionType.EnabledUnsignedSystemIntegrityPolicy))
		{
			// If it allows for Supplemental policies but no Supplemental policy Signers have been specified
			if (policyRules.Contains(OptionType.EnabledAllowSupplementalPolicies) && policy.SupplementalPolicySigners.Count == 0)
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
			List<AppRoot> apps = [];
			foreach (XmlNode node in appSettingsElem.ChildNodes)
			{
				if (node is XmlElement appElem)
				{
					apps.Add(DeserializeAppRoot(appElem));
				}
			}
			policy.AppSettings = new(app: apps);
		}

		return policy;
	}

	// Helper to get the inner text of an element.
	private static string GetElementText(XmlElement parent, string localName)
	{
		XmlElement? elem = parent[localName, GlobalVars.SiPolicyNamespace];
		return elem is not null ? elem.InnerText : string.Empty;
	}

	// Convert a hex string (without delimiters) to a ReadOnlyMemory<byte>.
	private static ReadOnlyMemory<byte> ConvertHexStringToByteArray(string? hex)
	{
		if (string.IsNullOrEmpty(hex))
			return ReadOnlyMemory<byte>.Empty;

		return Convert.FromHexString(hex);
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
		{ "Enabled:Conditional Windows Lockdown Policy", OptionType.EnabledConditionalWindowsLockdownPolicy },
		{ "Disabled:Default Windows Certificate Remapping", OptionType.DisabledDefaultWindowsCertificateRemapping }
	}.ToFrozenDictionary(StringComparer.Ordinal);

	// Conversion methods for enums.
	internal static OptionType ConvertStringToOptionType(string s) => PolicyRuleOptionsActual[s];

	private static PolicyType ConvertStringToPolicyType(string s) => s switch
	{
		"Base Policy" => PolicyType.BasePolicy,
		"Supplemental Policy" => PolicyType.SupplementalPolicy,
		"AppID Tagging Policy" => PolicyType.AppIDTaggingPolicy,
		_ => throw new InvalidOperationException("Unknown PolicyType: " + s)
	};
	private static CertEnumType ConvertStringToCertEnumType(string s) => s switch
	{
		"TBS" => CertEnumType.TBS,
		"Wellknown" => CertEnumType.Wellknown,
		_ => throw new InvalidOperationException("Unknown CertEnumType: " + s)
	};
	private static RuleTypeType ConvertStringToRuleTypeType(string s) => s switch
	{
		"Match" => RuleTypeType.Match,
		"Exclude" => RuleTypeType.Exclude,
		"Attribute" => RuleTypeType.Attribute,
		_ => throw new InvalidOperationException("Unknown RuleTypeType: " + s)
	};

	// Deserialization methods for nested types

	private static Allow DeserializeAllow(XmlElement elem, HashSet<string> IDsCollection)
	{
		Allow allow = new(id: elem.GetAttribute("ID"));
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

		if (!IDsCollection.Add(allow.ID))
		{
			throw new InvalidOperationException($"{GlobalVars.GetStr("AllowRuleDupIDValidationError")}: {allow.ID}");
		}

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

		if (!allow.Hash.IsEmpty)
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
		Deny deny = new(id: elem.GetAttribute("ID"));
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

		if (!IDsCollection.Add(deny.ID))
		{
			throw new InvalidOperationException(string.Format(
				GlobalVars.GetStr("DenyRuleDupIDValidationError"),
				deny.ID));
		}

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

		if (!deny.Hash.IsEmpty)
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
		FileAttrib fa = new(id: elem.GetAttribute("ID"));
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

		if (!IDsCollection.Add(fa.ID))
		{
			throw new InvalidOperationException(string.Format(
				GlobalVars.GetStr("FileAttribDupIDValidationError"),
				fa.ID));
		}

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

		if (!fa.Hash.IsEmpty)
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
		FileRule fr = new(id: elem.GetAttribute("ID"), type: ConvertStringToRuleTypeType(elem.GetAttribute("Type")));
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

		if (!IDsCollection.Add(fr.ID))
		{
			throw new InvalidOperationException($"{GlobalVars.GetStr("FileRuleDupIDValidationError")}: {fr.ID}");
		}

		return fr;
	}

	private static Signer DeserializeSigner(XmlElement elem, HashSet<string> IDsCollection)
	{
		// Retrieve ID
		string id = elem.GetAttribute("ID");

		// Check duplicate ID
		if (!IDsCollection.Add(id))
			throw new InvalidOperationException($"{GlobalVars.GetStr("SignerDupIDValidationError")}: {id}");

		// Retrieve Name
		string name = string.Empty;
		if (elem.HasAttribute("Name"))
			name = elem.GetAttribute("Name");

		// Retrieve CertRoot
		XmlElement certRootElem = elem["CertRoot", GlobalVars.SiPolicyNamespace] ?? throw new InvalidOperationException(
			string.Format(GlobalVars.GetStr("SignerNoCertRootError"), id));

		CertRoot certRoot = new(
				type: ConvertStringToCertEnumType(certRootElem.GetAttribute("Type")),
				value: ConvertHexStringToByteArray(certRootElem.GetAttribute("Value")));

		Signer signer = new(id, name, certRoot);

		if (elem.HasAttribute("SignTimeAfter"))
		{
			signer.SignTimeAfter = DateTime.Parse(elem.GetAttribute("SignTimeAfter"), null, DateTimeStyles.RoundtripKind);
		}

		XmlNodeList certEkuNodes = elem.GetElementsByTagName("CertEKU", GlobalVars.SiPolicyNamespace);
		if (certEkuNodes.Count > 0)
		{
			List<CertEKU> ekus = [];
			foreach (XmlNode node in certEkuNodes)
			{
				if (node is XmlElement ekuElem)
				{
					ekus.Add(new CertEKU(id: ekuElem.GetAttribute("ID")));
				}
			}
			signer.CertEKU = ekus;
		}

		XmlElement? certIssuerElem = elem["CertIssuer", GlobalVars.SiPolicyNamespace];
		if (certIssuerElem is not null)
		{
			signer.CertIssuer = new CertIssuer(value: certIssuerElem.GetAttribute("Value"));
		}

		XmlElement? certPublisherElem = elem["CertPublisher", GlobalVars.SiPolicyNamespace];
		if (certPublisherElem is not null)
		{
			signer.CertPublisher = new CertPublisher(value: certPublisherElem.GetAttribute("Value"));
		}

		XmlElement? certOemIDElem = elem["CertOemID", GlobalVars.SiPolicyNamespace];
		if (certOemIDElem is not null)
		{
			signer.CertOemID = new CertOemID(value: certOemIDElem.GetAttribute("Value"));
		}

		XmlNodeList farNodes = elem.GetElementsByTagName("FileAttribRef", GlobalVars.SiPolicyNamespace);
		if (farNodes.Count > 0)
		{
			List<FileAttribRef> fars = [];
			foreach (XmlNode node in farNodes)
			{
				if (node is XmlElement farElem)
				{
					fars.Add(new FileAttribRef(ruleID: farElem.GetAttribute("RuleID")));
				}
			}
			signer.FileAttribRef = fars;
		}

		return signer;
	}

	private static SigningScenario DeserializeSigningScenario(XmlElement elem, HashSet<string> IDsCollection)
	{
		// Retrieve ID
		string id = elem.GetAttribute("ID");

		// Check for duplicate ID
		if (!IDsCollection.Add(id))
			throw new InvalidOperationException($"{GlobalVars.GetStr("SigningScenarioDupIDValidationError")}: {id}");

		// Retrieve Value
		byte value = byte.Parse(elem.GetAttribute("Value"), CultureInfo.InvariantCulture);

		// Value cannot be 0
		if (value == 0)
			throw new InvalidOperationException($"The SigningScenario with the ID {id} has a value of 0, making it invalid.");

		// Retrieve ProductSigners
		// Default to empty ProductSigners if element is missing
		ProductSigners productSigners = new();
		XmlElement? prodSignersElem = elem["ProductSigners", GlobalVars.SiPolicyNamespace];
		if (prodSignersElem is not null)
		{
			productSigners = DeserializeProductSigners(prodSignersElem);
		}

		// Instantiate SigningScenario
		SigningScenario scenario = new(id, value, productSigners);

		if (elem.HasAttribute("FriendlyName"))
		{
			scenario.FriendlyName = elem.GetAttribute("FriendlyName");
		}

		if (elem.HasAttribute("InheritedScenarios"))
		{
			scenario.InheritedScenarios = elem.GetAttribute("InheritedScenarios");
		}

		if (elem.HasAttribute("MinimumHashAlgorithm"))
		{
			scenario.MinimumHashAlgorithm = ushort.Parse(elem.GetAttribute("MinimumHashAlgorithm"), CultureInfo.InvariantCulture);
		}

		// Deserialize TestSigners
		XmlElement? testSignersElem = elem["TestSigners", GlobalVars.SiPolicyNamespace];
		if (testSignersElem is not null)
		{
			scenario.TestSigners = DeserializeTestSigners(testSignersElem);
		}

		// Deserialize TestSigningSigners
		XmlElement? testSigningSignersElem = elem["TestSigningSigners", GlobalVars.SiPolicyNamespace];
		if (testSigningSignersElem is not null)
		{
			scenario.TestSigningSigners = DeserializeTestSigningSigners(testSigningSignersElem);
		}

		// Deserialize AppIDTags
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
			string? workAround = null;
			if (allowedElem.HasAttribute("Workaround"))
				workAround = allowedElem.GetAttribute("Workaround");
			List<AllowedSigner> asList = [];
			foreach (XmlElement aSignerElem in allowedElem.GetElementsByTagName("AllowedSigner"))
			{
				XmlNodeList edrNodes = aSignerElem.GetElementsByTagName("ExceptDenyRule", GlobalVars.SiPolicyNamespace);
				List<ExceptDenyRule>? rules = null;
				if (edrNodes.Count > 0)
				{
					rules = [];
					foreach (XmlNode node in edrNodes)
					{
						if (node is XmlElement ruleElem)
						{
							rules.Add(new ExceptDenyRule(ruleElem.GetAttribute("DenyRuleID")));
						}
					}
				}
				asList.Add(new AllowedSigner(signerId: aSignerElem.GetAttribute("SignerId"), exceptDenyRule: rules));
			}
			ps.AllowedSigners = new AllowedSigners(allowedSigner: asList) { Workaround = workAround };
		}
		XmlElement? deniedElem = elem["DeniedSigners", GlobalVars.SiPolicyNamespace];
		if (deniedElem is not null)
		{
			string? workAround = null;
			if (deniedElem.HasAttribute("Workaround"))
				workAround = deniedElem.GetAttribute("Workaround");
			List<DeniedSigner> dsList = [];
			foreach (XmlElement dSignerElem in deniedElem.GetElementsByTagName("DeniedSigner"))
			{
				XmlNodeList earNodes = dSignerElem.GetElementsByTagName("ExceptAllowRule", GlobalVars.SiPolicyNamespace);
				List<ExceptAllowRule>? rules = null;
				if (earNodes.Count > 0)
				{
					rules = [];
					foreach (XmlNode node in earNodes)
					{
						if (node is XmlElement ruleElem)
						{
							rules.Add(new ExceptAllowRule(allowRuleID: ruleElem.GetAttribute("AllowRuleID")));
						}
					}
				}
				dsList.Add(new DeniedSigner(signerId: dSignerElem.GetAttribute("SignerId"), exceptAllowRule: rules));
			}
			ps.DeniedSigners = new DeniedSigners(deniedSigner: dsList) { Workaround = workAround };
		}
		XmlElement? fileRulesRefElem = elem["FileRulesRef", GlobalVars.SiPolicyNamespace];
		if (fileRulesRefElem is not null)
		{
			string? workAround = null;
			if (fileRulesRefElem.HasAttribute("Workaround"))
				workAround = fileRulesRefElem.GetAttribute("Workaround");
			List<FileRuleRef> frrList = [];
			foreach (XmlElement frElem in fileRulesRefElem.GetElementsByTagName("FileRuleRef"))
			{
				frrList.Add(new FileRuleRef(ruleID: frElem.GetAttribute("RuleID")));
			}
			ps.FileRulesRef = new FileRulesRef(fileRuleRef: frrList) { Workaround = workAround };
		}
		return ps;
	}

	private static TestSigners DeserializeTestSigners(XmlElement elem)
	{
		TestSigners ts = new();
		XmlElement? allowedElem = elem["AllowedSigners", GlobalVars.SiPolicyNamespace];
		if (allowedElem is not null)
		{
			string? workAround = null;
			if (allowedElem.HasAttribute("Workaround"))
				workAround = allowedElem.GetAttribute("Workaround");
			List<AllowedSigner> asList = [];
			foreach (XmlElement aSignerElem in allowedElem.GetElementsByTagName("AllowedSigner"))
			{
				XmlNodeList edrNodes = aSignerElem.GetElementsByTagName("ExceptDenyRule", GlobalVars.SiPolicyNamespace);
				List<ExceptDenyRule>? rules = null;
				if (edrNodes.Count > 0)
				{
					rules = [];
					foreach (XmlNode node in edrNodes)
					{
						if (node is XmlElement ruleElem)
						{
							rules.Add(new ExceptDenyRule(ruleElem.GetAttribute("DenyRuleID")));
						}
					}
				}
				asList.Add(new AllowedSigner(signerId: aSignerElem.GetAttribute("SignerId"), exceptDenyRule: rules));
			}
			ts.AllowedSigners = new AllowedSigners(allowedSigner: asList) { Workaround = workAround };
		}
		XmlElement? deniedElem = elem["DeniedSigners", GlobalVars.SiPolicyNamespace];
		if (deniedElem is not null)
		{
			string? workAround = null;
			if (deniedElem.HasAttribute("Workaround"))
				workAround = deniedElem.GetAttribute("Workaround");
			List<DeniedSigner> dsList = [];
			foreach (XmlElement dSignerElem in deniedElem.GetElementsByTagName("DeniedSigner"))
			{
				XmlNodeList earNodes = dSignerElem.GetElementsByTagName("ExceptAllowRule", GlobalVars.SiPolicyNamespace);
				List<ExceptAllowRule>? rules = null;
				if (earNodes.Count > 0)
				{
					rules = [];
					foreach (XmlNode node in earNodes)
					{
						if (node is XmlElement ruleElem)
						{
							rules.Add(new ExceptAllowRule(allowRuleID: ruleElem.GetAttribute("AllowRuleID")));
						}
					}
				}
				dsList.Add(new DeniedSigner(signerId: dSignerElem.GetAttribute("SignerId"), exceptAllowRule: rules));
			}
			ts.DeniedSigners = new DeniedSigners(deniedSigner: dsList) { Workaround = workAround };
		}
		XmlElement? fileRulesRefElem = elem["FileRulesRef", GlobalVars.SiPolicyNamespace];
		if (fileRulesRefElem is not null)
		{
			string? workAround = null;
			if (fileRulesRefElem.HasAttribute("Workaround"))
				workAround = fileRulesRefElem.GetAttribute("Workaround");
			List<FileRuleRef> frrList = [];
			foreach (XmlElement frElem in fileRulesRefElem.GetElementsByTagName("FileRuleRef"))
			{
				frrList.Add(new FileRuleRef(ruleID: frElem.GetAttribute("RuleID")));
			}

			ts.FileRulesRef = new FileRulesRef(fileRuleRef: frrList) { Workaround = workAround };
		}
		return ts;
	}

	private static TestSigningSigners DeserializeTestSigningSigners(XmlElement elem)
	{
		TestSigningSigners tss = new();
		XmlElement? allowedElem = elem["AllowedSigners", GlobalVars.SiPolicyNamespace];
		if (allowedElem is not null)
		{
			string? workAround = null;
			if (allowedElem.HasAttribute("Workaround"))
				workAround = allowedElem.GetAttribute("Workaround");
			List<AllowedSigner> asList = [];
			foreach (XmlElement aSignerElem in allowedElem.GetElementsByTagName("AllowedSigner"))
			{
				XmlNodeList edrNodes = aSignerElem.GetElementsByTagName("ExceptDenyRule", GlobalVars.SiPolicyNamespace);
				List<ExceptDenyRule>? rules = null;
				if (edrNodes.Count > 0)
				{
					rules = [];
					foreach (XmlNode node in edrNodes)
					{
						if (node is XmlElement ruleElem)
						{
							rules.Add(new ExceptDenyRule(ruleElem.GetAttribute("DenyRuleID")));
						}
					}
				}
				asList.Add(new AllowedSigner(signerId: aSignerElem.GetAttribute("SignerId"), exceptDenyRule: rules));
			}
			tss.AllowedSigners = new AllowedSigners(allowedSigner: asList) { Workaround = workAround };
		}
		XmlElement? deniedElem = elem["DeniedSigners", GlobalVars.SiPolicyNamespace];
		if (deniedElem is not null)
		{
			string? workAround = null;
			if (deniedElem.HasAttribute("Workaround"))
				workAround = deniedElem.GetAttribute("Workaround");
			List<DeniedSigner> dsList = [];
			foreach (XmlElement dSignerElem in deniedElem.GetElementsByTagName("DeniedSigner"))
			{
				XmlNodeList earNodes = dSignerElem.GetElementsByTagName("ExceptAllowRule", GlobalVars.SiPolicyNamespace);
				List<ExceptAllowRule>? rules = null;
				if (earNodes.Count > 0)
				{
					rules = [];
					foreach (XmlNode node in earNodes)
					{
						if (node is XmlElement ruleElem)
						{
							rules.Add(new ExceptAllowRule(allowRuleID: ruleElem.GetAttribute("AllowRuleID")));
						}
					}
				}
				dsList.Add(new DeniedSigner(signerId: dSignerElem.GetAttribute("SignerId"), exceptAllowRule: rules));
			}
			tss.DeniedSigners = new DeniedSigners(deniedSigner: dsList) { Workaround = workAround };
		}
		XmlElement? fileRulesRefElem = elem["FileRulesRef", GlobalVars.SiPolicyNamespace];
		if (fileRulesRefElem is not null)
		{
			string? workAround = null;
			if (fileRulesRefElem.HasAttribute("Workaround"))
				workAround = fileRulesRefElem.GetAttribute("Workaround");
			List<FileRuleRef> frrList = [];
			foreach (XmlElement frElem in fileRulesRefElem.GetElementsByTagName("FileRuleRef"))
			{
				frrList.Add(new FileRuleRef(ruleID: frElem.GetAttribute("RuleID")));
			}
			tss.FileRulesRef = new FileRulesRef(fileRuleRef: frrList) { Workaround = workAround };
		}
		return tss;
	}

	private static AppRoot DeserializeAppRoot(XmlElement elem)
	{
		string manifest = elem.GetAttribute("Manifest");
		List<AppSetting> settings = [];
		foreach (XmlNode node in elem.ChildNodes)
		{
			if (node is XmlElement settingElem)
			{
				settings.Add(DeserializeAppSetting(settingElem));
			}
		}
		return new(manifest: manifest, setting: settings);
	}

	private static AppSetting DeserializeAppSetting(XmlElement elem)
	{
		string? name = null;
		if (elem.HasAttribute("Name"))
			name = elem.GetAttribute("Name");

		List<string> values = [];
		foreach (XmlElement valueElem in elem.GetElementsByTagName("Value"))
		{
			values.Add(valueElem.InnerText);
		}
		return new AppSetting(name: name, value: values);
	}

	private static Setting DeserializeSetting(XmlElement elem)
	{
		string provider = elem.GetAttribute("Provider");
		string key = elem.GetAttribute("Key");
		string valueName = elem.GetAttribute("ValueName");

		XmlElement valueElem = elem["Value", GlobalVars.SiPolicyNamespace] ?? throw new InvalidOperationException("There is a Setting in the policy that has no Value");

		SettingValueType settingValue = valueElem["Binary", GlobalVars.SiPolicyNamespace] is not null
			? new SettingValueType(
				item: ConvertHexStringToByteArray(GetElementText(valueElem, "Binary"))
			)
			: valueElem["Boolean", GlobalVars.SiPolicyNamespace] is not null
				? new SettingValueType(
				item: bool.Parse(GetElementText(valueElem, "Boolean"))
			)
				: valueElem["DWord", GlobalVars.SiPolicyNamespace] is not null
				? new SettingValueType(
				item: uint.Parse(GetElementText(valueElem, "DWord"), CultureInfo.InvariantCulture)
			)
				: valueElem["String", GlobalVars.SiPolicyNamespace] is not null
				? new SettingValueType(
				item: GetElementText(valueElem, "String")
			)
				: throw new InvalidOperationException(
				GlobalVars.GetStr("PolicySettingInvalidValueElementMessage"));

		return new Setting(settingValue, provider, key, valueName);
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
			}
		}

		// Parse the AppIDTag child elements
		XmlNodeList appIDTagNodes = elem.GetElementsByTagName("AppIDTag");
		List<AppIDTag> tags = [];
		foreach (XmlElement tagElem in appIDTagNodes)
		{
			tags.Add(new AppIDTag(key: tagElem.GetAttribute("Key"), value: tagElem.GetAttribute("Value")));
		}
		appIDTags.AppIDTag = tags;

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
		if (!Version.TryParse(minimumVersion, out Version? minVer))
			throw new ArgumentException(
				string.Format(
					GlobalVars.GetStr("ValidateVersionRangeInvalidMinVersionMessage"),
					id,
					minimumVersion),
				nameof(minimumVersion));

		if (!Version.TryParse(maximumVersion, out Version? maxVer))
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
