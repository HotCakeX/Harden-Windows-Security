using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Xml;
using AppControlManager.Main;
using AppControlManager.Others;

namespace AppControlManager.SiPolicy;

internal static class CustomDeserialization
{

	internal static SiPolicy DeserializeSiPolicy(string? filePath, XmlDocument? Xml)
	{

		XmlElement? root;

		if (!string.IsNullOrEmpty(filePath))
		{
			XmlDocument xmlDoc = new();
			xmlDoc.Load(filePath);
			root = xmlDoc.DocumentElement ?? throw new InvalidOperationException("Invalid XML: Missing root element.");

			// Make sure the policy file is valid
			_ = CiPolicyTest.TestCiPolicy(filePath);
		}
		else if (Xml is not null)
		{
			root = Xml.DocumentElement ?? throw new InvalidOperationException("Invalid XML: Missing root element.");
		}
		else
		{
			throw new InvalidOperationException("file path or XML document must be provided for deserialization");
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

		// Deserialize Rules
		XmlElement? rulesElement = root["Rules", GlobalVars.SiPolicyNamespace];
		if (rulesElement is not null)
		{
			List<RuleType> rules = [];
			foreach (XmlElement ruleElem in rulesElement.ChildNodes.OfType<XmlElement>())
			{
				string optionText = GetElementText(ruleElem, "Option");
				OptionType opt = ConvertStringToOptionType(optionText);
				RuleType rule = new() { Item = opt };
				rules.Add(rule);
			}
			policy.Rules = [.. rules];
		}

		// Deserialize EKUs
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
			}
			policy.EKUs = [.. ekus];
		}

		// Deserialize FileRules
		XmlElement? fileRulesElement = root["FileRules", GlobalVars.SiPolicyNamespace];
		if (fileRulesElement is not null)
		{
			List<object> fileRules = [];
			foreach (XmlElement ruleElem in fileRulesElement.ChildNodes.OfType<XmlElement>())
			{
				switch (ruleElem.LocalName)
				{
					case "Allow":
						fileRules.Add(DeserializeAllow(ruleElem));
						break;
					case "Deny":
						fileRules.Add(DeserializeDeny(ruleElem));
						break;
					case "FileAttrib":
						fileRules.Add(DeserializeFileAttrib(ruleElem));
						break;
					case "FileRule":
						fileRules.Add(DeserializeFileRule(ruleElem));
						break;
					default:
						break;
				}
			}
			policy.FileRules = [.. fileRules];
		}

		// Deserialize Signers
		XmlElement? signersElement = root["Signers", GlobalVars.SiPolicyNamespace];
		if (signersElement is not null)
		{
			List<Signer> signers = [];
			foreach (XmlElement signerElem in signersElement.ChildNodes.OfType<XmlElement>())
			{
				signers.Add(DeserializeSigner(signerElem));
			}
			policy.Signers = [.. signers];
		}

		// Deserialize SigningScenarios
		XmlElement? signingScenariosElement = root["SigningScenarios", GlobalVars.SiPolicyNamespace];
		if (signingScenariosElement is not null)
		{
			List<SigningScenario> scenarios = [];
			foreach (XmlElement scenarioElem in signingScenariosElement.ChildNodes.OfType<XmlElement>())
			{
				scenarios.Add(DeserializeSigningScenario(scenarioElem));
			}
			policy.SigningScenarios = [.. scenarios];
		}

		// Deserialize UpdatePolicySigners
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

		// Deserialize CiSigners
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

		// Deserialize Macros
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
			}
			policy.Macros = [.. macros];
		}

		// Deserialize SupplementalPolicySigners
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


	private static readonly Dictionary<string, OptionType> PolicyRuleOptionsActual = new()
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
	};

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

	private static Allow DeserializeAllow(XmlElement elem)
	{
		Allow allow = new();
		if (elem.HasAttribute("ID"))
			allow.ID = elem.GetAttribute("ID");
		if (elem.HasAttribute("FriendlyName"))
			allow.FriendlyName = elem.GetAttribute("FriendlyName");
		if (elem.HasAttribute("FileName"))
			allow.FileName = elem.GetAttribute("FileName");
		if (elem.HasAttribute("InternalName"))
			allow.InternalName = elem.GetAttribute("InternalName");
		if (elem.HasAttribute("FileDescription"))
			allow.FileDescription = elem.GetAttribute("FileDescription");
		if (elem.HasAttribute("ProductName"))
			allow.ProductName = elem.GetAttribute("ProductName");
		if (elem.HasAttribute("PackageFamilyName"))
			allow.PackageFamilyName = elem.GetAttribute("PackageFamilyName");
		if (elem.HasAttribute("PackageVersion"))
			allow.PackageVersion = elem.GetAttribute("PackageVersion");
		if (elem.HasAttribute("MinimumFileVersion"))
			allow.MinimumFileVersion = elem.GetAttribute("MinimumFileVersion");
		if (elem.HasAttribute("MaximumFileVersion"))
			allow.MaximumFileVersion = elem.GetAttribute("MaximumFileVersion");
		if (elem.HasAttribute("Hash"))
			allow.Hash = ConvertHexStringToByteArray(elem.GetAttribute("Hash"));
		if (elem.HasAttribute("AppIDs"))
			allow.AppIDs = elem.GetAttribute("AppIDs");
		if (elem.HasAttribute("FilePath"))
			allow.FilePath = elem.GetAttribute("FilePath");
		return allow;
	}

	private static Deny DeserializeDeny(XmlElement elem)
	{
		Deny deny = new();
		if (elem.HasAttribute("ID"))
			deny.ID = elem.GetAttribute("ID");
		if (elem.HasAttribute("FriendlyName"))
			deny.FriendlyName = elem.GetAttribute("FriendlyName");
		if (elem.HasAttribute("FileName"))
			deny.FileName = elem.GetAttribute("FileName");
		if (elem.HasAttribute("InternalName"))
			deny.InternalName = elem.GetAttribute("InternalName");
		if (elem.HasAttribute("FileDescription"))
			deny.FileDescription = elem.GetAttribute("FileDescription");
		if (elem.HasAttribute("ProductName"))
			deny.ProductName = elem.GetAttribute("ProductName");
		if (elem.HasAttribute("PackageFamilyName"))
			deny.PackageFamilyName = elem.GetAttribute("PackageFamilyName");
		if (elem.HasAttribute("PackageVersion"))
			deny.PackageVersion = elem.GetAttribute("PackageVersion");
		if (elem.HasAttribute("MinimumFileVersion"))
			deny.MinimumFileVersion = elem.GetAttribute("MinimumFileVersion");
		if (elem.HasAttribute("MaximumFileVersion"))
			deny.MaximumFileVersion = elem.GetAttribute("MaximumFileVersion");
		if (elem.HasAttribute("Hash"))
			deny.Hash = ConvertHexStringToByteArray(elem.GetAttribute("Hash"));
		if (elem.HasAttribute("AppIDs"))
			deny.AppIDs = elem.GetAttribute("AppIDs");
		if (elem.HasAttribute("FilePath"))
			deny.FilePath = elem.GetAttribute("FilePath");
		return deny;
	}

	private static FileAttrib DeserializeFileAttrib(XmlElement elem)
	{
		FileAttrib fa = new();
		if (elem.HasAttribute("ID"))
			fa.ID = elem.GetAttribute("ID");
		if (elem.HasAttribute("FriendlyName"))
			fa.FriendlyName = elem.GetAttribute("FriendlyName");
		if (elem.HasAttribute("FileName"))
			fa.FileName = elem.GetAttribute("FileName");
		if (elem.HasAttribute("InternalName"))
			fa.InternalName = elem.GetAttribute("InternalName");
		if (elem.HasAttribute("FileDescription"))
			fa.FileDescription = elem.GetAttribute("FileDescription");
		if (elem.HasAttribute("ProductName"))
			fa.ProductName = elem.GetAttribute("ProductName");
		if (elem.HasAttribute("PackageFamilyName"))
			fa.PackageFamilyName = elem.GetAttribute("PackageFamilyName");
		if (elem.HasAttribute("PackageVersion"))
			fa.PackageVersion = elem.GetAttribute("PackageVersion");
		if (elem.HasAttribute("MinimumFileVersion"))
			fa.MinimumFileVersion = elem.GetAttribute("MinimumFileVersion");
		if (elem.HasAttribute("MaximumFileVersion"))
			fa.MaximumFileVersion = elem.GetAttribute("MaximumFileVersion");
		if (elem.HasAttribute("Hash"))
			fa.Hash = ConvertHexStringToByteArray(elem.GetAttribute("Hash"));
		if (elem.HasAttribute("AppIDs"))
			fa.AppIDs = elem.GetAttribute("AppIDs");
		if (elem.HasAttribute("FilePath"))
			fa.FilePath = elem.GetAttribute("FilePath");
		return fa;
	}

	private static FileRule DeserializeFileRule(XmlElement elem)
	{
		FileRule fr = new();
		if (elem.HasAttribute("ID"))
			fr.ID = elem.GetAttribute("ID");
		if (elem.HasAttribute("FriendlyName"))
			fr.FriendlyName = elem.GetAttribute("FriendlyName");
		if (elem.HasAttribute("FileName"))
			fr.FileName = elem.GetAttribute("FileName");
		if (elem.HasAttribute("InternalName"))
			fr.InternalName = elem.GetAttribute("InternalName");
		if (elem.HasAttribute("FileDescription"))
			fr.FileDescription = elem.GetAttribute("FileDescription");
		if (elem.HasAttribute("ProductName"))
			fr.ProductName = elem.GetAttribute("ProductName");
		if (elem.HasAttribute("PackageFamilyName"))
			fr.PackageFamilyName = elem.GetAttribute("PackageFamilyName");
		if (elem.HasAttribute("PackageVersion"))
			fr.PackageVersion = elem.GetAttribute("PackageVersion");
		if (elem.HasAttribute("MinimumFileVersion"))
			fr.MinimumFileVersion = elem.GetAttribute("MinimumFileVersion");
		if (elem.HasAttribute("MaximumFileVersion"))
			fr.MaximumFileVersion = elem.GetAttribute("MaximumFileVersion");
		if (elem.HasAttribute("Hash"))
			fr.Hash = ConvertHexStringToByteArray(elem.GetAttribute("Hash"));
		if (elem.HasAttribute("AppIDs"))
			fr.AppIDs = elem.GetAttribute("AppIDs");
		if (elem.HasAttribute("FilePath"))
			fr.FilePath = elem.GetAttribute("FilePath");
		if (elem.HasAttribute("Type"))
			fr.Type = ConvertStringToRuleTypeType(elem.GetAttribute("Type"));
		return fr;
	}

	private static Signer DeserializeSigner(XmlElement elem)
	{
		Signer signer = new();
		if (elem.HasAttribute("ID"))
			signer.ID = elem.GetAttribute("ID");
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
			signer.CertRoot = cr;
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

	private static SigningScenario DeserializeSigningScenario(XmlElement elem)
	{
		SigningScenario scenario = new();
		if (elem.HasAttribute("ID"))
			scenario.ID = elem.GetAttribute("ID");
		if (elem.HasAttribute("FriendlyName"))
			scenario.FriendlyName = elem.GetAttribute("FriendlyName");
		if (elem.HasAttribute("Value"))
			scenario.Value = byte.Parse(elem.GetAttribute("Value"), CultureInfo.InvariantCulture);
		if (elem.HasAttribute("InheritedScenarios"))
			scenario.InheritedScenarios = elem.GetAttribute("InheritedScenarios");
		if (elem.HasAttribute("MinimumHashAlgorithm"))
		{
			scenario.MinimumHashAlgorithm = ushort.Parse(elem.GetAttribute("MinimumHashAlgorithm"), CultureInfo.InvariantCulture);
			scenario.MinimumHashAlgorithmSpecified = true;
		}
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
			scenario.AppIDTags = DeserializeAppIDTags(appIDTagsElem);
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
		var appIDTagNodes = elem.GetElementsByTagName("AppIDTag");
		var tags = new List<AppIDTag>();
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

}
