using System;
using System.Linq;
using System.Xml;

namespace AppControlManager.SiPolicy;

internal static class CustomSerialization
{
	private const string NameSpace = "urn:schemas-microsoft-com:sipolicy";

	internal static XmlDocument CreateXmlFromSiPolicy(SiPolicy policy)
	{
		XmlDocument xmlDoc = new();
		XmlDeclaration xmlDecl = xmlDoc.CreateXmlDeclaration("1.0", "utf-8", null);
		_ = xmlDoc.AppendChild(xmlDecl);

		// Create root element
		XmlElement root = xmlDoc.CreateElement("SiPolicy", NameSpace);
		_ = xmlDoc.AppendChild(root);

		// Set attributes for the root element
		if (!string.IsNullOrEmpty(policy.FriendlyName))
			root.SetAttribute("FriendlyName", policy.FriendlyName);
		if (policy.PolicyTypeSpecified)
			root.SetAttribute("PolicyType", ConvertPolicyType(policy.PolicyType));

		// VersionEx, PolicyID, BasePolicyID, PlatformID
		AppendTextElement(xmlDoc, root, "VersionEx", policy.VersionEx);
		AppendTextElement(xmlDoc, root, "PolicyID", policy.PolicyID);
		AppendTextElement(xmlDoc, root, "BasePolicyID", policy.BasePolicyID);
		AppendTextElement(xmlDoc, root, "PlatformID", policy.PlatformID);

		// Rules
		// Adding this first so if there are no rules, an empty Rules node will exist to satisfy the schema validation
		XmlElement rulesElement = xmlDoc.CreateElement("Rules", NameSpace);
		_ = root.AppendChild(rulesElement);

		if (policy.Rules is { Length: > 0 })
		{
			foreach (RuleType rule in policy.Rules)
			{
				XmlElement ruleElement = xmlDoc.CreateElement("Rule", NameSpace);
				AppendTextElement(xmlDoc, ruleElement, "Option", ConvertOptionType(rule.Item));
				_ = rulesElement.AppendChild(ruleElement);
			}
		}

		// EKUs
		// Adding this first so if there are no EKUs, an empty EKUs node will exist to satisfy the schema validation
		XmlElement ekusElement = xmlDoc.CreateElement("EKUs", NameSpace);
		_ = root.AppendChild(ekusElement);

		if (policy.EKUs is { Length: > 0 })
		{
			foreach (EKU eku in policy.EKUs)
			{
				XmlElement ekuElement = xmlDoc.CreateElement("EKU", NameSpace);
				ekuElement.SetAttribute("ID", eku.ID);

				if (!string.IsNullOrEmpty(eku.FriendlyName))
					ekuElement.SetAttribute("FriendlyName", eku.FriendlyName);

				ekuElement.SetAttribute("Value", ConvertByteArrayToHex(eku.Value));
				_ = ekusElement.AppendChild(ekuElement);
			}
		}

		// FileRules
		XmlElement fileRulesElement = xmlDoc.CreateElement("FileRules", NameSpace);
		_ = root.AppendChild(fileRulesElement);

		if (policy.FileRules is { Length: > 0 })
		{
			// Detect the types of each FileRule
			foreach (object fr in policy.FileRules)
			{
				if (fr is Allow allow)
				{
					AppendAllow(xmlDoc, fileRulesElement, allow);
				}
				else if (fr is Deny deny)
				{
					AppendDeny(xmlDoc, fileRulesElement, deny);
				}
				else if (fr is FileAttrib fileAttrib)
				{
					AppendFileAttrib(xmlDoc, fileRulesElement, fileAttrib);
				}
				else if (fr is FileRule fileRule)
				{
					AppendFileRule(xmlDoc, fileRulesElement, fileRule);
				}
			}
		}

		// Signers
		XmlElement signersElement = xmlDoc.CreateElement("Signers", NameSpace);
		_ = root.AppendChild(signersElement);

		if (policy.Signers is { Length: > 0 })
		{
			foreach (Signer signer in policy.Signers)
			{
				XmlElement signerElement = xmlDoc.CreateElement("Signer", NameSpace);
				signerElement.SetAttribute("ID", signer.ID);
				signerElement.SetAttribute("Name", signer.Name);
				if (signer.SignTimeAfterSpecified)
					signerElement.SetAttribute("SignTimeAfter", signer.SignTimeAfter.ToString("o"));

				// CertRoot
				if (signer.CertRoot is not null)
				{
					XmlElement certRootElement = xmlDoc.CreateElement("CertRoot", NameSpace);
					certRootElement.SetAttribute("Type", signer.CertRoot.Type.ToString());
					certRootElement.SetAttribute("Value", ConvertByteArrayToHex(signer.CertRoot.Value));
					_ = signerElement.AppendChild(certRootElement);
				}

				// CertEKU(s)
				if (signer.CertEKU is { Length: > 0 })
				{
					foreach (CertEKU certEku in signer.CertEKU)
					{
						XmlElement certEkuElement = xmlDoc.CreateElement("CertEKU", NameSpace);
						certEkuElement.SetAttribute("ID", certEku.ID);
						_ = signerElement.AppendChild(certEkuElement);
					}
				}

				// CertIssuer, CertPublisher, CertOemID
				if (signer.CertIssuer is not null)
					AppendAttributeElement(xmlDoc, signerElement, "CertIssuer", "Value", signer.CertIssuer.Value);
				if (signer.CertPublisher is not null)
					AppendAttributeElement(xmlDoc, signerElement, "CertPublisher", "Value", signer.CertPublisher.Value);
				if (signer.CertOemID is not null)
					AppendAttributeElement(xmlDoc, signerElement, "CertOemID", "Value", signer.CertOemID.Value);

				// FileAttribRef(s)
				if (signer.FileAttribRef is { Length: > 0 })
				{
					foreach (FileAttribRef far in signer.FileAttribRef)
					{
						XmlElement farElement = xmlDoc.CreateElement("FileAttribRef", NameSpace);
						farElement.SetAttribute("RuleID", far.RuleID);
						_ = signerElement.AppendChild(farElement);
					}
				}
				_ = signersElement.AppendChild(signerElement);
			}
		}

		// SigningScenarios
		if (policy.SigningScenarios is { Length: > 0 })
		{
			XmlElement signingScenariosElement = xmlDoc.CreateElement("SigningScenarios", NameSpace);
			_ = root.AppendChild(signingScenariosElement);

			foreach (SigningScenario scenario in policy.SigningScenarios)
			{
				XmlElement scenarioElement = xmlDoc.CreateElement("SigningScenario", NameSpace);
				scenarioElement.SetAttribute("Value", scenario.Value.ToString());
				scenarioElement.SetAttribute("ID", scenario.ID);

				if (!string.IsNullOrEmpty(scenario.FriendlyName))
					scenarioElement.SetAttribute("FriendlyName", scenario.FriendlyName);

				if (!string.IsNullOrEmpty(scenario.InheritedScenarios))
					scenarioElement.SetAttribute("InheritedScenarios", scenario.InheritedScenarios);

				if (scenario.MinimumHashAlgorithmSpecified)
					scenarioElement.SetAttribute("MinimumHashAlgorithm", scenario.MinimumHashAlgorithm.ToString());

				// ProductSigners
				if (scenario.ProductSigners is not null)
				{
					XmlElement prodSigners = xmlDoc.CreateElement("ProductSigners", NameSpace);
					AppendProductSigners(xmlDoc, prodSigners, scenario.ProductSigners);
					_ = scenarioElement.AppendChild(prodSigners);
				}
				// TestSigners
				if (scenario.TestSigners is not null)
				{
					XmlElement testSigners = xmlDoc.CreateElement("TestSigners", NameSpace);
					AppendTestSigners(xmlDoc, testSigners, scenario.TestSigners);
					_ = scenarioElement.AppendChild(testSigners);
				}
				// TestSigningSigners
				if (scenario.TestSigningSigners is not null)
				{
					XmlElement testSigningSigners = xmlDoc.CreateElement("TestSigningSigners", NameSpace);
					AppendTestSigningSigners(xmlDoc, testSigningSigners, scenario.TestSigningSigners);
					_ = scenarioElement.AppendChild(testSigningSigners);
				}
				// AppIDTags
				if (scenario.AppIDTags is not null)
				{
					XmlElement appIDTagsElement = xmlDoc.CreateElement("AppIDTags", NameSpace);
					if (scenario.AppIDTags.EnforceDLLSpecified)
						appIDTagsElement.SetAttribute("EnforceDLL", scenario.AppIDTags.EnforceDLL.ToString());
					if (scenario.AppIDTags.AppIDTag is not null)
					{
						foreach (AppIDTag tag in scenario.AppIDTags.AppIDTag)
						{
							XmlElement tagElement = xmlDoc.CreateElement("AppIDTag", NameSpace);
							tagElement.SetAttribute("Key", tag.Key);
							tagElement.SetAttribute("Value", tag.Value);
							_ = appIDTagsElement.AppendChild(tagElement);
						}
					}
					_ = scenarioElement.AppendChild(appIDTagsElement);
				}
				_ = signingScenariosElement.AppendChild(scenarioElement);
			}
		}

		// UpdatePolicySigners
		XmlElement upsElement = xmlDoc.CreateElement("UpdatePolicySigners", NameSpace);
		_ = root.AppendChild(upsElement);

		if (policy.UpdatePolicySigners is { Length: > 0 })
		{
			foreach (UpdatePolicySigner ups in policy.UpdatePolicySigners)
			{
				XmlElement upsChild = xmlDoc.CreateElement("UpdatePolicySigner", NameSpace);
				upsChild.SetAttribute("SignerId", ups.SignerId);
				_ = upsElement.AppendChild(upsChild);
			}
		}

		// CiSigners
		XmlElement ciElement = xmlDoc.CreateElement("CiSigners", NameSpace);
		_ = root.AppendChild(ciElement);

		if (policy.CiSigners is { Length: > 0 })
		{
			foreach (CiSigner ci in policy.CiSigners)
			{
				XmlElement ciSignerElement = xmlDoc.CreateElement("CiSigner", NameSpace);
				ciSignerElement.SetAttribute("SignerId", ci.SignerId);
				_ = ciElement.AppendChild(ciSignerElement);
			}
		}

		// HvciOptions
		if (policy.HvciOptionsSpecified)
			AppendTextElement(xmlDoc, root, "HvciOptions", policy.HvciOptions.ToString());

		// Settings
		if (policy.Settings is { Length: > 0 })
		{
			XmlElement settingsElement = xmlDoc.CreateElement("Settings", NameSpace);
			_ = root.AppendChild(settingsElement);

			foreach (Setting setting in policy.Settings)
			{
				XmlElement settingElement = xmlDoc.CreateElement("Setting", NameSpace);
				settingElement.SetAttribute("Provider", setting.Provider);
				settingElement.SetAttribute("Key", setting.Key);
				settingElement.SetAttribute("ValueName", setting.ValueName);

				if (setting.Value is not null)
				{
					XmlElement valueElement = xmlDoc.CreateElement("Value", NameSpace);
					if (setting.Value.Item is byte[] b)
						AppendTextElement(xmlDoc, valueElement, "Binary", ConvertByteArrayToHex(b));
					else if (setting.Value.Item is bool boolVal)
						AppendTextElement(xmlDoc, valueElement, "Boolean", boolVal.ToString().ToLowerInvariant()); // Somehow the CIP conversion cmdlet doesn't like "True" but "true" is ok
					else if (setting.Value.Item is uint uintVal)
						AppendTextElement(xmlDoc, valueElement, "DWord", uintVal.ToString());
					else if (setting.Value.Item is string s)
						AppendTextElement(xmlDoc, valueElement, "String", s);
					_ = settingElement.AppendChild(valueElement);
				}
				_ = settingsElement.AppendChild(settingElement);
			}
		}

		// Macros
		if (policy.Macros is { Length: > 0 })
		{
			XmlElement macrosElement = xmlDoc.CreateElement("Macros", NameSpace);
			_ = root.AppendChild(macrosElement);
			foreach (MacrosMacro macro in policy.Macros)
			{
				XmlElement macroElement = xmlDoc.CreateElement("Macro", NameSpace);
				macroElement.SetAttribute("Id", macro.Id);
				macroElement.SetAttribute("Value", macro.Value);
				_ = macrosElement.AppendChild(macroElement);
			}
		}

		// Supplemental policy signers
		if (policy.SupplementalPolicySigners is { Length: > 0 })
		{
			XmlElement suppElement = xmlDoc.CreateElement("SupplementalPolicySigners", NameSpace);
			_ = root.AppendChild(suppElement);
			foreach (SupplementalPolicySigner sps in policy.SupplementalPolicySigners)
			{
				XmlElement spsElement = xmlDoc.CreateElement("SupplementalPolicySigner", NameSpace);
				spsElement.SetAttribute("SignerId", sps.SignerId);
				_ = suppElement.AppendChild(spsElement);
			}
		}

		// AppSettings (AppSettingRegion)
		if (policy.AppSettings is not null)
		{
			XmlElement appSettingsElement = xmlDoc.CreateElement("AppSettings", NameSpace);
			_ = root.AppendChild(appSettingsElement);
			if (policy.AppSettings.App is not null)
			{
				foreach (AppRoot app in policy.AppSettings.App)
				{
					XmlElement appElement = xmlDoc.CreateElement("App", NameSpace);
					if (!string.IsNullOrEmpty(app.Manifest))
						appElement.SetAttribute("Manifest", app.Manifest);
					if (app.Setting is { Length: > 0 })
					{
						foreach (AppSetting appSetting in app.Setting)
						{
							XmlElement settingElem = xmlDoc.CreateElement("Setting", NameSpace);
							settingElem.SetAttribute("Name", appSetting.Name);
							if (appSetting.Value is { Length: > 0 })
							{
								foreach (string val in appSetting.Value)
								{
									AppendTextElement(xmlDoc, settingElem, "Value", val);
								}
							}
							_ = appElement.AppendChild(settingElem);
						}
					}
					_ = appSettingsElement.AppendChild(appElement);
				}
			}
		}

		return xmlDoc;
	}

	// Helper for OptionType conversion
	private static string ConvertOptionType(OptionType option)
	{
		return option switch
		{
			OptionType.EnabledUMCI => "Enabled:UMCI",
			OptionType.EnabledBootMenuProtection => "Enabled:Boot Menu Protection",
			OptionType.EnabledIntelligentSecurityGraphAuthorization => "Enabled:Intelligent Security Graph Authorization",
			OptionType.EnabledInvalidateEAsonReboot => "Enabled:Invalidate EAs on Reboot",
			OptionType.RequiredWHQL => "Required:WHQL",
			OptionType.EnabledDeveloperModeDynamicCodeTrust => "Enabled:Developer Mode Dynamic Code Trust",
			OptionType.EnabledAllowSupplementalPolicies => "Enabled:Allow Supplemental Policies",
			OptionType.DisabledRuntimeFilePathRuleProtection => "Disabled:Runtime FilePath Rule Protection",
			OptionType.EnabledRevokedExpiredAsUnsigned => "Enabled:Revoked Expired As Unsigned",
			OptionType.EnabledAuditMode => "Enabled:Audit Mode",
			OptionType.DisabledFlightSigning => "Disabled:Flight Signing",
			OptionType.EnabledInheritDefaultPolicy => "Enabled:Inherit Default Policy",
			OptionType.EnabledUnsignedSystemIntegrityPolicy => "Enabled:Unsigned System Integrity Policy",
			OptionType.EnabledDynamicCodeSecurity => "Enabled:Dynamic Code Security",
			OptionType.RequiredEVSigners => "Required:EV Signers",
			OptionType.EnabledBootAuditOnFailure => "Enabled:Boot Audit On Failure",
			OptionType.EnabledAdvancedBootOptionsMenu => "Enabled:Advanced Boot Options Menu",
			OptionType.DisabledScriptEnforcement => "Disabled:Script Enforcement",
			OptionType.RequiredEnforceStoreApplications => "Required:Enforce Store Applications",
			OptionType.EnabledSecureSettingPolicy => "Enabled:Secure Setting Policy",
			OptionType.EnabledManagedInstaller => "Enabled:Managed Installer",
			OptionType.EnabledUpdatePolicyNoReboot => "Enabled:Update Policy No Reboot",
			OptionType.EnabledConditionalWindowsLockdownPolicy => "Enabled:Conditional Windows Lockdown Policy",
			_ => option.ToString(),
		};
	}

	// Helper for PolicyType conversion
	private static string ConvertPolicyType(PolicyType pt)
	{
		return pt switch
		{
			PolicyType.BasePolicy => "Base Policy",
			PolicyType.SupplementalPolicy => "Supplemental Policy",
			PolicyType.AppIDTaggingPolicy => "AppID Tagging Policy",
			_ => throw new InvalidOperationException("Unknown PolicyType")
		};
	}

	// FileRules Helpers
	private static void AppendAllow(XmlDocument doc, XmlElement parent, Allow allow)
	{
		XmlElement element = doc.CreateElement("Allow", NameSpace);
		if (!string.IsNullOrEmpty(allow.ID)) element.SetAttribute("ID", allow.ID);
		if (!string.IsNullOrEmpty(allow.FriendlyName)) element.SetAttribute("FriendlyName", allow.FriendlyName);
		if (!string.IsNullOrEmpty(allow.FileName)) element.SetAttribute("FileName", allow.FileName);
		if (!string.IsNullOrEmpty(allow.InternalName)) element.SetAttribute("InternalName", allow.InternalName);
		if (!string.IsNullOrEmpty(allow.FileDescription)) element.SetAttribute("FileDescription", allow.FileDescription);
		if (!string.IsNullOrEmpty(allow.ProductName)) element.SetAttribute("ProductName", allow.ProductName);
		if (!string.IsNullOrEmpty(allow.PackageFamilyName)) element.SetAttribute("PackageFamilyName", allow.PackageFamilyName);
		if (!string.IsNullOrEmpty(allow.PackageVersion)) element.SetAttribute("PackageVersion", allow.PackageVersion);
		if (!string.IsNullOrEmpty(allow.MinimumFileVersion)) element.SetAttribute("MinimumFileVersion", allow.MinimumFileVersion);
		if (!string.IsNullOrEmpty(allow.MaximumFileVersion)) element.SetAttribute("MaximumFileVersion", allow.MaximumFileVersion);
		if (allow.Hash is { Length: > 0 }) element.SetAttribute("Hash", ConvertByteArrayToHex(allow.Hash));
		if (!string.IsNullOrEmpty(allow.AppIDs)) element.SetAttribute("AppIDs", allow.AppIDs);
		if (!string.IsNullOrEmpty(allow.FilePath)) element.SetAttribute("FilePath", allow.FilePath);
		_ = parent.AppendChild(element);
	}

	private static void AppendDeny(XmlDocument doc, XmlElement parent, Deny deny)
	{
		XmlElement element = doc.CreateElement("Deny", NameSpace);
		if (!string.IsNullOrEmpty(deny.ID)) element.SetAttribute("ID", deny.ID);
		if (!string.IsNullOrEmpty(deny.FriendlyName)) element.SetAttribute("FriendlyName", deny.FriendlyName);
		if (!string.IsNullOrEmpty(deny.FileName)) element.SetAttribute("FileName", deny.FileName);
		if (!string.IsNullOrEmpty(deny.InternalName)) element.SetAttribute("InternalName", deny.InternalName);
		if (!string.IsNullOrEmpty(deny.FileDescription)) element.SetAttribute("FileDescription", deny.FileDescription);
		if (!string.IsNullOrEmpty(deny.ProductName)) element.SetAttribute("ProductName", deny.ProductName);
		if (!string.IsNullOrEmpty(deny.PackageFamilyName)) element.SetAttribute("PackageFamilyName", deny.PackageFamilyName);
		if (!string.IsNullOrEmpty(deny.PackageVersion)) element.SetAttribute("PackageVersion", deny.PackageVersion);
		if (!string.IsNullOrEmpty(deny.MinimumFileVersion)) element.SetAttribute("MinimumFileVersion", deny.MinimumFileVersion);
		if (!string.IsNullOrEmpty(deny.MaximumFileVersion)) element.SetAttribute("MaximumFileVersion", deny.MaximumFileVersion);
		if (deny.Hash is { Length: > 0 }) element.SetAttribute("Hash", ConvertByteArrayToHex(deny.Hash));
		if (!string.IsNullOrEmpty(deny.AppIDs)) element.SetAttribute("AppIDs", deny.AppIDs);
		if (!string.IsNullOrEmpty(deny.FilePath)) element.SetAttribute("FilePath", deny.FilePath);
		_ = parent.AppendChild(element);
	}

	private static void AppendFileAttrib(XmlDocument doc, XmlElement parent, FileAttrib fileAttrib)
	{
		XmlElement element = doc.CreateElement("FileAttrib", NameSpace);
		if (!string.IsNullOrEmpty(fileAttrib.ID)) element.SetAttribute("ID", fileAttrib.ID);
		if (!string.IsNullOrEmpty(fileAttrib.FriendlyName)) element.SetAttribute("FriendlyName", fileAttrib.FriendlyName);
		if (!string.IsNullOrEmpty(fileAttrib.FileName)) element.SetAttribute("FileName", fileAttrib.FileName);
		if (!string.IsNullOrEmpty(fileAttrib.InternalName)) element.SetAttribute("InternalName", fileAttrib.InternalName);
		if (!string.IsNullOrEmpty(fileAttrib.FileDescription)) element.SetAttribute("FileDescription", fileAttrib.FileDescription);
		if (!string.IsNullOrEmpty(fileAttrib.ProductName)) element.SetAttribute("ProductName", fileAttrib.ProductName);
		if (!string.IsNullOrEmpty(fileAttrib.PackageFamilyName)) element.SetAttribute("PackageFamilyName", fileAttrib.PackageFamilyName);
		if (!string.IsNullOrEmpty(fileAttrib.PackageVersion)) element.SetAttribute("PackageVersion", fileAttrib.PackageVersion);
		if (!string.IsNullOrEmpty(fileAttrib.MinimumFileVersion)) element.SetAttribute("MinimumFileVersion", fileAttrib.MinimumFileVersion);
		if (!string.IsNullOrEmpty(fileAttrib.MaximumFileVersion)) element.SetAttribute("MaximumFileVersion", fileAttrib.MaximumFileVersion);
		if (fileAttrib.Hash is { Length: > 0 }) element.SetAttribute("Hash", ConvertByteArrayToHex(fileAttrib.Hash));
		if (!string.IsNullOrEmpty(fileAttrib.AppIDs)) element.SetAttribute("AppIDs", fileAttrib.AppIDs);
		if (!string.IsNullOrEmpty(fileAttrib.FilePath)) element.SetAttribute("FilePath", fileAttrib.FilePath);
		_ = parent.AppendChild(element);
	}

	private static void AppendFileRule(XmlDocument doc, XmlElement parent, FileRule fileRule)
	{
		XmlElement element = doc.CreateElement("FileRule", NameSpace);
		if (!string.IsNullOrEmpty(fileRule.ID)) element.SetAttribute("ID", fileRule.ID);
		if (!string.IsNullOrEmpty(fileRule.FriendlyName)) element.SetAttribute("FriendlyName", fileRule.FriendlyName);
		if (!string.IsNullOrEmpty(fileRule.FileName)) element.SetAttribute("FileName", fileRule.FileName);
		if (!string.IsNullOrEmpty(fileRule.InternalName)) element.SetAttribute("InternalName", fileRule.InternalName);
		if (!string.IsNullOrEmpty(fileRule.FileDescription)) element.SetAttribute("FileDescription", fileRule.FileDescription);
		if (!string.IsNullOrEmpty(fileRule.ProductName)) element.SetAttribute("ProductName", fileRule.ProductName);
		if (!string.IsNullOrEmpty(fileRule.PackageFamilyName)) element.SetAttribute("PackageFamilyName", fileRule.PackageFamilyName);
		if (!string.IsNullOrEmpty(fileRule.PackageVersion)) element.SetAttribute("PackageVersion", fileRule.PackageVersion);
		if (!string.IsNullOrEmpty(fileRule.MinimumFileVersion)) element.SetAttribute("MinimumFileVersion", fileRule.MinimumFileVersion);
		if (!string.IsNullOrEmpty(fileRule.MaximumFileVersion)) element.SetAttribute("MaximumFileVersion", fileRule.MaximumFileVersion);
		if (fileRule.Hash is { Length: > 0 }) element.SetAttribute("Hash", ConvertByteArrayToHex(fileRule.Hash));
		if (!string.IsNullOrEmpty(fileRule.AppIDs)) element.SetAttribute("AppIDs", fileRule.AppIDs);
		if (!string.IsNullOrEmpty(fileRule.FilePath)) element.SetAttribute("FilePath", fileRule.FilePath);
		element.SetAttribute("Type", fileRule.Type.ToString());
		_ = parent.AppendChild(element);
	}

	// Signers Group Helpers
	private static void AppendProductSigners(XmlDocument doc, XmlElement parent, ProductSigners ps)
	{
		if (ps.AllowedSigners is not null)
		{
			XmlElement allowedElement = doc.CreateElement("AllowedSigners", NameSpace);
			if (!string.IsNullOrEmpty(ps.AllowedSigners.Workaround))
				allowedElement.SetAttribute("Workaround", ps.AllowedSigners.Workaround);
			if (ps.AllowedSigners.AllowedSigner is not null)
			{
				foreach (AllowedSigner aSigner in ps.AllowedSigners.AllowedSigner)
				{
					XmlElement aSignerElement = doc.CreateElement("AllowedSigner", NameSpace);
					if (!string.IsNullOrEmpty(aSigner.SignerId))
						aSignerElement.SetAttribute("SignerId", aSigner.SignerId);
					if (aSigner.ExceptDenyRule is not null)
					{
						foreach (ExceptDenyRule rule in aSigner.ExceptDenyRule)
						{
							XmlElement ruleElem = doc.CreateElement("ExceptDenyRule", NameSpace);
							if (!string.IsNullOrEmpty(rule.DenyRuleID))
								ruleElem.SetAttribute("DenyRuleID", rule.DenyRuleID);
							_ = aSignerElement.AppendChild(ruleElem);
						}
					}
					_ = allowedElement.AppendChild(aSignerElement);
				}
			}
			_ = parent.AppendChild(allowedElement);
		}
		if (ps.DeniedSigners is not null)
		{
			XmlElement deniedElement = doc.CreateElement("DeniedSigners", NameSpace);
			if (!string.IsNullOrEmpty(ps.DeniedSigners.Workaround))
				deniedElement.SetAttribute("Workaround", ps.DeniedSigners.Workaround);
			if (ps.DeniedSigners.DeniedSigner is not null)
			{
				foreach (DeniedSigner dSigner in ps.DeniedSigners.DeniedSigner)
				{
					XmlElement dSignerElement = doc.CreateElement("DeniedSigner", NameSpace);
					if (!string.IsNullOrEmpty(dSigner.SignerId))
						dSignerElement.SetAttribute("SignerId", dSigner.SignerId);
					if (dSigner.ExceptAllowRule is not null)
					{
						foreach (ExceptAllowRule rule in dSigner.ExceptAllowRule)
						{
							XmlElement ruleElem = doc.CreateElement("ExceptAllowRule", NameSpace);
							if (!string.IsNullOrEmpty(rule.AllowRuleID))
								ruleElem.SetAttribute("AllowRuleID", rule.AllowRuleID);
							_ = dSignerElement.AppendChild(ruleElem);
						}
					}
					_ = deniedElement.AppendChild(dSignerElement);
				}
			}
			_ = parent.AppendChild(deniedElement);
		}
		if (ps.FileRulesRef is not null)
		{
			XmlElement fileRulesRefElement = doc.CreateElement("FileRulesRef", NameSpace);
			if (!string.IsNullOrEmpty(ps.FileRulesRef.Workaround))
				fileRulesRefElement.SetAttribute("Workaround", ps.FileRulesRef.Workaround);
			if (ps.FileRulesRef.FileRuleRef is not null)
			{
				foreach (FileRuleRef fr in ps.FileRulesRef.FileRuleRef)
				{
					XmlElement frElement = doc.CreateElement("FileRuleRef", NameSpace);
					if (!string.IsNullOrEmpty(fr.RuleID))
						frElement.SetAttribute("RuleID", fr.RuleID);
					_ = fileRulesRefElement.AppendChild(frElement);
				}
			}
			_ = parent.AppendChild(fileRulesRefElement);
		}
	}

	private static void AppendTestSigners(XmlDocument doc, XmlElement parent, TestSigners ts)
	{
		if (ts.AllowedSigners is not null)
		{
			XmlElement allowedElement = doc.CreateElement("AllowedSigners", NameSpace);
			if (!string.IsNullOrEmpty(ts.AllowedSigners.Workaround))
				allowedElement.SetAttribute("Workaround", ts.AllowedSigners.Workaround);
			if (ts.AllowedSigners.AllowedSigner is not null)
			{
				foreach (AllowedSigner aSigner in ts.AllowedSigners.AllowedSigner)
				{
					XmlElement aSignerElement = doc.CreateElement("AllowedSigner", NameSpace);
					if (!string.IsNullOrEmpty(aSigner.SignerId))
						aSignerElement.SetAttribute("SignerId", aSigner.SignerId);
					if (aSigner.ExceptDenyRule is not null)
					{
						foreach (ExceptDenyRule rule in aSigner.ExceptDenyRule)
						{
							XmlElement ruleElem = doc.CreateElement("ExceptDenyRule", NameSpace);
							if (!string.IsNullOrEmpty(rule.DenyRuleID))
								ruleElem.SetAttribute("DenyRuleID", rule.DenyRuleID);
							_ = aSignerElement.AppendChild(ruleElem);
						}
					}
					_ = allowedElement.AppendChild(aSignerElement);
				}
			}
			_ = parent.AppendChild(allowedElement);
		}
		if (ts.DeniedSigners is not null)
		{
			XmlElement deniedElement = doc.CreateElement("DeniedSigners", NameSpace);
			if (!string.IsNullOrEmpty(ts.DeniedSigners.Workaround))
				deniedElement.SetAttribute("Workaround", ts.DeniedSigners.Workaround);
			if (ts.DeniedSigners.DeniedSigner is not null)
			{
				foreach (DeniedSigner dSigner in ts.DeniedSigners.DeniedSigner)
				{
					XmlElement dSignerElement = doc.CreateElement("DeniedSigner", NameSpace);
					if (!string.IsNullOrEmpty(dSigner.SignerId))
						dSignerElement.SetAttribute("SignerId", dSigner.SignerId);
					if (dSigner.ExceptAllowRule is not null)
					{
						foreach (ExceptAllowRule rule in dSigner.ExceptAllowRule)
						{
							XmlElement ruleElem = doc.CreateElement("ExceptAllowRule", NameSpace);
							if (!string.IsNullOrEmpty(rule.AllowRuleID))
								ruleElem.SetAttribute("AllowRuleID", rule.AllowRuleID);
							_ = dSignerElement.AppendChild(ruleElem);
						}
					}
					_ = deniedElement.AppendChild(dSignerElement);
				}
			}
			_ = parent.AppendChild(deniedElement);
		}
		if (ts.FileRulesRef is not null)
		{
			XmlElement fileRulesRefElement = doc.CreateElement("FileRulesRef", NameSpace);
			if (!string.IsNullOrEmpty(ts.FileRulesRef.Workaround))
				fileRulesRefElement.SetAttribute("Workaround", ts.FileRulesRef.Workaround);
			if (ts.FileRulesRef.FileRuleRef is not null)
			{
				foreach (FileRuleRef fr in ts.FileRulesRef.FileRuleRef)
				{
					XmlElement frElement = doc.CreateElement("FileRuleRef", NameSpace);
					if (!string.IsNullOrEmpty(fr.RuleID))
						frElement.SetAttribute("RuleID", fr.RuleID);
					_ = fileRulesRefElement.AppendChild(frElement);
				}
			}
			_ = parent.AppendChild(fileRulesRefElement);
		}
	}

	private static void AppendTestSigningSigners(XmlDocument doc, XmlElement parent, TestSigningSigners tss)
	{
		if (tss.AllowedSigners is not null)
		{
			XmlElement allowedElement = doc.CreateElement("AllowedSigners", NameSpace);
			if (!string.IsNullOrEmpty(tss.AllowedSigners.Workaround))
				allowedElement.SetAttribute("Workaround", tss.AllowedSigners.Workaround);
			if (tss.AllowedSigners.AllowedSigner is not null)
			{
				foreach (AllowedSigner aSigner in tss.AllowedSigners.AllowedSigner)
				{
					XmlElement aSignerElement = doc.CreateElement("AllowedSigner", NameSpace);
					if (!string.IsNullOrEmpty(aSigner.SignerId))
						aSignerElement.SetAttribute("SignerId", aSigner.SignerId);
					if (aSigner.ExceptDenyRule is not null)
					{
						foreach (ExceptDenyRule rule in aSigner.ExceptDenyRule)
						{
							XmlElement ruleElem = doc.CreateElement("ExceptDenyRule", NameSpace);
							if (!string.IsNullOrEmpty(rule.DenyRuleID))
								ruleElem.SetAttribute("DenyRuleID", rule.DenyRuleID);
							_ = aSignerElement.AppendChild(ruleElem);
						}
					}
					_ = allowedElement.AppendChild(aSignerElement);
				}
			}
			_ = parent.AppendChild(allowedElement);
		}
		if (tss.DeniedSigners is not null)
		{
			XmlElement deniedElement = doc.CreateElement("DeniedSigners", NameSpace);
			if (!string.IsNullOrEmpty(tss.DeniedSigners.Workaround))
				deniedElement.SetAttribute("Workaround", tss.DeniedSigners.Workaround);
			if (tss.DeniedSigners.DeniedSigner is not null)
			{
				foreach (DeniedSigner dSigner in tss.DeniedSigners.DeniedSigner)
				{
					XmlElement dSignerElement = doc.CreateElement("DeniedSigner", NameSpace);
					if (!string.IsNullOrEmpty(dSigner.SignerId))
						dSignerElement.SetAttribute("SignerId", dSigner.SignerId);
					if (dSigner.ExceptAllowRule is not null)
					{
						foreach (ExceptAllowRule rule in dSigner.ExceptAllowRule)
						{
							XmlElement ruleElem = doc.CreateElement("ExceptAllowRule", NameSpace);
							if (!string.IsNullOrEmpty(rule.AllowRuleID))
								ruleElem.SetAttribute("AllowRuleID", rule.AllowRuleID);
							_ = dSignerElement.AppendChild(ruleElem);
						}
					}
					_ = deniedElement.AppendChild(dSignerElement);
				}
			}
			_ = parent.AppendChild(deniedElement);
		}
		if (tss.FileRulesRef is not null)
		{
			XmlElement fileRulesRefElement = doc.CreateElement("FileRulesRef", NameSpace);
			if (!string.IsNullOrEmpty(tss.FileRulesRef.Workaround))
				fileRulesRefElement.SetAttribute("Workaround", tss.FileRulesRef.Workaround);
			if (tss.FileRulesRef.FileRuleRef is not null)
			{
				foreach (FileRuleRef fr in tss.FileRulesRef.FileRuleRef)
				{
					XmlElement frElement = doc.CreateElement("FileRuleRef", NameSpace);
					if (!string.IsNullOrEmpty(fr.RuleID))
						frElement.SetAttribute("RuleID", fr.RuleID);
					_ = fileRulesRefElement.AppendChild(frElement);
				}
			}
			_ = parent.AppendChild(fileRulesRefElement);
		}
	}

	// Utility Helpers
	private static void AppendTextElement(XmlDocument doc, XmlElement parent, string name, string? value)
	{
		if (!string.IsNullOrEmpty(value))
		{
			XmlElement element = doc.CreateElement(name, NameSpace);
			element.InnerText = value;
			_ = parent.AppendChild(element);
		}
	}

	private static void AppendAttributeElement(XmlDocument doc, XmlElement parent, string name, string attribute, string? value)
	{
		if (!string.IsNullOrEmpty(value))
		{
			XmlElement element = doc.CreateElement(name, NameSpace);
			element.SetAttribute(attribute, value);
			_ = parent.AppendChild(element);
		}
	}

	private static string ConvertByteArrayToHex(byte[]? data)
	{
		return data is not null ? string.Concat(data.Select(x => x.ToString("X2"))) : string.Empty;
	}
}
