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

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Xml;

namespace AppControlManager.SiPolicy;

internal static class CustomSerialization
{
	/// <summary>
	/// Generates an XML document from a given security policy object, encapsulating various attributes and elements.
	/// </summary>
	/// <param name="policy">The security policy object provides the necessary data to populate the XML structure.</param>
	/// <returns>An XmlDocument representing the structured XML of the security policy.</returns>
	/// <exception cref="InvalidOperationException">Thrown when required elements or attributes cannot be appended to the XML document.</exception>
	internal static XmlDocument CreateXmlFromSiPolicy(SiPolicy policy)
	{
		XmlDocument xmlDoc = new();
		XmlDeclaration xmlDecl = xmlDoc.CreateXmlDeclaration("1.0", "utf-8", null);
		_ = xmlDoc.AppendChild(xmlDecl);

		// Create root element
		XmlElement root = xmlDoc.CreateElement("SiPolicy", GlobalVars.SiPolicyNamespace);
		_ = xmlDoc.AppendChild(root);

		// Set attributes for the root element
		if (!string.IsNullOrEmpty(policy.FriendlyName))
			root.SetAttribute("FriendlyName", policy.FriendlyName);

		root.SetAttribute("PolicyType", ConvertPolicyType(policy.PolicyType));

		// VersionEx, PolicyID, BasePolicyID, PlatformID
		if (!AppendTextElement(xmlDoc, root, "VersionEx", policy.VersionEx))
		{
			throw new InvalidOperationException("Could not get the policy version");
		}
		if (!AppendTextElement(xmlDoc, root, "PolicyID", policy.PolicyID))
		{
			throw new InvalidOperationException("Could not get the policy ID");
		}
		if (!AppendTextElement(xmlDoc, root, "BasePolicyID", policy.BasePolicyID))
		{
			throw new InvalidOperationException("Could not get the Base policy ID");
		}
		if (!AppendTextElement(xmlDoc, root, "PlatformID", policy.PlatformID))
		{
			throw new InvalidOperationException("Could not get the Platform ID");
		}

		// Rules
		// Adding this first so if there are no rules, an empty Rules node will exist to satisfy the schema validation
		XmlElement rulesElement = xmlDoc.CreateElement("Rules", GlobalVars.SiPolicyNamespace);
		_ = root.AppendChild(rulesElement);

		if (policy.Rules is { Count: > 0 })
		{
			foreach (RuleType rule in policy.Rules)
			{
				XmlElement ruleElement = xmlDoc.CreateElement("Rule", GlobalVars.SiPolicyNamespace);

				if (!AppendTextElement(xmlDoc, ruleElement, "Option", ConvertOptionType(rule.Item)))
					continue;

				_ = rulesElement.AppendChild(ruleElement);
			}
		}

		// EKUs
		if (policy.EKUs?.Count > 0)
		{
			XmlElement ekusElement = xmlDoc.CreateElement("EKUs", GlobalVars.SiPolicyNamespace);
			_ = root.AppendChild(ekusElement);

			foreach (EKU eku in policy.EKUs)
			{
				XmlElement ekuElement = xmlDoc.CreateElement("EKU", GlobalVars.SiPolicyNamespace);
				ekuElement.SetAttribute("ID", eku.ID);

				if (!string.IsNullOrEmpty(eku.FriendlyName))
					ekuElement.SetAttribute("FriendlyName", eku.FriendlyName);

				ekuElement.SetAttribute("Value", ConvertByteArrayToHex(eku.Value));
				_ = ekusElement.AppendChild(ekuElement);
			}
		}

		// FileRules
		if (policy.FileRules?.Count > 0)
		{
			XmlElement fileRulesElement = xmlDoc.CreateElement("FileRules", GlobalVars.SiPolicyNamespace);
			_ = root.AppendChild(fileRulesElement);

			// Detect the types of each FileRule
			foreach (object fr in CollectionsMarshal.AsSpan(policy.FileRules))
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
		if (policy.Signers?.Count > 0)
		{
			// Only create the <Signers> block if there are any signers since it is nullable (can be absent in the XML) according to the Schema.
			// Don't append to the root yet
			XmlElement signersElement = xmlDoc.CreateElement("Signers", GlobalVars.SiPolicyNamespace);

			int totalValidSignerElements = 0;

			foreach (Signer signer in policy.Signers)
			{
				XmlElement signerElement = xmlDoc.CreateElement("Signer", GlobalVars.SiPolicyNamespace);
				signerElement.SetAttribute("ID", signer.ID);
				signerElement.SetAttribute("Name", signer.Name);
				if (signer.SignTimeAfter is not null)
					signerElement.SetAttribute("SignTimeAfter", signer.SignTimeAfter.Value.ToString("o"));

				// CertRoot
				if (signer.CertRoot.Value.IsEmpty) continue;
				XmlElement certRootElement = xmlDoc.CreateElement("CertRoot", GlobalVars.SiPolicyNamespace);
				certRootElement.SetAttribute("Type", signer.CertRoot.Type.ToString());
				certRootElement.SetAttribute("Value", ConvertByteArrayToHex(signer.CertRoot.Value));
				_ = signerElement.AppendChild(certRootElement);

				// CertEKU(s)
				if (signer.CertEKU is { Count: > 0 })
				{
					foreach (CertEKU certEku in CollectionsMarshal.AsSpan(signer.CertEKU))
					{
						XmlElement certEkuElement = xmlDoc.CreateElement("CertEKU", GlobalVars.SiPolicyNamespace);
						certEkuElement.SetAttribute("ID", certEku.ID);
						_ = signerElement.AppendChild(certEkuElement);
					}
				}

				// CertIssuer, CertPublisher, CertOemID
				if (signer.CertIssuer is not null)
				{
					if (!AppendAttributeElement(xmlDoc, signerElement, "CertIssuer", "Value", signer.CertIssuer.Value))
					{
						throw new InvalidOperationException("Could not get the CertIssuer value");
					}
				}
				if (signer.CertPublisher is not null)
				{
					if (!AppendAttributeElement(xmlDoc, signerElement, "CertPublisher", "Value", signer.CertPublisher.Value))
					{
						throw new InvalidOperationException("Could not get the CertPublisher value");
					}
				}
				if (signer.CertOemID is not null)
				{
					if (!AppendAttributeElement(xmlDoc, signerElement, "CertOemID", "Value", signer.CertOemID.Value))
					{
						throw new InvalidOperationException("Could not get the CertOemID value");
					}
				}

				// FileAttribRef(s)
				if (signer.FileAttribRef is { Count: > 0 })
				{
					foreach (FileAttribRef far in CollectionsMarshal.AsSpan(signer.FileAttribRef))
					{
						XmlElement farElement = xmlDoc.CreateElement("FileAttribRef", GlobalVars.SiPolicyNamespace);
						farElement.SetAttribute("RuleID", far.RuleID);
						_ = signerElement.AppendChild(farElement);
					}
				}

				totalValidSignerElements++;
				_ = signersElement.AppendChild(signerElement);
			}
			// Only append the Signers element to the root if it has valid elements and won't be empty
			if (totalValidSignerElements > 0)
				_ = root.AppendChild(signersElement);
		}

		// SigningScenarios
		if (policy.SigningScenarios is { Count: > 0 })
		{
			XmlElement signingScenariosElement = xmlDoc.CreateElement("SigningScenarios", GlobalVars.SiPolicyNamespace);
			_ = root.AppendChild(signingScenariosElement);

			foreach (SigningScenario scenario in policy.SigningScenarios)
			{
				XmlElement scenarioElement = xmlDoc.CreateElement("SigningScenario", GlobalVars.SiPolicyNamespace);
				scenarioElement.SetAttribute("Value", scenario.Value.ToString());
				scenarioElement.SetAttribute("ID", scenario.ID);

				if (!string.IsNullOrEmpty(scenario.FriendlyName))
					scenarioElement.SetAttribute("FriendlyName", scenario.FriendlyName);

				if (!string.IsNullOrEmpty(scenario.InheritedScenarios))
					scenarioElement.SetAttribute("InheritedScenarios", scenario.InheritedScenarios);

				string? possibleMinimumHashAlgorithm = scenario.MinimumHashAlgorithm.ToString();
				if (!string.IsNullOrEmpty(possibleMinimumHashAlgorithm))
					scenarioElement.SetAttribute("MinimumHashAlgorithm", possibleMinimumHashAlgorithm);

				// ProductSigners
				XmlElement prodSigners = xmlDoc.CreateElement("ProductSigners", GlobalVars.SiPolicyNamespace);
				AppendProductSigners(xmlDoc, prodSigners, scenario.ProductSigners);
				_ = scenarioElement.AppendChild(prodSigners);
				// TestSigners
				if (scenario.TestSigners is not null)
				{
					XmlElement testSigners = xmlDoc.CreateElement("TestSigners", GlobalVars.SiPolicyNamespace);
					AppendTestSigners(xmlDoc, testSigners, scenario.TestSigners);
					_ = scenarioElement.AppendChild(testSigners);
				}
				// TestSigningSigners
				if (scenario.TestSigningSigners is not null)
				{
					XmlElement testSigningSigners = xmlDoc.CreateElement("TestSigningSigners", GlobalVars.SiPolicyNamespace);
					AppendTestSigningSigners(xmlDoc, testSigningSigners, scenario.TestSigningSigners);
					_ = scenarioElement.AppendChild(testSigningSigners);
				}
				// AppIDTags
				if (scenario.AppIDTags is not null)
				{
					XmlElement appIDTagsElement = xmlDoc.CreateElement("AppIDTags", GlobalVars.SiPolicyNamespace);
					if (scenario.AppIDTags.EnforceDLL is not null)
						appIDTagsElement.SetAttribute("EnforceDLL", scenario.AppIDTags.EnforceDLL.ToString()?.ToLowerInvariant()); // Only lowercase "true" is considered valid by the schema

					if (scenario.AppIDTags.AppIDTag is not null)
					{
						foreach (AppIDTag tag in CollectionsMarshal.AsSpan(scenario.AppIDTags.AppIDTag))
						{
							XmlElement tagElement = xmlDoc.CreateElement("AppIDTag", GlobalVars.SiPolicyNamespace);
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
		if (policy.UpdatePolicySigners?.Count > 0)
		{
			XmlElement upsElement = xmlDoc.CreateElement("UpdatePolicySigners", GlobalVars.SiPolicyNamespace);
			_ = root.AppendChild(upsElement);

			foreach (UpdatePolicySigner ups in policy.UpdatePolicySigners)
			{
				XmlElement upsChild = xmlDoc.CreateElement("UpdatePolicySigner", GlobalVars.SiPolicyNamespace);
				upsChild.SetAttribute("SignerId", ups.SignerId);
				_ = upsElement.AppendChild(upsChild);
			}
		}

		// CiSigners
		if (policy.CiSigners?.Count > 0)
		{
			XmlElement ciElement = xmlDoc.CreateElement("CiSigners", GlobalVars.SiPolicyNamespace);
			_ = root.AppendChild(ciElement);

			foreach (CiSigner ci in CollectionsMarshal.AsSpan(policy.CiSigners))
			{
				XmlElement ciSignerElement = xmlDoc.CreateElement("CiSigner", GlobalVars.SiPolicyNamespace);
				ciSignerElement.SetAttribute("SignerId", ci.SignerId);
				_ = ciElement.AppendChild(ciSignerElement);
			}
		}

		// HvciOptions
		if (policy.HvciOptions is not null)
			if (!AppendTextElement(xmlDoc, root, "HvciOptions", policy.HvciOptions.ToString()))
			{
				throw new InvalidOperationException("Could not get the HVCI Optons value");
			}

		// Settings
		if (policy.Settings is { Count: > 0 })
		{
			// Create element but don't append it to the root yet
			XmlElement settingsElement = xmlDoc.CreateElement("Settings", GlobalVars.SiPolicyNamespace);

			int totalValidSettingsCount = 0;

			foreach (Setting setting in CollectionsMarshal.AsSpan(policy.Settings))
			{
				// If the Setting's value is null we shouldn't create any setting at all because it would be against the schema guidelines
				if (setting is null || setting.Value is null || setting.Value.Item is null)
					continue;

				XmlElement settingElement = xmlDoc.CreateElement("Setting", GlobalVars.SiPolicyNamespace);
				settingElement.SetAttribute("Provider", setting.Provider);
				settingElement.SetAttribute("Key", setting.Key);
				settingElement.SetAttribute("ValueName", setting.ValueName);

				XmlElement valueElement = xmlDoc.CreateElement("Value", GlobalVars.SiPolicyNamespace);
				if (setting.Value.Item is ReadOnlyMemory<byte> bMem)
				{
					if (!AppendTextElement(xmlDoc, valueElement, "Binary", ConvertByteArrayToHex(bMem)))
					{
						continue;
					}
				}
				else if (setting.Value.Item is bool boolVal)
				{
					// Must be lowercase for CIP conversion to succeed, "True" is not ok but "true" is ok.
					if (!AppendTextElement(xmlDoc, valueElement, "Boolean", boolVal.ToString().ToLowerInvariant()))
					{
						continue;
					}
				}
				else if (setting.Value.Item is uint uintVal)
				{
					if (!AppendTextElement(xmlDoc, valueElement, "DWord", uintVal.ToString()))
					{
						continue;
					}
				}
				else if (setting.Value.Item is string s)
				{
					if (!AppendTextElement(xmlDoc, valueElement, "String", s))
					{
						continue;
					}
				}
				else
				{
					// If the value doesn't match then do not add this setting at all
					continue;
				}

				_ = settingElement.AppendChild(valueElement);

				_ = settingsElement.AppendChild(settingElement);

				totalValidSettingsCount++;
			}

			// Only append to the root if it is guaranteed that it won't be empty
			if (totalValidSettingsCount > 0)
				_ = root.AppendChild(settingsElement);
		}

		// Macros
		if (policy.Macros is { Count: > 0 })
		{
			XmlElement macrosElement = xmlDoc.CreateElement("Macros", GlobalVars.SiPolicyNamespace);
			_ = root.AppendChild(macrosElement);
			foreach (MacrosMacro macro in CollectionsMarshal.AsSpan(policy.Macros))
			{
				XmlElement macroElement = xmlDoc.CreateElement("Macro", GlobalVars.SiPolicyNamespace);
				macroElement.SetAttribute("Id", macro.Id);
				macroElement.SetAttribute("Value", macro.Value);
				_ = macrosElement.AppendChild(macroElement);
			}
		}

		// Supplemental policy signers
		if (policy.SupplementalPolicySigners is { Count: > 0 })
		{
			XmlElement suppElement = xmlDoc.CreateElement("SupplementalPolicySigners", GlobalVars.SiPolicyNamespace);
			_ = root.AppendChild(suppElement);
			foreach (SupplementalPolicySigner sps in CollectionsMarshal.AsSpan(policy.SupplementalPolicySigners))
			{
				XmlElement spsElement = xmlDoc.CreateElement("SupplementalPolicySigner", GlobalVars.SiPolicyNamespace);
				spsElement.SetAttribute("SignerId", sps.SignerId);
				_ = suppElement.AppendChild(spsElement);
			}
		}

		// AppSettings (AppSettingRegion)
		if (policy.AppSettings is not null)
		{
			XmlElement appSettingsElement = xmlDoc.CreateElement("AppSettings", GlobalVars.SiPolicyNamespace);
			_ = root.AppendChild(appSettingsElement);
			if (policy.AppSettings.App is not null)
			{
				foreach (AppRoot app in policy.AppSettings.App)
				{
					XmlElement appElement = xmlDoc.CreateElement("App", GlobalVars.SiPolicyNamespace);
					if (!string.IsNullOrEmpty(app.Manifest))
						appElement.SetAttribute("Manifest", app.Manifest);
					if (app.Setting is { Count: > 0 })
					{
						foreach (AppSetting appSetting in CollectionsMarshal.AsSpan(app.Setting))
						{
							XmlElement settingElem = xmlDoc.CreateElement("Setting", GlobalVars.SiPolicyNamespace);
							settingElem.SetAttribute("Name", appSetting.Name);
							if (appSetting.Value is { Count: > 0 })
							{
								foreach (string val in CollectionsMarshal.AsSpan(appSetting.Value))
								{
									if (!AppendTextElement(xmlDoc, settingElem, "Value", val))
									{
										continue;
									}
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
	private static string ConvertOptionType(OptionType option) => option switch
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
		OptionType.DisabledDefaultWindowsCertificateRemapping => "Disabled:Default Windows Certificate Remapping",
		_ => throw new InvalidOperationException("Policy Rule Option is not valid")
	};

	// Helper for PolicyType conversion
	private static string ConvertPolicyType(PolicyType pt) => pt switch
	{
		PolicyType.BasePolicy => "Base Policy",
		PolicyType.SupplementalPolicy => "Supplemental Policy",
		PolicyType.AppIDTaggingPolicy => "AppID Tagging Policy",
		_ => throw new InvalidOperationException("Unknown PolicyType")
	};

	// FileRules Helpers
	private static void AppendAllow(XmlDocument doc, XmlElement parent, Allow allow)
	{
		XmlElement element = doc.CreateElement("Allow", GlobalVars.SiPolicyNamespace);
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
		if (!allow.Hash.IsEmpty) element.SetAttribute("Hash", ConvertByteArrayToHex(allow.Hash));
		if (!string.IsNullOrEmpty(allow.AppIDs)) element.SetAttribute("AppIDs", allow.AppIDs);
		if (!string.IsNullOrEmpty(allow.FilePath)) element.SetAttribute("FilePath", allow.FilePath);
		_ = parent.AppendChild(element);
	}

	private static void AppendDeny(XmlDocument doc, XmlElement parent, Deny deny)
	{
		XmlElement element = doc.CreateElement("Deny", GlobalVars.SiPolicyNamespace);
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
		if (!deny.Hash.IsEmpty) element.SetAttribute("Hash", ConvertByteArrayToHex(deny.Hash));
		if (!string.IsNullOrEmpty(deny.AppIDs)) element.SetAttribute("AppIDs", deny.AppIDs);
		if (!string.IsNullOrEmpty(deny.FilePath)) element.SetAttribute("FilePath", deny.FilePath);
		_ = parent.AppendChild(element);
	}

	private static void AppendFileAttrib(XmlDocument doc, XmlElement parent, FileAttrib fileAttrib)
	{
		XmlElement element = doc.CreateElement("FileAttrib", GlobalVars.SiPolicyNamespace);
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
		if (!fileAttrib.Hash.IsEmpty) element.SetAttribute("Hash", ConvertByteArrayToHex(fileAttrib.Hash));
		if (!string.IsNullOrEmpty(fileAttrib.AppIDs)) element.SetAttribute("AppIDs", fileAttrib.AppIDs);
		if (!string.IsNullOrEmpty(fileAttrib.FilePath)) element.SetAttribute("FilePath", fileAttrib.FilePath);
		_ = parent.AppendChild(element);
	}

	private static void AppendFileRule(XmlDocument doc, XmlElement parent, FileRule fileRule)
	{
		XmlElement element = doc.CreateElement("FileRule", GlobalVars.SiPolicyNamespace);
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
		if (!fileRule.Hash.IsEmpty) element.SetAttribute("Hash", ConvertByteArrayToHex(fileRule.Hash));
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
			XmlElement allowedElement = doc.CreateElement("AllowedSigners", GlobalVars.SiPolicyNamespace);
			if (!string.IsNullOrEmpty(ps.AllowedSigners.Workaround))
				allowedElement.SetAttribute("Workaround", ps.AllowedSigners.Workaround);
			if (ps.AllowedSigners.AllowedSigner.Count > 0)
			{
				foreach (AllowedSigner aSigner in CollectionsMarshal.AsSpan(ps.AllowedSigners.AllowedSigner))
				{
					XmlElement aSignerElement = doc.CreateElement("AllowedSigner", GlobalVars.SiPolicyNamespace);
					if (!string.IsNullOrEmpty(aSigner.SignerId))
						aSignerElement.SetAttribute("SignerId", aSigner.SignerId);
					if (aSigner.ExceptDenyRule is not null)
					{
						foreach (ExceptDenyRule rule in CollectionsMarshal.AsSpan(aSigner.ExceptDenyRule))
						{
							XmlElement ruleElem = doc.CreateElement("ExceptDenyRule", GlobalVars.SiPolicyNamespace);
							if (!string.IsNullOrEmpty(rule.DenyRuleID))
								ruleElem.SetAttribute("DenyRuleID", rule.DenyRuleID);
							_ = aSignerElement.AppendChild(ruleElem);
						}
					}
					_ = allowedElement.AppendChild(aSignerElement);
				}
				_ = parent.AppendChild(allowedElement);
			}
		}
		if (ps.DeniedSigners is not null)
		{
			XmlElement deniedElement = doc.CreateElement("DeniedSigners", GlobalVars.SiPolicyNamespace);
			if (!string.IsNullOrEmpty(ps.DeniedSigners.Workaround))
				deniedElement.SetAttribute("Workaround", ps.DeniedSigners.Workaround);

			if (ps.DeniedSigners.DeniedSigner.Count > 0)
			{
				foreach (DeniedSigner dSigner in CollectionsMarshal.AsSpan(ps.DeniedSigners.DeniedSigner))
				{
					XmlElement dSignerElement = doc.CreateElement("DeniedSigner", GlobalVars.SiPolicyNamespace);
					if (!string.IsNullOrEmpty(dSigner.SignerId))
						dSignerElement.SetAttribute("SignerId", dSigner.SignerId);
					if (dSigner.ExceptAllowRule is not null)
					{
						foreach (ExceptAllowRule rule in CollectionsMarshal.AsSpan(dSigner.ExceptAllowRule))
						{
							XmlElement ruleElem = doc.CreateElement("ExceptAllowRule", GlobalVars.SiPolicyNamespace);
							if (!string.IsNullOrEmpty(rule.AllowRuleID))
								ruleElem.SetAttribute("AllowRuleID", rule.AllowRuleID);
							_ = dSignerElement.AppendChild(ruleElem);
						}
					}
					_ = deniedElement.AppendChild(dSignerElement);
				}
				_ = parent.AppendChild(deniedElement);
			}
		}
		if (ps.FileRulesRef is not null)
		{
			XmlElement fileRulesRefElement = doc.CreateElement("FileRulesRef", GlobalVars.SiPolicyNamespace);
			if (!string.IsNullOrEmpty(ps.FileRulesRef.Workaround))
				fileRulesRefElement.SetAttribute("Workaround", ps.FileRulesRef.Workaround);
			if (ps.FileRulesRef.FileRuleRef.Count > 0)
			{
				foreach (FileRuleRef fr in CollectionsMarshal.AsSpan(ps.FileRulesRef.FileRuleRef))
				{
					XmlElement frElement = doc.CreateElement("FileRuleRef", GlobalVars.SiPolicyNamespace);
					if (!string.IsNullOrEmpty(fr.RuleID))
						frElement.SetAttribute("RuleID", fr.RuleID);
					_ = fileRulesRefElement.AppendChild(frElement);
				}
				// Only append if it will have members because it cannot exist empty as `<FileRulesRef />` in the XML according to the schema.
				_ = parent.AppendChild(fileRulesRefElement);
			}
		}
	}

	private static void AppendTestSigners(XmlDocument doc, XmlElement parent, TestSigners ts)
	{
		if (ts.AllowedSigners is not null)
		{
			XmlElement allowedElement = doc.CreateElement("AllowedSigners", GlobalVars.SiPolicyNamespace);
			if (!string.IsNullOrEmpty(ts.AllowedSigners.Workaround))
				allowedElement.SetAttribute("Workaround", ts.AllowedSigners.Workaround);
			if (ts.AllowedSigners.AllowedSigner.Count > 0)
			{
				foreach (AllowedSigner aSigner in CollectionsMarshal.AsSpan(ts.AllowedSigners.AllowedSigner))
				{
					XmlElement aSignerElement = doc.CreateElement("AllowedSigner", GlobalVars.SiPolicyNamespace);
					if (!string.IsNullOrEmpty(aSigner.SignerId))
						aSignerElement.SetAttribute("SignerId", aSigner.SignerId);
					if (aSigner.ExceptDenyRule is not null)
					{
						foreach (ExceptDenyRule rule in CollectionsMarshal.AsSpan(aSigner.ExceptDenyRule))
						{
							XmlElement ruleElem = doc.CreateElement("ExceptDenyRule", GlobalVars.SiPolicyNamespace);
							if (!string.IsNullOrEmpty(rule.DenyRuleID))
								ruleElem.SetAttribute("DenyRuleID", rule.DenyRuleID);
							_ = aSignerElement.AppendChild(ruleElem);
						}
					}
					_ = allowedElement.AppendChild(aSignerElement);
				}
				_ = parent.AppendChild(allowedElement);
			}
		}
		if (ts.DeniedSigners is not null)
		{
			XmlElement deniedElement = doc.CreateElement("DeniedSigners", GlobalVars.SiPolicyNamespace);
			if (!string.IsNullOrEmpty(ts.DeniedSigners.Workaround))
				deniedElement.SetAttribute("Workaround", ts.DeniedSigners.Workaround);
			if (ts.DeniedSigners.DeniedSigner.Count > 0)
			{
				foreach (DeniedSigner dSigner in CollectionsMarshal.AsSpan(ts.DeniedSigners.DeniedSigner))
				{
					XmlElement dSignerElement = doc.CreateElement("DeniedSigner", GlobalVars.SiPolicyNamespace);
					if (!string.IsNullOrEmpty(dSigner.SignerId))
						dSignerElement.SetAttribute("SignerId", dSigner.SignerId);
					if (dSigner.ExceptAllowRule is not null)
					{
						foreach (ExceptAllowRule rule in CollectionsMarshal.AsSpan(dSigner.ExceptAllowRule))
						{
							XmlElement ruleElem = doc.CreateElement("ExceptAllowRule", GlobalVars.SiPolicyNamespace);
							if (!string.IsNullOrEmpty(rule.AllowRuleID))
								ruleElem.SetAttribute("AllowRuleID", rule.AllowRuleID);
							_ = dSignerElement.AppendChild(ruleElem);
						}
					}
					_ = deniedElement.AppendChild(dSignerElement);
				}
				_ = parent.AppendChild(deniedElement);
			}
		}
		if (ts.FileRulesRef is not null)
		{
			XmlElement fileRulesRefElement = doc.CreateElement("FileRulesRef", GlobalVars.SiPolicyNamespace);
			if (!string.IsNullOrEmpty(ts.FileRulesRef.Workaround))
				fileRulesRefElement.SetAttribute("Workaround", ts.FileRulesRef.Workaround);
			if (ts.FileRulesRef.FileRuleRef.Count > 0)
			{
				foreach (FileRuleRef fr in CollectionsMarshal.AsSpan(ts.FileRulesRef.FileRuleRef))
				{
					XmlElement frElement = doc.CreateElement("FileRuleRef", GlobalVars.SiPolicyNamespace);
					if (!string.IsNullOrEmpty(fr.RuleID))
						frElement.SetAttribute("RuleID", fr.RuleID);
					_ = fileRulesRefElement.AppendChild(frElement);
				}
				// Only append if it will have members because it cannot exist empty as `<FileRulesRef />` in the XML according to the schema.
				_ = parent.AppendChild(fileRulesRefElement);
			}
		}
	}

	private static void AppendTestSigningSigners(XmlDocument doc, XmlElement parent, TestSigningSigners tss)
	{
		if (tss.AllowedSigners is not null)
		{
			XmlElement allowedElement = doc.CreateElement("AllowedSigners", GlobalVars.SiPolicyNamespace);
			if (!string.IsNullOrEmpty(tss.AllowedSigners.Workaround))
				allowedElement.SetAttribute("Workaround", tss.AllowedSigners.Workaround);
			if (tss.AllowedSigners.AllowedSigner.Count > 0)
			{
				foreach (AllowedSigner aSigner in CollectionsMarshal.AsSpan(tss.AllowedSigners.AllowedSigner))
				{
					XmlElement aSignerElement = doc.CreateElement("AllowedSigner", GlobalVars.SiPolicyNamespace);
					if (!string.IsNullOrEmpty(aSigner.SignerId))
						aSignerElement.SetAttribute("SignerId", aSigner.SignerId);
					if (aSigner.ExceptDenyRule is not null)
					{
						foreach (ExceptDenyRule rule in CollectionsMarshal.AsSpan(aSigner.ExceptDenyRule))
						{
							XmlElement ruleElem = doc.CreateElement("ExceptDenyRule", GlobalVars.SiPolicyNamespace);
							if (!string.IsNullOrEmpty(rule.DenyRuleID))
								ruleElem.SetAttribute("DenyRuleID", rule.DenyRuleID);
							_ = aSignerElement.AppendChild(ruleElem);
						}
					}
					_ = allowedElement.AppendChild(aSignerElement);
				}
				_ = parent.AppendChild(allowedElement);
			}
		}
		if (tss.DeniedSigners is not null)
		{
			XmlElement deniedElement = doc.CreateElement("DeniedSigners", GlobalVars.SiPolicyNamespace);
			if (!string.IsNullOrEmpty(tss.DeniedSigners.Workaround))
				deniedElement.SetAttribute("Workaround", tss.DeniedSigners.Workaround);
			if (tss.DeniedSigners.DeniedSigner.Count > 0)
			{
				foreach (DeniedSigner dSigner in CollectionsMarshal.AsSpan(tss.DeniedSigners.DeniedSigner))
				{
					XmlElement dSignerElement = doc.CreateElement("DeniedSigner", GlobalVars.SiPolicyNamespace);
					if (!string.IsNullOrEmpty(dSigner.SignerId))
						dSignerElement.SetAttribute("SignerId", dSigner.SignerId);
					if (dSigner.ExceptAllowRule is not null)
					{
						foreach (ExceptAllowRule rule in CollectionsMarshal.AsSpan(dSigner.ExceptAllowRule))
						{
							XmlElement ruleElem = doc.CreateElement("ExceptAllowRule", GlobalVars.SiPolicyNamespace);
							if (!string.IsNullOrEmpty(rule.AllowRuleID))
								ruleElem.SetAttribute("AllowRuleID", rule.AllowRuleID);
							_ = dSignerElement.AppendChild(ruleElem);
						}
					}
					_ = deniedElement.AppendChild(dSignerElement);
				}
				_ = parent.AppendChild(deniedElement);
			}
		}
		if (tss.FileRulesRef is not null)
		{
			XmlElement fileRulesRefElement = doc.CreateElement("FileRulesRef", GlobalVars.SiPolicyNamespace);
			if (!string.IsNullOrEmpty(tss.FileRulesRef.Workaround))
				fileRulesRefElement.SetAttribute("Workaround", tss.FileRulesRef.Workaround);
			if (tss.FileRulesRef.FileRuleRef.Count > 0)
			{
				foreach (FileRuleRef fr in CollectionsMarshal.AsSpan(tss.FileRulesRef.FileRuleRef))
				{
					XmlElement frElement = doc.CreateElement("FileRuleRef", GlobalVars.SiPolicyNamespace);
					if (!string.IsNullOrEmpty(fr.RuleID))
						frElement.SetAttribute("RuleID", fr.RuleID);
					_ = fileRulesRefElement.AppendChild(frElement);
				}
				// Only append if it will have members because it cannot exist empty as `<FileRulesRef />` in the XML according to the schema.
				_ = parent.AppendChild(fileRulesRefElement);
			}
		}
	}


	/// <summary>
	/// Helper method, its return value must be checked by the caller and handled accordingly
	/// </summary>
	/// <param name="doc"></param>
	/// <param name="parent"></param>
	/// <param name="name"></param>
	/// <param name="value"></param>
	/// <returns></returns>
	private static bool AppendTextElement(XmlDocument doc, XmlElement parent, string name, string? value)
	{
		if (!string.IsNullOrEmpty(value))
		{
			XmlElement element = doc.CreateElement(name, GlobalVars.SiPolicyNamespace);
			element.InnerText = value;
			_ = parent.AppendChild(element);

			return true;
		}
		return false;
	}


	/// <summary>
	/// Helper method, its return value must be checked by the caller and handled accordingly
	/// </summary>
	/// <param name="doc"></param>
	/// <param name="parent"></param>
	/// <param name="name"></param>
	/// <param name="attribute"></param>
	/// <param name="value"></param>
	/// <returns></returns>
	private static bool AppendAttributeElement(XmlDocument doc, XmlElement parent, string name, string attribute, string? value)
	{
		if (!string.IsNullOrEmpty(value))
		{
			XmlElement element = doc.CreateElement(name, GlobalVars.SiPolicyNamespace);
			element.SetAttribute(attribute, value);
			_ = parent.AppendChild(element);

			return true;
		}
		return false;
	}

	/*
	internal static string ConvertByteArrayToHex(byte[]? data)
	{
		return data is not null ? string.Concat(data.Select(x => x.ToString("X2"))) : string.Empty;
	}
	*/

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static unsafe string ConvertByteArrayToHex(ReadOnlyMemory<byte>? data)
	{
		// If the input data is null or empty, return an empty string immediately.
		if (!data.HasValue || data.Value.IsEmpty)
			return string.Empty;

		ReadOnlySpan<byte> byteSpan = data.Value.Span;
		int length = byteSpan.Length;

		// Pre-allocate a string to hold the hexadecimal representation.
		// Each byte will be represented by 2 hexadecimal characters.
		string result = new('\0', length * 2);

		// Use the 'fixed' statement to pin the data span and the result string in memory.
		// This prevents the garbage collector from relocating them while we work with pointers.
		fixed (byte* dataPtr = byteSpan)
		fixed (char* resultPtr = result)
		{
			// Create local pointer variables for clarity:
			byte* pData = dataPtr;
			char* pResult = resultPtr;

			// Loop through each byte in the input span.
			for (int i = 0; i < length; i++)
			{
				// Retrieve the current byte from the pointer.
				byte b = pData[i];

				// Process the high nibble (upper 4 bits)
				pResult[i * 2] = (char)(b >> 4 < 10 ? (b >> 4) + '0' : (b >> 4) - 10 + 'A');

				// Process the low nibble (lower 4 bits)
				pResult[i * 2 + 1] = (char)((b & 0xF) < 10 ? (b & 0xF) + '0' : (b & 0xF) - 10 + 'A');
			}
		}
		// After processing all bytes, return the constructed hexadecimal string.
		return result;
	}

}
