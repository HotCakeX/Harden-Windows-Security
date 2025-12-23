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

// . "C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\x64\xsd.exe" "C:\Windows\schemas\CodeIntegrity\cipolicy.xsd" /classes /namespace:AppControlManager.SiPolicy /language:CS

using System.Collections.Generic;

namespace AppControlManager.SiPolicy;

internal sealed class MacrosMacro(string id, string value)
{
	internal string Id => id;

	internal string Value => value;
}

internal sealed class AppSetting(List<string>? value, string? name)
{
	internal List<string>? Value => value;

	internal string? Name => name;
}

internal sealed class AppRoot(List<AppSetting>? setting, string manifest)
{
	internal List<AppSetting>? Setting => setting;

	internal string Manifest => manifest;
}

internal sealed class AppSettingRegion(List<AppRoot>? app)
{
	internal List<AppRoot>? App => app;
}

internal sealed class RuleType(OptionType item)
{
	internal OptionType Item => item;
}

internal enum OptionType
{
	EnabledUMCI,
	EnabledBootMenuProtection,
	EnabledIntelligentSecurityGraphAuthorization,
	EnabledInvalidateEAsonReboot,
	RequiredWHQL,
	EnabledDeveloperModeDynamicCodeTrust,
	EnabledAllowSupplementalPolicies,
	DisabledRuntimeFilePathRuleProtection,
	EnabledRevokedExpiredAsUnsigned,
	EnabledAuditMode,
	DisabledFlightSigning,
	EnabledInheritDefaultPolicy,
	EnabledUnsignedSystemIntegrityPolicy,
	EnabledDynamicCodeSecurity,
	RequiredEVSigners,
	EnabledBootAuditOnFailure,
	EnabledAdvancedBootOptionsMenu,
	DisabledScriptEnforcement,
	RequiredEnforceStoreApplications,
	EnabledSecureSettingPolicy,
	EnabledManagedInstaller,
	EnabledUpdatePolicyNoReboot,
	EnabledConditionalWindowsLockdownPolicy,
	DisabledDefaultWindowsCertificateRemapping
}

internal sealed class SettingValueType(object item)
{
	/// Can only hold Binary/Boolean/DWord/String
	internal object Item { get; set; } = item;
}

internal sealed class Setting(SettingValueType value, string provider, string key, string valueName)
{
	internal SettingValueType Value { get; set; } = value;

	internal string Provider => provider;

	internal string Key => key;

	internal string ValueName { get; set; } = valueName;
}

internal sealed class CertEKU(string id)
{
	internal string ID => id;
}

internal sealed class CertOemID(string value)
{
	internal string Value = value;
}

internal sealed class CertPublisher(string value)
{
	internal string Value => value;
}

internal sealed class CertIssuer(string value)
{
	internal string Value => value;
}

internal sealed class CertRoot(CertEnumType type, ReadOnlyMemory<byte> value)
{
	internal CertEnumType Type => type;

	/// <summary>
	/// Holds hexBinary
	/// </summary>
	internal ReadOnlyMemory<byte> Value => value;
}

internal enum CertEnumType
{
	TBS,
	Wellknown,
}

internal sealed class ProductSigners
{
	internal AllowedSigners? AllowedSigners { get; set; }

	internal DeniedSigners? DeniedSigners { get; set; }

	internal FileRulesRef? FileRulesRef { get; set; }
}

internal sealed class AllowedSigners(List<AllowedSigner> allowedSigner)
{
	internal List<AllowedSigner> AllowedSigner { get; set; } = allowedSigner;

	internal string? Workaround { get; set; }
}

internal sealed class AllowedSigner(string signerId, List<ExceptDenyRule>? exceptDenyRule)
{
	internal List<ExceptDenyRule>? ExceptDenyRule => exceptDenyRule;

	internal string SignerId => signerId;
}

internal sealed class ExceptDenyRule(string denyRuleID)
{
	internal string DenyRuleID => denyRuleID;
}

internal sealed class DeniedSigners(List<DeniedSigner> deniedSigner)
{
	internal List<DeniedSigner> DeniedSigner { get; set; } = deniedSigner;

	internal string? Workaround { get; set; }
}

internal sealed class DeniedSigner(string signerId, List<ExceptAllowRule>? exceptAllowRule)
{
	internal List<ExceptAllowRule>? ExceptAllowRule { get; set; } = exceptAllowRule;

	internal string SignerId => signerId;
}

internal sealed class ExceptAllowRule(string allowRuleID)
{
	internal string AllowRuleID => allowRuleID;
}

internal sealed class FileRulesRef(List<FileRuleRef> fileRuleRef)
{
	internal List<FileRuleRef> FileRuleRef { get; set; } = fileRuleRef;

	internal string? Workaround { get; set; }
}

internal sealed class FileRuleRef(string ruleID)
{
	internal string RuleID => ruleID;
}

internal sealed class TestSigners
{
	internal AllowedSigners? AllowedSigners { get; set; }

	internal DeniedSigners? DeniedSigners { get; set; }

	internal FileRulesRef? FileRulesRef { get; set; }
}

internal sealed class TestSigningSigners
{
	internal AllowedSigners? AllowedSigners { get; set; }

	internal DeniedSigners? DeniedSigners { get; set; }

	internal FileRulesRef? FileRulesRef { get; set; }
}

internal sealed class AppIDTag(string key, string value)
{
	internal string Key => key;

	internal string Value => value;
}

internal sealed class AppIDTags
{
	internal List<AppIDTag>? AppIDTag { get; set; }

	internal bool? EnforceDLL { get; set; }
}

internal sealed class FileAttribRef(string ruleID)
{
	internal string RuleID { get; set; } = ruleID;
}

internal sealed class EKU(string id, ReadOnlyMemory<byte> value, string? friendlyName)
{
	internal string ID { get; set; } = id;

	/// <summary>
	/// Holds hexBinary
	/// </summary>
	internal ReadOnlyMemory<byte> Value => value;

	internal string? FriendlyName => friendlyName;
}

internal sealed class Allow(string id)
{
	internal string ID { get; set; } = id;

	internal string? FriendlyName { get; set; }

	internal string? FileName { get; set; }

	internal string? InternalName { get; set; }

	internal string? FileDescription { get; set; }

	internal string? ProductName { get; set; }

	internal string? PackageFamilyName { get; set; }

	internal string? PackageVersion { get; set; }

	internal string? MinimumFileVersion { get; set; }

	internal string? MaximumFileVersion { get; set; }

	/// <summary>
	/// Holds hexBinary
	/// </summary>
	internal ReadOnlyMemory<byte> Hash { get; set; }

	internal string? AppIDs { get; set; }

	internal string? FilePath { get; set; }
}

internal sealed class Deny(string id)
{
	internal string ID { get; set; } = id;

	internal string? FriendlyName { get; set; }

	internal string? FileName { get; set; }

	internal string? InternalName { get; set; }

	internal string? FileDescription { get; set; }

	internal string? ProductName { get; set; }

	internal string? PackageFamilyName { get; set; }

	internal string? PackageVersion { get; set; }

	internal string? MinimumFileVersion { get; set; }

	internal string? MaximumFileVersion { get; set; }

	/// <summary>
	/// Holds hexBinary
	/// </summary>
	internal ReadOnlyMemory<byte> Hash { get; set; }

	internal string? AppIDs { get; set; }

	internal string? FilePath { get; set; }
}

internal sealed class FileAttrib(string id)
{
	internal string ID { get; set; } = id;

	internal string? FriendlyName { get; set; }

	internal string? FileName { get; set; }

	internal string? InternalName { get; set; }

	internal string? FileDescription { get; set; }

	internal string? ProductName { get; set; }

	internal string? PackageFamilyName { get; set; }

	internal string? PackageVersion { get; set; }

	internal string? MinimumFileVersion { get; set; }

	internal string? MaximumFileVersion { get; set; }

	/// <summary>
	/// Holds hexBinary
	/// </summary>
	internal ReadOnlyMemory<byte> Hash { get; set; }

	internal string? AppIDs { get; set; }

	internal string? FilePath { get; set; }
}

internal sealed class FileRule(string id, RuleTypeType type)
{
	internal string ID { get; set; } = id;

	internal RuleTypeType Type => type;

	internal string? FriendlyName { get; set; }

	internal string? FileName { get; set; }

	internal string? InternalName { get; set; }

	internal string? FileDescription { get; set; }

	internal string? ProductName { get; set; }

	internal string? PackageFamilyName { get; set; }

	internal string? PackageVersion { get; set; }

	internal string? MinimumFileVersion { get; set; }

	internal string? MaximumFileVersion { get; set; }

	/// <summary>
	/// Holds hexBinary
	/// </summary>
	internal ReadOnlyMemory<byte> Hash { get; set; }

	internal string? AppIDs { get; set; }

	internal string? FilePath { get; set; }
}

internal enum RuleTypeType
{
	Match,
	Exclude,
	Attribute
}

internal sealed class UpdatePolicySigner(string signerID)
{
	internal string SignerId { get; set; } = signerID;
}

internal sealed class SupplementalPolicySigner(string signerID)
{
	internal string SignerId { get; set; } = signerID;
}

internal sealed class CiSigner(string signerID)
{
	internal string SignerId { get; set; } = signerID;
}

internal sealed class Signer(string id, string name, CertRoot certRoot)
{
	internal CertRoot CertRoot { get; set; } = certRoot;

	internal List<CertEKU>? CertEKU { get; set; }

	internal CertIssuer? CertIssuer { get; set; }

	internal CertPublisher? CertPublisher { get; set; }

	internal CertOemID? CertOemID { get; set; }

	internal List<FileAttribRef>? FileAttribRef { get; set; }

	internal string Name { get; set; } = name;

	internal string ID { get; set; } = id;

	internal DateTime? SignTimeAfter { get; set; }
}

internal sealed class SigningScenario(string id, byte value, ProductSigners productSigners)
{
	internal ProductSigners ProductSigners { get; set; } = productSigners;

	internal TestSigners? TestSigners { get; set; }

	internal TestSigningSigners? TestSigningSigners { get; set; }

	internal AppIDTags? AppIDTags { get; set; }

	internal string ID { get; set; } = id;

	internal string? FriendlyName { get; set; }

	internal byte Value { get; set; } = value;

	internal string? InheritedScenarios { get; set; }

	internal ushort? MinimumHashAlgorithm { get; set; }
}

internal sealed class SiPolicy(
	string versionEx,
	string platformID,
	string policyID,
	string basePolicyID,
	List<RuleType> rules,
	PolicyType policyType)
{
	internal string VersionEx { get; set; } = versionEx;

	internal string? PolicyTypeID { get; set; }

	internal string PlatformID { get; set; } = platformID;

	internal string PolicyID { get; set; } = policyID;

	internal string BasePolicyID { get; set; } = basePolicyID;

	internal List<RuleType> Rules { get; set; } = rules;

	internal List<EKU>? EKUs { get; set; }

	/// Can only hold the following types:
	/// <see cref="Allow"/>
	/// <see cref="Deny"/>
	/// <see cref="FileAttrib"/>
	/// <see cref="FileRule"/>
	internal List<object>? FileRules { get; set; }

	internal List<Signer>? Signers { get; set; }

	internal List<SigningScenario>? SigningScenarios { get; set; }

	internal List<UpdatePolicySigner>? UpdatePolicySigners { get; set; }

	internal List<CiSigner>? CiSigners { get; set; }

	internal uint? HvciOptions { get; set; }

	internal List<Setting>? Settings { get; set; }

	internal List<MacrosMacro>? Macros { get; set; }

	internal List<SupplementalPolicySigner>? SupplementalPolicySigners { get; set; }

	internal AppSettingRegion? AppSettings { get; set; }

	internal string? FriendlyName { get; set; }

	internal PolicyType PolicyType { get; set; } = policyType;
}

internal enum PolicyType
{
	BasePolicy,
	SupplementalPolicy,
	AppIDTaggingPolicy,
}
