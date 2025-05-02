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

pub enum PolicyType {
    BasePolicy,
    SupplementalPolicy,
    AppIDTaggingPolicy,
}

pub enum OptionType {
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
    DisabledDefaultWindowsCertificateRemapping,
}

pub enum CertEnumType {
    TBS,
    Wellknown,
}

pub enum RuleTypeType {
    Match,
    Exclude,
    Attribute,
}

pub struct MacrosMacro {
    pub Id: String,
    pub Value: String,
}

pub struct AppSetting {
    pub Value: Vec<String>,
    pub Name: String,
}

pub struct AppRoot {
    pub Setting: Vec<AppSetting>,
    pub Manifest: String,
}

pub struct AppSettingRegion {
    pub App: Vec<AppRoot>,
}

pub struct RuleType {
    pub Item: OptionType,
}

pub enum SettingValueType {
    Binary(Vec<u8>),
    Boolean(bool),
    DWord(u32),
    String(String),
}

pub struct Setting {
    pub Value: SettingValueType,
    pub Provider: String,
    pub Key: String,
    pub ValueName: String,
}

pub struct CertEKU {
    pub ID: String,
}

pub struct CertOemID {
    pub Value: String,
}

pub struct CertPublisher {
    pub Value: String,
}

pub struct CertIssuer {
    pub Value: String,
}

pub struct CertRoot {
    pub Type: CertEnumType,
    pub Value: Vec<u8>,
}

pub struct AllowedSigner {
    pub ExceptDenyRule: Vec<ExceptDenyRule>,
    pub SignerId: String,
}

pub struct ExceptDenyRule {
    pub DenyRuleID: String,
}

pub struct DeniedSigner {
    pub ExceptAllowRule: Vec<ExceptAllowRule>,
    pub SignerId: String,
}

pub struct ExceptAllowRule {
    pub AllowRuleID: String,
}

pub struct FileRuleRef {
    pub RuleID: String,
}

pub struct FileRulesRef {
    pub FileRuleRef: Vec<FileRuleRef>,
    pub Workaround: Option<String>,
}

pub struct AllowedSigners {
    pub AllowedSigner: Vec<AllowedSigner>,
    pub Workaround: Option<String>,
}

pub struct DeniedSigners {
    pub DeniedSigner: Vec<DeniedSigner>,
    pub Workaround: Option<String>,
}

pub struct ProductSigners {
    pub AllowedSigners: Option<AllowedSigners>,
    pub DeniedSigners: Option<DeniedSigners>,
    pub FileRulesRef: Option<FileRulesRef>,
}

pub struct TestSigners {
    pub AllowedSigners: Option<AllowedSigners>,
    pub DeniedSigners: Option<DeniedSigners>,
    pub FileRulesRef: Option<FileRulesRef>,
}

pub struct TestSigningSigners {
    pub AllowedSigners: Option<AllowedSigners>,
    pub DeniedSigners: Option<DeniedSigners>,
    pub FileRulesRef: Option<FileRulesRef>,
}

pub struct AppIDTag {
    pub Key: String,
    pub Value: String,
}

pub struct AppIDTags {
    pub AppIDTag: Vec<AppIDTag>,
    pub EnforceDLL: Option<bool>,
}

pub struct FileAttribRef {
    pub RuleID: String,
}

pub struct EKU {
    pub ID: String,
    pub Value: Vec<u8>,
    pub FriendlyName: String,
}

pub struct FileRuleBase {
    pub ID: String,
    pub FriendlyName: String,
    pub FileName: String,
    pub InternalName: String,
    pub FileDescription: String,
    pub ProductName: String,
    pub PackageFamilyName: String,
    pub PackageVersion: String,
    pub MinimumFileVersion: String,
    pub MaximumFileVersion: String,
    pub Hash: Vec<u8>,
    pub AppIDs: String,
    pub FilePath: String,
}

pub struct Allow {
    pub base: FileRuleBase,
}

pub struct Deny {
    pub base: FileRuleBase,
}

pub struct FileAttrib {
    pub base: FileRuleBase,
}

pub struct FileRule {
    pub base: FileRuleBase,
    pub Type: RuleTypeType,
}

pub enum FileRuleVariant {
    Allow(Allow),
    Deny(Deny),
    FileAttrib(FileAttrib),
    FileRule(FileRule),
}

pub struct UpdatePolicySigner {
    pub SignerId: String,
}

pub struct SupplementalPolicySigner {
    pub SignerId: String,
}

pub struct CiSigner {
    pub SignerId: String,
}

pub struct Signer {
    pub CertRoot: CertRoot,
    pub CertEKU: Vec<CertEKU>,
    pub CertIssuer: CertIssuer,
    pub CertPublisher: CertPublisher,
    pub CertOemID: CertOemID,
    pub FileAttribRef: Vec<FileAttribRef>,
    pub Name: String,
    pub ID: String,
    pub SignTimeAfter: Option<String>, // DateTime represented as String
}

pub struct SigningScenario {
    pub ProductSigners: Option<ProductSigners>,
    pub TestSigners: Option<TestSigners>,
    pub TestSigningSigners: Option<TestSigningSigners>,
    pub AppIDTags: Option<AppIDTags>,
    pub ID: String,
    pub FriendlyName: String,
    pub Value: u8,
    pub InheritedScenarios: Option<String>,
    pub MinimumHashAlgorithm: Option<u16>,
}

pub struct SiPolicy {
    pub VersionEx: String,
    pub PolicyTypeID: String,
    pub PlatformID: String,
    pub PolicyID: String,
    pub BasePolicyID: String,
    pub Rules: Vec<RuleType>,
    pub EKUs: Vec<EKU>,
    pub FileRules: Vec<FileRuleVariant>,
    pub Signers: Vec<Signer>,
    pub SigningScenarios: Vec<SigningScenario>,
    pub UpdatePolicySigners: Vec<UpdatePolicySigner>,
    pub CiSigners: Vec<CiSigner>,
    pub HvciOptions: Option<u32>,
    pub Settings: Vec<Setting>,
    pub Macros: Vec<MacrosMacro>,
    pub SupplementalPolicySigners: Vec<SupplementalPolicySigner>,
    pub AppSettings: AppSettingRegion,
    pub FriendlyName: String,
    pub PolicyType: PolicyType,
}
