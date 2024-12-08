using System;
using System.Collections.Generic;

#pragma warning disable

namespace AppControlManager.SiPolicyAlt
{
    /// <summary>
    /// This class will be potentially used in the future to create serialization/deserialization manually to be trim and NativeAOT compatible
    /// It currently completely represents the SiPolicy based on the auto-generated class
    /// </summary>
    public class SiPolicy
    {
        public string VersionEx { get; set; }
        public string PolicyTypeID { get; set; }
        public string PlatformID { get; set; }
        public string PolicyID { get; set; }
        public string BasePolicyID { get; set; }
        public List<RuleType> Rules { get; set; }
        public List<EKU> EKUs { get; set; }
        public List<FileRule> FileRules { get; set; }
        public List<Signer> Signers { get; set; }
        public List<SigningScenario> SigningScenarios { get; set; }
        public List<UpdatePolicySigner> UpdatePolicySigners { get; set; }
        public List<CiSigner> CiSigners { get; set; }
        public uint HvciOptions { get; set; }
        public bool HvciOptionsSpecified { get; set; }
        public List<Setting> Settings { get; set; }
        public List<Macro> Macros { get; set; }
        public List<SupplementalPolicySigner> SupplementalPolicySigners { get; set; }
        public AppSettingRegion AppSettings { get; set; }
        public string FriendlyName { get; set; }
        public PolicyType PolicyType { get; set; }
        public bool PolicyTypeSpecified { get; set; }
    }

    public class RuleType
    {
        public OptionType Item { get; set; }
    }

    public enum OptionType
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
        EnabledConditionalWindowsLockdownPolicy
    }

    public class EKUs
    {
        public List<EKU> Items { get; set; }
    }

    public class EKU
    {
        public string ID { get; set; }
        public string Value { get; set; }
        public string FriendlyName { get; set; }
    }

    public class FileRules
    {
        public List<Allow> AllowItems { get; set; }
        public List<Deny> DenyItems { get; set; }
        public List<FileAttrib> FileAttribItems { get; set; }
        public List<FileRule> FileRuleItems { get; set; }

        public FileRules()
        {
            AllowItems = [];
            DenyItems = [];
            FileAttribItems = [];
            FileRuleItems = [];
        }
    }

    public class Allow
    {
        public string ID { get; set; }
        public string FriendlyName { get; set; }
        public string FileName { get; set; }
        public string InternalName { get; set; }
        public string FileDescription { get; set; }
        public string ProductName { get; set; }
        public string PackageFamilyName { get; set; }
        public string PackageVersion { get; set; }
        public string MinimumFileVersion { get; set; }
        public string MaximumFileVersion { get; set; }
        public string Hash { get; set; }
        public string AppIDs { get; set; }
        public string FilePath { get; set; }
    }

    public class Deny
    {
        public string ID { get; set; }
        public string FriendlyName { get; set; }
        public string FileName { get; set; }
        public string InternalName { get; set; }
        public string FileDescription { get; set; }
        public string ProductName { get; set; }
        public string PackageFamilyName { get; set; }
        public string PackageVersion { get; set; }
        public string MinimumFileVersion { get; set; }
        public string MaximumFileVersion { get; set; }
        public string Hash { get; set; }
        public string AppIDs { get; set; }
        public string FilePath { get; set; }
    }

    public class FileAttrib
    {
        public string ID { get; set; }
        public string FriendlyName { get; set; }
        public string FileName { get; set; }
        public string InternalName { get; set; }
        public string FileDescription { get; set; }
        public string ProductName { get; set; }
        public string PackageFamilyName { get; set; }
        public string PackageVersion { get; set; }
        public string MinimumFileVersion { get; set; }
        public string MaximumFileVersion { get; set; }
        public string Hash { get; set; }
        public string AppIDs { get; set; }
        public string FilePath { get; set; }
    }

    public class FileRule
    {
        public string ID { get; set; }
        public string FriendlyName { get; set; }
        public string FileName { get; set; }
        public string InternalName { get; set; }
        public string FileDescription { get; set; }
        public string ProductName { get; set; }
        public string PackageFamilyName { get; set; }
        public string PackageVersion { get; set; }
        public string MinimumFileVersion { get; set; }
        public string MaximumFileVersion { get; set; }
        public string Hash { get; set; }
        public string AppIDs { get; set; }
        public string FilePath { get; set; }
        public RuleTypeType Type { get; set; }
    }

    public enum RuleTypeType
    {
        Match,
        Exclude,
        Attribute
    }

    public class Signer
    {
        public CertRoot CertRoot { get; set; }
        public List<CertEKU> CertEKU { get; set; }
        public CertIssuer CertIssuer { get; set; }
        public CertPublisher CertPublisher { get; set; }
        public CertOemID CertOemID { get; set; }
        public List<FileAttribRef> FileAttribRef { get; set; }
        public string Name { get; set; }
        public string ID { get; set; }
        public DateTime SignTimeAfter { get; set; }
        public bool SignTimeAfterSpecified { get; set; }
    }

    public enum CertEnumType
    {
        TBS,
        Wellknown
    }

    public class CertRoot
    {
        public CertEnumType Type { get; set; }
        public string Value { get; set; }
    }

    public class CertEKU
    {
        public string ID { get; set; }
    }

    public class CertIssuer
    {
        public string Value { get; set; }
    }

    public class CertPublisher
    {
        public string Value { get; set; }
    }


    public class CertOemID
    {
        public string Value { get; set; }
    }

    public class FileAttribRef
    {
        public string RuleID { get; set; }
    }

    public enum PolicyType
    {
        BasePolicy,
        SupplementalPolicy,
        AppIDTaggingPolicy,
    }

    public class AppSettingRegion
    {
        public List<AppRoot> App { get; set; }
    }

    public class AppRoot
    {
        public List<AppSetting> Setting { get; set; }
        public string Manifest { get; set; }
    }

    public class AppSetting
    {
        public List<string> Value { get; set; }
        public string Name { get; set; }
    }

    public class SupplementalPolicySigner
    {
        public string SignerId { get; set; }
    }

    public class Macro
    {
        public string Id { get; set; }
        public string Value { get; set; }
    }

    public class Setting
    {
        public SettingValueType Value { get; set; }
        public string Provider { get; set; }
        public string Key { get; set; }
        public string ValueName { get; set; }
    }

    public class SettingValueType
    {
        public object Item { get; set; }
    }

    public class CiSigner
    {
        public string SignerId { get; set; }
    }

    public class UpdatePolicySigner
    {
        public string SignerId { get; set; }
    }

    public class SigningScenario
    {
        public ProductSigners ProductSigners { get; set; }
        public TestSigners TestSigners { get; set; }
        public TestSigningSigners TestSigningSigners { get; set; }
        public AppIDTags AppIDTags { get; set; }
        public string ID { get; set; }
        public string FriendlyName { get; set; }
        public byte Value { get; set; }
        public string InheritedScenarios { get; set; }
        public ushort MinimumHashAlgorithm { get; set; }
        public bool MinimumHashAlgorithmSpecified { get; set; }
    }

    public class ProductSigners
    {
        public AllowedSigners AllowedSigners { get; set; }
        public DeniedSigners DeniedSigners { get; set; }
        public FileRulesRef FileRulesRef { get; set; }
    }

    public class TestSigners
    {
        public AllowedSigners AllowedSigners { get; set; }
        public DeniedSigners DeniedSigners { get; set; }
        public FileRulesRef FileRulesRef { get; set; }
    }

    public class TestSigningSigners
    {
        public AllowedSigners AllowedSigners { get; set; }
        public DeniedSigners DeniedSigners { get; set; }
        public FileRulesRef FileRulesRef { get; set; }
    }

    public class AppIDTags
    {
        public List<AppIDTag> AppIDTag { get; set; }
        public bool EnforceDLL { get; set; }
        public bool EnforceDLLSpecified { get; set; }
    }

    public class AppIDTag
    {
        public string Key { get; set; }
        public string Value { get; set; }
    }

    public class AllowedSigners
    {
        public List<AllowedSigner> AllowedSigner { get; set; }
        public string Workaround { get; set; }
    }

    public class AllowedSigner
    {
        public List<ExceptDenyRule> ExceptDenyRule { get; set; }
        public string SignerId { get; set; }
    }

    public class ExceptDenyRule
    {
        public string DenyRuleID { get; set; }
    }

    public class DeniedSigners
    {
        public List<DeniedSigner> DeniedSigner { get; set; }
        public string Workaround { get; set; }
    }

    public class DeniedSigner
    {
        public List<ExceptAllowRule> ExceptAllowRule { get; set; }
        public string SignerId { get; set; }
    }

    public class ExceptAllowRule
    {
        public string AllowRuleID { get; set; }
    }

    public class FileRulesRef
    {
        public List<FileRuleRef> FileRuleRef { get; set; }
        public string Workaround { get; set; }
    }

    public class FileRuleRef
    {
        public string RuleID { get; set; }
    }
}
