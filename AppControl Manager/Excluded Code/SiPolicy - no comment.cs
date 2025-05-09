namespace AppControlManager.SiPolicy;
public partial class Macros
{
	public MacrosMacro[] Macro { get; set; }
}

public partial class MacrosMacro
{
	public string Id { get; set; }
	public string Value { get; set; }
}

public partial class AppSetting
{
	public string[] Value { get; set; }
	public string Name { get; set; }
}

public partial class AppRoot
{
	public AppSetting[] Setting { get; set; }
	public string Manifest { get; set; }
}

public partial class AppSettingRegion
{
	public AppRoot[] App { get; set; }
}

public partial class RuleType
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
	EnabledConditionalWindowsLockdownPolicy,
	DisabledDefaultWindowsCertificateRemapping
}

public partial class SettingValueType
{
	public object Item { get; set; }
}

public partial class Setting
{
	public SettingValueType Value { get; set; }
	public string Provider { get; set; }
	public string Key { get; set; }
	public string ValueName { get; set; }
}

public partial class Settings
{
	public Setting[] Items { get; set; }
}

public partial class CertEKU
{
	public string ID { get; set; }
}

public partial class CertOemID
{
	[System.Xml.Serialization.XmlAttributeAttribute()]
	public string Value { get; set; }
}

public partial class CertPublisher
{
	public string Value { get; set; }
}

public partial class CertIssuer
{
	public string Value { get; set; }
}

public partial class CertRoot
{
	public CertEnumType Type { get; set; }
	public byte[] Value { get; set; }
}

public enum CertEnumType
{
	TBS,
	Wellknown,
}

public partial class ProductSigners
{
	public AllowedSigners AllowedSigners { get; set; }
	public DeniedSigners DeniedSigners { get; set; }
	public FileRulesRef FileRulesRef { get; set; }
}

public partial class AllowedSigners
{
	public AllowedSigner[] AllowedSigner { get; set; }
	public string Workaround { get; set; }
}

public partial class AllowedSigner
{
	public ExceptDenyRule[] ExceptDenyRule { get; set; }
	public string SignerId { get; set; }
}

public partial class ExceptDenyRule
{
	public string DenyRuleID { get; set; }
}

public partial class DeniedSigners
{
	public DeniedSigner[] DeniedSigner { get; set; }
	public string Workaround { get; set; }
}

public partial class DeniedSigner
{
	public ExceptAllowRule[] ExceptAllowRule { get; set; }
	public string SignerId { get; set; }
}

public partial class ExceptAllowRule
{
	public string AllowRuleID { get; set; }
}

public partial class FileRulesRef
{
	public FileRuleRef[] FileRuleRef { get; set; }
	public string Workaround { get; set; }
}

public partial class FileRuleRef
{
	public string RuleID { get; set; }
}

public partial class TestSigners
{
	public AllowedSigners AllowedSigners { get; set; }
	public DeniedSigners DeniedSigners { get; set; }
	public FileRulesRef FileRulesRef { get; set; }
}

public partial class TestSigningSigners
{
	public AllowedSigners AllowedSigners { get; set; }
	public DeniedSigners DeniedSigners { get; set; }
	public FileRulesRef FileRulesRef { get; set; }
}

public partial class AppIDTag
{
	public string Key { get; set; }
	public string Value { get; set; }
}

public partial class AppIDTags
{
	public AppIDTag[] AppIDTag { get; set; }
	public bool EnforceDLL { get; set; }
	public bool EnforceDLLSpecified { get; set; }
}

public partial class FileAttribRef
{
	public string RuleID { get; set; }
}

public partial class EKUs
{
	public EKU[] Items { get; set; }
}

public partial class EKU
{
	public string ID { get; set; }
	public byte[] Value { get; set; }
	public string FriendlyName { get; set; }
}

public partial class FileRules
{
	public object[] Items { get; set; }
}

public partial class Allow
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
	public byte[] Hash { get; set; }
	public string AppIDs { get; set; }
	public string FilePath { get; set; }
}

public partial class Deny
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
	public byte[] Hash { get; set; }
	public string AppIDs { get; set; }
	public string FilePath { get; set; }
}

public partial class FileAttrib
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
	public byte[] Hash { get; set; }
	public string AppIDs { get; set; }
	public string FilePath { get; set; }
}

public partial class FileRule
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
	public byte[] Hash { get; set; }
	public string AppIDs { get; set; }
	public string FilePath { get; set; }
	public RuleTypeType Type { get; set; }
}

public enum RuleTypeType
{
	Match,
	Exclude,
	Attribute,
}

public partial class UpdatePolicySigner
{
	public string SignerId { get; set; }
}

public partial class UpdatePolicySigners
{
	public UpdatePolicySigner[] Items { get; set; }
}

public partial class SupplementalPolicySigner
{
	public string SignerId { get; set; }
}

public partial class SupplementalPolicySigners
{
	public SupplementalPolicySigner[] Items { get; set; }
}

public partial class CiSigner
{
	public string SignerId { get; set; }
}

public partial class CiSigners
{
	public CiSigner[] Items { get; set; }
}

public partial class Signers
{
	public Signer[] Items { get; set; }
}

public partial class Signer
{
	public CertRoot CertRoot { get; set; }
	public CertEKU[] CertEKU { get; set; }
	public CertIssuer CertIssuer { get; set; }
	public CertPublisher CertPublisher { get; set; }
	public CertOemID CertOemID { get; set; }
	public FileAttribRef[] FileAttribRef { get; set; }
	public string Name { get; set; }
	public string ID { get; set; }
	public DateTime SignTimeAfter { get; set; }
	public bool SignTimeAfterSpecified { get; set; }
}

public partial class SigningScenarios
{
	public SigningScenario[] Items { get; set; }
}

public partial class SigningScenario
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

public partial class SiPolicy
{
	public string VersionEx { get; set; }
	public string PolicyTypeID { get; set; }
	public string PlatformID { get; set; }
	public string PolicyID { get; set; }
	public string BasePolicyID { get; set; }
	public RuleType[] Rules { get; set; }
	public EKU[] EKUs { get; set; }
	public object[] FileRules { get; set; }
	public Signer[] Signers { get; set; }
	public SigningScenario[] SigningScenarios { get; set; }
	public UpdatePolicySigner[] UpdatePolicySigners { get; set; }
	public CiSigner[] CiSigners { get; set; }
	public uint HvciOptions { get; set; }
	public bool HvciOptionsSpecified { get; set; }
	public Setting[] Settings { get; set; }
	public MacrosMacro[] Macros { get; set; }
	public SupplementalPolicySigner[] SupplementalPolicySigners { get; set; }
	public AppSettingRegion AppSettings { get; set; }
	public string FriendlyName { get; set; }
	public PolicyType PolicyType { get; set; }
	public bool PolicyTypeSpecified { get; set; }
}

public enum PolicyType
{
	BasePolicy,
	SupplementalPolicy,
	AppIDTaggingPolicy,
}
