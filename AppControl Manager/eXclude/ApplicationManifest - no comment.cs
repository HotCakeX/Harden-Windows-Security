namespace AppControlManager.SiPolicy;
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


public partial class AppManifest
{
	public SettingDefinition[] SettingDefinition { get; set; }
	public string Id { get; set; }
}

public partial class SettingDefinition
{
	public string Name { get; set; }
	public SettingType Type { get; set; }
	public bool IgnoreAuditPolicies { get; set; }
}

public enum SettingType
{
	Bool,
	StringList,
	StringSet,
}
