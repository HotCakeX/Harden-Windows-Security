using AppControlManager.SiPolicy;

namespace AppControlManager.SiPolicyIntel;

// For levels: Hash, FileName, FilePath, PFN
internal sealed class AllowRule
{
	internal required Allow AllowElement { get; set; }
	internal required FileRuleRef FileRuleRefElement { get; set; }
	internal required SSType SigningScenario { get; set; }
}
