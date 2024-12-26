using AppControlManager.SiPolicy;

namespace AppControlManager.SiPolicyIntel;

internal sealed class SupplementalPolicySignerRule
{
	internal required Signer SignerElement { get; set; }
	internal required SupplementalPolicySigner SupplementalPolicySigner { get; set; }
}
