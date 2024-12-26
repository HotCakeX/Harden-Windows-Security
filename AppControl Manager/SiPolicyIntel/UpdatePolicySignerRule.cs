using AppControlManager.SiPolicy;

namespace AppControlManager.SiPolicyIntel;

internal sealed class UpdatePolicySignerRule
{
	internal required Signer SignerElement { get; set; }
	internal required UpdatePolicySigner UpdatePolicySigner { get; set; }
}
