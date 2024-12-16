using System.Collections.Generic;

namespace AppControlManager.SiPolicyIntel;

/// <summary>
/// This is the output of the method that collects all types of signers from SiPolicies
/// </summary>
internal sealed class SignerCollection
{
	internal required HashSet<FilePublisherSignerRule> FilePublisherSigners { get; set; }
	internal required HashSet<SignerRule> SignerRules { get; set; }
	internal required HashSet<WHQLPublisher> WHQLPublishers { get; set; }
	internal required HashSet<WHQLFilePublisher> WHQLFilePublishers { get; set; }
}
