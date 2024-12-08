using AppControlManager.SiPolicy;

namespace AppControlManager.SiPolicyIntel
{
    // For Levels: Publisher, LeafCertificate, PcaCertificate, RootCertificate,
    internal sealed class SignerRule
    {
        internal required Signer SignerElement { get; set; }
        internal AllowedSigner? AllowedSignerElement { get; set; }
        internal DeniedSigner? DeniedSignerElement { get; set; }
        internal CiSigner? CiSignerElement { get; set; }
        internal required SSType SigningScenario { get; set; }
        internal required Authorization Auth { get; set; }
    }
}
