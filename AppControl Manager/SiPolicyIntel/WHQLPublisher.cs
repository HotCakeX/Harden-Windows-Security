using AppControlManager.SiPolicy;
using System.Collections.Generic;

namespace AppControlManager.SiPolicyIntel
{
    // For Levels: WHQLPublisher, WHQL
    internal sealed class WHQLPublisher
    {
        internal AllowedSigner? AllowedSignerElement { get; set; }
        internal DeniedSigner? DeniedSignerElement { get; set; }
        internal CiSigner? CiSignerElement { get; set; }
        internal required Signer SignerElement { get; set; }
        internal required List<EKU> Ekus { get; set; }
        internal required SSType SigningScenario { get; set; }
        internal required Authorization Auth { get; set; }
    }
}

