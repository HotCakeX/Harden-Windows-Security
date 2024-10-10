#nullable enable

namespace WDACConfig
{
    public class CertificateSignerCreator(string tbs, string signerName, int siSigningScenario)
    {
        public string TBS { get; set; } = tbs;
        public string SignerName { get; set; } = signerName;
        public int SiSigningScenario { get; set; } = siSigningScenario;
    }
}
