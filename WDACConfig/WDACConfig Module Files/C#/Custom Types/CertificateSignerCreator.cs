using System;

#nullable enable

namespace WDACConfig
{
    public class CertificateSignerCreator
    {
        public string TBS { get; set; }
        public string SignerName { get; set; }
        public int SiSigningScenario { get; set; }
        public CertificateSignerCreator(string tbs, string signerName, int siSigningScenario)
        {
            TBS = tbs;
            SignerName = signerName;
            SiSigningScenario = siSigningScenario;
        }
    }
}
