using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

#nullable enable

namespace WDACConfig
{
    public class ChainPackage(X509Chain certificatechain, SignedCms signedcms, WDACConfig.ChainElement rootcertificate,
     WDACConfig.ChainElement[] intermediatecertificates,
      WDACConfig.ChainElement leafcertificate)
    {
        public X509Chain CertificateChain { get; set; } = certificatechain;
        public SignedCms SignedCms { get; set; } = signedcms;
        public WDACConfig.ChainElement RootCertificate { get; set; } = rootcertificate;
        public WDACConfig.ChainElement[] IntermediateCertificates { get; set; } = intermediatecertificates;
        public WDACConfig.ChainElement LeafCertificate { get; set; } = leafcertificate;
    }
}

