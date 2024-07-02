using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace WDACConfig
{
    public class ChainPackage
    {
        public X509Chain CertificateChain { get; set; }
        public SignedCms SignedCms { get; set; }
        public WDACConfig.ChainElement RootCertificate { get; set; }
        public WDACConfig.ChainElement[] IntermediateCertificates { get; set; }
        public WDACConfig.ChainElement LeafCertificate { get; set; }
        public ChainPackage(X509Chain certificatechain, SignedCms signedcms, WDACConfig.ChainElement rootcertificate,
         WDACConfig.ChainElement[] intermediatecertificates,
          WDACConfig.ChainElement leafcertificate)
        {
            CertificateChain = certificatechain;
            SignedCms = signedcms;
            RootCertificate = rootcertificate;
            IntermediateCertificates = intermediatecertificates;
            LeafCertificate = leafcertificate;
        }
    }
}

