using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

#nullable enable

namespace WDACConfig
{
    public class ChainPackage(X509Chain certificatechain, SignedCms signedcms, ChainElement rootcertificate,
     ChainElement[]? intermediatecertificates,
      ChainElement? leafcertificate)
    {
        public X509Chain CertificateChain { get; set; } = certificatechain;
        public SignedCms SignedCms { get; set; } = signedcms;
        public ChainElement RootCertificate { get; set; } = rootcertificate;
        public ChainElement[]? IntermediateCertificates { get; set; } = intermediatecertificates;
        public ChainElement? LeafCertificate { get; set; } = leafcertificate;
    }
}

