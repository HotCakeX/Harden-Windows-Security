using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace AppControlManager.Others;

internal sealed class ChainPackage(X509Chain certificatechain, SignedCms signedcms, ChainElement rootcertificate,
 ChainElement[]? intermediatecertificates,
  ChainElement? leafcertificate)
{
	internal X509Chain CertificateChain { get; set; } = certificatechain;
	internal SignedCms SignedCms { get; set; } = signedcms;
	internal ChainElement RootCertificate { get; set; } = rootcertificate;
	internal ChainElement[]? IntermediateCertificates { get; set; } = intermediatecertificates;
	internal ChainElement? LeafCertificate { get; set; } = leafcertificate;
}

