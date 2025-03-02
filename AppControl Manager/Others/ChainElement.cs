using System;
using System.Security.Cryptography.X509Certificates;

namespace AppControlManager.Others;

// the enum for CertificateType
internal enum CertificateType
{
	Root = 0,
	Intermediate = 1,
	Leaf = 2
}

internal sealed class ChainElement(string subjectCN, string issuerCN, DateTime notAfter, DateTime notBefore, string tbsValue, X509Certificate2 certificate, CertificateType type, X509Certificate2 issuer)
{
	internal string SubjectCN { get; set; } = subjectCN;
	internal string IssuerCN { get; set; } = issuerCN;
	internal DateTime NotAfter { get; set; } = notAfter;
	internal DateTime NotBefore { get; set; } = notBefore;
	internal string TBSValue { get; set; } = tbsValue;
	internal X509Certificate2 Certificate { get; set; } = certificate;
	internal CertificateType Type { get; set; } = type;
	internal X509Certificate2 Issuer { get; set; } = issuer;
}
