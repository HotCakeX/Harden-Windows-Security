using System;
using System.Security.Cryptography.X509Certificates;

namespace AppControlManager.Others;

// the enum for CertificateType
public enum CertificateType
{
	Root = 0,
	Intermediate = 1,
	Leaf = 2
}

public sealed class ChainElement(string subjectCN, string issuerCN, DateTime notAfter, DateTime notBefore, string tbsValue, X509Certificate2 certificate, CertificateType type, X509Certificate2 issuer)
{
	public string SubjectCN { get; set; } = subjectCN;
	public string IssuerCN { get; set; } = issuerCN;
	public DateTime NotAfter { get; set; } = notAfter;
	public DateTime NotBefore { get; set; } = notBefore;
	public string TBSValue { get; set; } = tbsValue;
	public X509Certificate2 Certificate { get; set; } = certificate;
	public CertificateType Type { get; set; } = type;
	public X509Certificate2 Issuer { get; set; } = issuer;
}
