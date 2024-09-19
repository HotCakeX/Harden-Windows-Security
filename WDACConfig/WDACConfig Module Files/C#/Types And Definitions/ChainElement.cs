using System;
using System.Security.Cryptography.X509Certificates;

#nullable enable

namespace WDACConfig
{
    // the enum for CertificateType
    public enum CertificateType
    {
        Root = 0,
        Intermediate = 1,
        Leaf = 2
    }

    public class ChainElement(string subjectcn, string issuercn, DateTime notafter, string tbsvalue, X509Certificate2 certificate, CertificateType type)
    {
        public string SubjectCN { get; set; } = subjectcn;
        public string IssuerCN { get; set; } = issuercn;
        public DateTime NotAfter { get; set; } = notafter;
        public string TBSValue { get; set; } = tbsvalue;
        public X509Certificate2 Certificate { get; set; } = certificate;
        public CertificateType Type { get; set; } = type;
    }
}
