using System;
using System.Security.Cryptography.X509Certificates;

namespace WDACConfig
{
    // the enum for CertificateType
    public enum CertificateType
    {
        Root = 0,
        Intermediate = 1,
        Leaf = 2
    }

    public class ChainElement
    {
        public string SubjectCN { get; set; }
        public string IssuerCN { get; set; }
        public DateTime NotAfter { get; set; }
        public string TBSValue { get; set; }
        public X509Certificate2 Certificate { get; set; }
        public CertificateType Type { get; set; }

        public ChainElement(string subjectcn, string issuercn, DateTime notafter, string tbsvalue, X509Certificate2 certificate, CertificateType type)
        {
            SubjectCN = subjectcn;
            IssuerCN = issuercn;
            NotAfter = notafter;
            TBSValue = tbsvalue;
            Certificate = certificate;
            Type = type;
        }
    }
}
