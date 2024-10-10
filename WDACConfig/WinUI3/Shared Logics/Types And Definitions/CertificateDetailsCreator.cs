
#nullable enable

namespace WDACConfig
{
    public class CertificateDetailsCreator(string intermediateCertTBS, string intermediateCertName, string leafCertTBS, string leafCertName)
    {
        public string IntermediateCertTBS { get; set; } = intermediateCertTBS;
        public string IntermediateCertName { get; set; } = intermediateCertName;
        public string LeafCertTBS { get; set; } = leafCertTBS;
        public string LeafCertName { get; set; } = leafCertName;
    }
}