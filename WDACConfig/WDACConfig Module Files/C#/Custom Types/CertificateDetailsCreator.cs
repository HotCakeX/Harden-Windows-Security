namespace WDACConfig
{
    public class CertificateDetailsCreator
    {
        public string IntermediateCertTBS { get; set; }
        public string IntermediateCertName { get; set; }
        public string LeafCertTBS { get; set; }
        public string LeafCertName { get; set; }

        public CertificateDetailsCreator(string intermediateCertTBS, string intermediateCertName, string leafCertTBS, string leafCertName)
        {
            IntermediateCertTBS = intermediateCertTBS;
            IntermediateCertName = intermediateCertName;
            LeafCertTBS = leafCertTBS;
            LeafCertName = leafCertName;
        }
    }
}