using System.Collections.Generic;

#nullable enable

namespace WDACConfig
{
    public class PublisherSignerCreator
    {
        public List<CertificateDetailsCreator> CertificateDetails { get; set; }
        public string? FileName { get; set; }
        public string? AuthenticodeSHA256 { get; set; }
        public string? AuthenticodeSHA1 { get; set; }
        public int SiSigningScenario { get; set; }

        public PublisherSignerCreator(List<CertificateDetailsCreator> certificateDetails, string fileName, string authenticodeSHA256, string authenticodeSHA1, int siSigningScenario)
        {
            CertificateDetails = certificateDetails;
            FileName = fileName;
            AuthenticodeSHA256 = authenticodeSHA256;
            AuthenticodeSHA1 = authenticodeSHA1;
            SiSigningScenario = siSigningScenario;
        }

        public PublisherSignerCreator()
        {
            // Initialize CertificateDetails to an empty list to avoid null reference issues
            CertificateDetails = [];
        }
    }
}
