using System;
using System.Collections.Generic;

#nullable enable

namespace WDACConfig
{
    public class FilePublisherSignerCreator
    {
        public List<CertificateDetailsCreator> CertificateDetails { get; set; }
        public Version? FileVersion { get; set; }
        public string? FileDescription { get; set; }
        public string? InternalName { get; set; }
        public string? OriginalFileName { get; set; }
        public string? PackageFamilyName { get; set; }
        public string? ProductName { get; set; }
        public string? FileName { get; set; }
        public string? AuthenticodeSHA256 { get; set; }
        public string? AuthenticodeSHA1 { get; set; }
        public int SiSigningScenario { get; set; }

        public FilePublisherSignerCreator(
            List<CertificateDetailsCreator> certificateDetails,
            Version fileVersion,
            string? fileDescription,
            string? internalName,
            string? originalFileName,
            string? packageFamilyName,
            string? productName,
            string? fileName,
            string? authenticodeSHA256,
            string? authenticodeSHA1,
            int siSigningScenario)
        {
            CertificateDetails = certificateDetails;
            FileVersion = fileVersion;
            FileDescription = fileDescription;
            InternalName = internalName;
            OriginalFileName = originalFileName;
            PackageFamilyName = packageFamilyName;
            ProductName = productName;
            FileName = fileName;
            AuthenticodeSHA256 = authenticodeSHA256;
            AuthenticodeSHA1 = authenticodeSHA1;
            SiSigningScenario = siSigningScenario;
        }

        public FilePublisherSignerCreator()
        {
            // Initialize CertificateDetails to an empty list to avoid null reference issues
            CertificateDetails = [];
        }
    }
}
