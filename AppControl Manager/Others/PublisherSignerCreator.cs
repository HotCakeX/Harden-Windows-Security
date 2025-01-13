using System.Collections.Generic;

namespace AppControlManager.Others;

internal sealed class PublisherSignerCreator
{
	internal List<CertificateDetailsCreator> CertificateDetails { get; set; }
	internal string? FileName { get; set; }
	internal string? AuthenticodeSHA256 { get; set; }
	internal string? AuthenticodeSHA1 { get; set; }
	internal int SiSigningScenario { get; set; }

	internal PublisherSignerCreator(List<CertificateDetailsCreator> certificateDetails, string fileName, string authenticodeSHA256, string authenticodeSHA1, int siSigningScenario)
	{
		CertificateDetails = certificateDetails;
		FileName = fileName;
		AuthenticodeSHA256 = authenticodeSHA256;
		AuthenticodeSHA1 = authenticodeSHA1;
		SiSigningScenario = siSigningScenario;
	}

	internal PublisherSignerCreator()
	{
		// Initialize CertificateDetails to an empty list to avoid null reference issues
		CertificateDetails = [];
	}
}
