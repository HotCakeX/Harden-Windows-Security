using System;
using System.Collections.Generic;

namespace AppControlManager.Others;

internal sealed class FilePublisherSignerCreator
{
	internal List<CertificateDetailsCreator> CertificateDetails { get; set; }
	internal Version? FileVersion { get; set; }
	internal string? FileDescription { get; set; }
	internal string? InternalName { get; set; }
	internal string? OriginalFileName { get; set; }
	internal string? PackageFamilyName { get; set; }
	internal string? ProductName { get; set; }
	internal string? FileName { get; set; }
	internal string? AuthenticodeSHA256 { get; set; }
	internal string? AuthenticodeSHA1 { get; set; }
	internal int SiSigningScenario { get; set; }

	internal FilePublisherSignerCreator(
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

	internal FilePublisherSignerCreator()
	{
		// Initialize CertificateDetails to an empty list to avoid null reference issues
		CertificateDetails = [];
	}
}
