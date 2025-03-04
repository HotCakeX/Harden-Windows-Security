using System;

namespace AppControlManager.Others;

// a class that represents each certificate in a chain
// Used by the ListView in the View File Certificates page
internal sealed class FileCertificateInfoCol
{
	internal int SignerNumber { get; set; }
	internal CertificateType Type { get; set; }
	internal string? SubjectCN { get; set; }
	internal string? IssuerCN { get; set; }
	internal DateTime NotBefore { get; set; }
	internal DateTime NotAfter { get; set; }
	internal string? HashingAlgorithm { get; set; }
	internal string? SerialNumber { get; set; }
	internal string? Thumbprint { get; set; }
	internal string? TBSHash { get; set; }
	internal string? OIDs { get; set; }
}
