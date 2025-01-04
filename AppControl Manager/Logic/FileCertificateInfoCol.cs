using System;

namespace AppControlManager;

// a class that represents each certificate in a chain
// Used by the DataGrid in the View File Certificates page
public sealed class FileCertificateInfoCol
{
	public int SignerNumber { get; set; }
	public CertificateType Type { get; set; }
	public string? SubjectCN { get; set; }
	public string? IssuerCN { get; set; }
	public DateTime NotBefore { get; set; }
	public DateTime NotAfter { get; set; }
	public string? HashingAlgorithm { get; set; }
	public string? SerialNumber { get; set; }
	public string? Thumbprint { get; set; }
	public string? TBSHash { get; set; }
	public string? OIDs { get; set; }
}
