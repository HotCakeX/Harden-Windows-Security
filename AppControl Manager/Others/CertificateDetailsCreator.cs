namespace AppControlManager.Others;

internal sealed class CertificateDetailsCreator(string intermediateCertTBS, string intermediateCertName, string leafCertTBS, string leafCertName)
{
	internal string IntermediateCertTBS { get; set; } = intermediateCertTBS;
	internal string IntermediateCertName { get; set; } = intermediateCertName;
	internal string LeafCertTBS { get; set; } = leafCertTBS;
	internal string LeafCertName { get; set; } = leafCertName;
}
