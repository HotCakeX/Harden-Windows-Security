namespace AppControlManager.Others;

internal sealed class CertificateSignerCreator(string tbs, string signerName, int siSigningScenario)
{
	internal string TBS { get; set; } = tbs;
	internal string SignerName { get; set; } = signerName;
	internal int SiSigningScenario { get; set; } = siSigningScenario;
}
