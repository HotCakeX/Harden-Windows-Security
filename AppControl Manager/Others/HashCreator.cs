namespace AppControlManager.Others;

internal sealed class HashCreator(string authenticodeSHA256, string authenticodeSHA1, string fileName, int siSigningScenario)
{
	internal string AuthenticodeSHA256 { get; set; } = authenticodeSHA256;
	internal string AuthenticodeSHA1 { get; set; } = authenticodeSHA1;
	internal string FileName { get; set; } = fileName;
	internal int SiSigningScenario { get; set; } = siSigningScenario;
}
