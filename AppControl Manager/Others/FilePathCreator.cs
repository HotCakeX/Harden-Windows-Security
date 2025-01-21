namespace AppControlManager.Others;

internal sealed class FilePathCreator(string filePath, string minimumFileVersion, int siSigningScenario)
{
	internal string FilePath { get; set; } = filePath;
	internal string MinimumFileVersion { get; set; } = minimumFileVersion;
	internal int SiSigningScenario { get; set; } = siSigningScenario;
}
