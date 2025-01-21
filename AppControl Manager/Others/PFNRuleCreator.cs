namespace AppControlManager.Others;

internal sealed class PFNRuleCreator(string packageFamilyName, string minimumFileVersion, int siSigningScenario)
{
	internal string PackageFamilyName { get; set; } = packageFamilyName;
	internal string MinimumFileVersion { get; set; } = minimumFileVersion;
	internal int SiSigningScenario { get; set; } = siSigningScenario;
}

