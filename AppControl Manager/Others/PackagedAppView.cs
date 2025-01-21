namespace AppControlManager.Others;

public sealed class PackagedAppView(string displayName, string version, string packageFamilyName, string logo, string packageFamilyNameActual)
{
	public string DisplayName { get; private set; } = displayName;
	public string Version { get; private set; } = version;
	public string PackageFamilyName { get; private set; } = packageFamilyName;
	public string PackageFamilyNameActual { get; private set; } = packageFamilyNameActual; // Since we add "PFN: " to the PackageFamilyName property for display purposes, this will be used to get the unmodified PFN of the app
	public string Logo { get; private set; } = logo;
}
