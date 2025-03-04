namespace AppControlManager.Others;

internal sealed class PackagedAppView(string displayName, string version, string packageFamilyName, string logo, string packageFamilyNameActual)
{
	internal string DisplayName { get; private set; } = displayName;
	internal string Version { get; private set; } = version;
	internal string PackageFamilyName { get; private set; } = packageFamilyName;
	internal string PackageFamilyNameActual { get; private set; } = packageFamilyNameActual; // Since we add "PFN: " to the PackageFamilyName property for display purposes, this will be used to get the unmodified PFN of the app
	internal string Logo { get; private set; } = logo;
}
