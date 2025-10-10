namespace HardenSystemSecurity.Helpers;

internal sealed class Exclusions(string target, ExclusionSource source)
{
	internal string Target => target;
	internal ExclusionSource Source => source;
	internal string SourceFriendlyName => ExclusionSourceToString(source);

	private static string ExclusionSourceToString(ExclusionSource s) => s switch
	{
		ExclusionSource.Antivirus_Path => "Antivirus - Path",
		ExclusionSource.Antivirus_Extension => "Antivirus - Extension",
		ExclusionSource.Antivirus_Process => "Antivirus - Process",
		ExclusionSource.ControlledFolderAccess => "Controlled Folder Access",
		ExclusionSource.AttackSurfaceReduction => "Attack Surface Reduction",
		_ => "Unknown Exclusion Source"
	};
}

internal enum ExclusionSource
{
	Antivirus_Path = 0,
	Antivirus_Extension = 1,
	Antivirus_Process = 2,
	ControlledFolderAccess = 3,
	AttackSurfaceReduction = 4
}
