namespace AppControlManager.Others;

internal sealed class CodeIntegrityHashes(string? sha1Page, string? sha256Page, string? sha1Authenticode, string? sha256Authenticode)
{
	internal string? SHA1Page { get; set; } = sha1Page;
	internal string? SHA256Page { get; set; } = sha256Page;
	internal string? SHa1Authenticode { get; set; } = sha1Authenticode;
	internal string? SHA256Authenticode { get; set; } = sha256Authenticode;
}
