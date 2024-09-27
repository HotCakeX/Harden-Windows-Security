#nullable enable

namespace WDACConfig
{
    public class CodeIntegrityHashes(string? sha1Page, string? sha256Page, string? sha1Authenticode, string? sha256Authenticode)
    {
        public string? SHA1Page { get; set; } = sha1Page;
        public string? SHA256Page { get; set; } = sha256Page;
        public string? SHa1Authenticode { get; set; } = sha1Authenticode;
        public string? SHA256Authenticode { get; set; } = sha256Authenticode;
    }
}
