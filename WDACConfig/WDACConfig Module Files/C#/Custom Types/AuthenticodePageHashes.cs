#nullable enable

namespace WDACConfig
{
    public class AuthenticodePageHashes
    {
        public string? SHA1Page { get; set; }
        public string? SHA256Page { get; set; }
        public string? SHa1Authenticode { get; set; }
        public string? SHA256Authenticode { get; set; }

        public AuthenticodePageHashes(string? sha1Page, string? sha256Page, string? sha1Authenticode, string? sha256Authenticode)
        {
            SHA1Page = sha1Page;
            SHA256Page = sha256Page;
            SHa1Authenticode = sha1Authenticode;
            SHA256Authenticode = sha256Authenticode;
        }
    }
}
