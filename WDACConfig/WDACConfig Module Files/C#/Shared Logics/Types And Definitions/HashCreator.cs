
#nullable enable

namespace WDACConfig
{
    public class HashCreator(string authenticodeSHA256, string authenticodeSHA1, string fileName, int siSigningScenario)
    {
        public string AuthenticodeSHA256 { get; set; } = authenticodeSHA256;
        public string AuthenticodeSHA1 { get; set; } = authenticodeSHA1;
        public string FileName { get; set; } = fileName;
        public int SiSigningScenario { get; set; } = siSigningScenario;
    }
}