namespace WDACConfig
{
    public class HashCreator
    {
        public string AuthenticodeSHA256 { get; set; }
        public string AuthenticodeSHA1 { get; set; }
        public string FileName { get; set; }
        public int SiSigningScenario { get; set; }

        public HashCreator(string authenticodeSHA256, string authenticodeSHA1, string fileName, int siSigningScenario)
        {
            AuthenticodeSHA256 = authenticodeSHA256;
            AuthenticodeSHA1 = authenticodeSHA1;
            FileName = fileName;
            SiSigningScenario = siSigningScenario;
        }
    }
}