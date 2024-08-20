
#nullable enable

// Used by WDAC Simulations
namespace WDACConfig
{
    public class SimulationInput
    {
        // Adding public getters and setters for the properties
        public System.IO.FileInfo FilePath { get; set; }
        public WDACConfig.ChainPackage[] AllFileSigners { get; set; }
        public WDACConfig.Signer[] SignerInfo { get; set; }
        public string[] EKUOIDs { get; set; }

        // Adding a constructor to initialize the properties
        public SimulationInput(System.IO.FileInfo filepath, WDACConfig.ChainPackage[] allfilesigners, WDACConfig.Signer[] signerinfo, string[] ekuoids)
        {
            FilePath = filepath;
            AllFileSigners = allfilesigners;
            SignerInfo = signerinfo;
            EKUOIDs = ekuoids;
        }
    }
}
