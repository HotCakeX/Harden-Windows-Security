
#nullable enable

// Used by WDAC Simulations
namespace WDACConfig
{
    public class SimulationInput(System.IO.FileInfo filepath, ChainPackage[] allfilesigners, Signer[] signerinfo, string[] ekuoids)
    {
        // Adding public getters and setters for the properties
        public System.IO.FileInfo FilePath { get; set; } = filepath;
        public ChainPackage[] AllFileSigners { get; set; } = allfilesigners;
        public Signer[] SignerInfo { get; set; } = signerinfo;
        public string[] EKUOIDs { get; set; } = ekuoids;
    }
}
