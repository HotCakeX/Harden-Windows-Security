// Used by WDAC Simulations
namespace WDACConfig
{
    public class Signer
    {
        // Adding public getters and setters for the properties
        public string ID { get; set; }
        public string Name { get; set; }
        public string CertRoot { get; set; }
        public string CertPublisher { get; set; }
        public bool HasEKU { get; set; }
        public string[] EKUOID { get; set; }
        public bool EKUsMatch { get; set; }

        // Adding a constructor to initialize the properties
        public Signer(string id, string name, string certRoot, string certPublisher, bool haseku, string[] ekuOID, bool ekusMatch)
        {
            ID = id;
            Name = name;
            CertRoot = certRoot;
            CertPublisher = certPublisher;
            HasEKU = haseku;
            EKUOID = ekuOID;
            EKUsMatch = ekusMatch;
        }
    }
}
