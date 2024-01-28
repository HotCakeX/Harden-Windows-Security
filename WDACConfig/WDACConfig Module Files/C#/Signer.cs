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

        // Adding a constructor to initialize the properties
        public Signer(string id, string name, string certRoot, string certPublisher)
        {
            ID = id;
            Name = name;
            CertRoot = certRoot;
            CertPublisher = certPublisher;
        }
    }
}
