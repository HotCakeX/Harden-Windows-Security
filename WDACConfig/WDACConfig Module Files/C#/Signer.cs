using System;

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
        public string SignerScope { get; set; }
        public bool HasFileAttrib { get; set; }
        public string FileAttribName { get; set; }
        public Version FileAttribMinimumVersion { get; set; }

        // Adding a constructor to initialize the properties
        public Signer(string id, string name, string certRoot, string certPublisher, bool haseku, string[] ekuOID, bool ekusMatch, string signerScope, bool hasFileAttrib, string fileAttribName, Version fileAttribMinimumVersion)
        {
            ID = id;
            Name = name;
            CertRoot = certRoot;
            CertPublisher = certPublisher;
            HasEKU = haseku;
            EKUOID = ekuOID;
            EKUsMatch = ekusMatch;
            SignerScope = signerScope;
            HasFileAttrib = hasFileAttrib;
            FileAttribName = fileAttribName;
            FileAttribMinimumVersion = fileAttribMinimumVersion;
        }
    }
}
