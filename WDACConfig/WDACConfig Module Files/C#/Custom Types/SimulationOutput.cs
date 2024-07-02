// Used by WDAC Simulations, the output of the comparer function/method
namespace WDACConfig
{
    // This class holds the details of the current file in the WDAC Simulation comparer
    public class SimulationOutput
    {
        public string Path { get; set; } // the name of the file, which is truncated version of its path
        public string Source { get; set; } // Source from the Comparer function is always 'Signer'
        public bool IsAuthorized { get; set; } // Whether the file is authorized or not
        public string SignerID { get; set; } // Gathered from the Get-SignerInfo function
        public string SignerName { get; set; } // Gathered from the Get-SignerInfo function
        public string SignerCertRoot { get; set; } // Gathered from the Get-SignerInfo function
        public string SignerCertPublisher { get; set; } // Gathered from the Get-SignerInfo function
        public string SignerScope { get; set; } // Gathered from the Get-SignerInfo function
        public string[] SignerFileAttributeIDs { get; set; } // Gathered from the Get-SignerInfo function
        public string MatchCriteria { get; set; } // The main level based on which the file is authorized
        public string SpecificFileNameLevelMatchCriteria { get; set; } // Only those eligible for FilePublisher, WHQLFilePublisher or SignedVersion levels assign this value, otherwise it stays null
        public string CertSubjectCN { get; set; } // Subject CN of the signer that allows the file
        public string CertIssuerCN { get; set; } // Issuer CN of the signer that allows the file
        public string CertNotAfter { get; set; } // NotAfter date of the signer that allows the file
        public string CertTBSValue { get; set; } // TBS value of the signer that allows the file
        public string FilePath { get; set; } // Full path of the file
        public SimulationOutput(string path, string source, bool isauthorized, string signerID, string signerName, string signerCertRoot, string signerCertPublisher, string signerScope, string[] signerFileAttributeIDs, string matchCriteria, string specificFileNameLevelMatchCriteria, string certSubjectCN, string certIssuerCN, string certNotAfter, string certTBSValue, string filePath)
        {
            Path = path;
            Source = source;
            IsAuthorized = isauthorized;
            SignerID = signerID;
            SignerName = signerName;
            SignerCertRoot = signerCertRoot;
            SignerCertPublisher = signerCertPublisher;
            SignerScope = signerScope;
            SignerFileAttributeIDs = signerFileAttributeIDs;
            MatchCriteria = matchCriteria;
            SpecificFileNameLevelMatchCriteria = specificFileNameLevelMatchCriteria;
            CertSubjectCN = certSubjectCN;
            CertIssuerCN = certIssuerCN;
            CertNotAfter = certNotAfter;
            CertTBSValue = certTBSValue;
            FilePath = filePath;
        }
    }
}
