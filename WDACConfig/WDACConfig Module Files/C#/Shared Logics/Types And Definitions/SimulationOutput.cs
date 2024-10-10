#nullable enable

// Used by WDAC Simulations, the output of the comparer function/method
namespace WDACConfig
{
    // This class holds the details of the current file in the WDAC Simulation comparer
    public class SimulationOutput(
        string path,
        string source,
        bool isAuthorized,
        string signerID,
        string signerName,
        string signerCertRoot,
        string signerCertPublisher,
        string signerScope,
        string[] signerFileAttributeIDs,
        string matchCriteria,
        string? specificFileNameLevelMatchCriteria,
        string certSubjectCN,
        string certIssuerCN,
        string certNotAfter,
        string certTBSValue,
        string filePath
    )
    {
        // The name of the file, which is a truncated version of its path
        public string Path { get; set; } = path;

        // Source from the Comparer function is always 'Signer'
        public string Source { get; set; } = source;

        // Whether the file is authorized or not
        public bool IsAuthorized { get; set; } = isAuthorized;

        // Gathered from the GetSignerInfo method
        public string SignerID { get; set; } = signerID;

        // Gathered from the GetSignerInfo method
        public string SignerName { get; set; } = signerName;

        // Gathered from the GetSignerInfo method
        public string SignerCertRoot { get; set; } = signerCertRoot;

        // Gathered from the GetSignerInfo method
        public string SignerCertPublisher { get; set; } = signerCertPublisher;

        // Gathered from the GetSignerInfo method
        public string SignerScope { get; set; } = signerScope;

        // Gathered from the GetSignerInfo method
        public string[] SignerFileAttributeIDs { get; set; } = signerFileAttributeIDs;

        // The main level based on which the file is authorized
        public string MatchCriteria { get; set; } = matchCriteria;

        // Only those eligible for FilePublisher, WHQLFilePublisher, or SignedVersion levels assign this value, otherwise it stays null
        public string? SpecificFileNameLevelMatchCriteria { get; set; } = specificFileNameLevelMatchCriteria;

        // Subject CN of the signer that allows the file
        public string CertSubjectCN { get; set; } = certSubjectCN;

        // Issuer CN of the signer that allows the file
        public string CertIssuerCN { get; set; } = certIssuerCN;

        // NotAfter date of the signer that allows the file
        public string CertNotAfter { get; set; } = certNotAfter;

        // TBS value of the signer that allows the file
        public string CertTBSValue { get; set; } = certTBSValue;

        // Full path of the file
        public string FilePath { get; set; } = filePath;
    }
}
