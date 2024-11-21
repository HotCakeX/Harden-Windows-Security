
namespace WDACConfig.IntelGathering
{
    // Define a public class to store the structure of the new CSV data
    public sealed class MDEAdvancedHuntingData
    {
        public string? Timestamp { get; set; }
        public string? DeviceId { get; set; }
        public string? DeviceName { get; set; }
        public string? ActionType { get; set; }
        public string? FileName { get; set; }
        public string? FolderPath { get; set; }
        public string? SHA1 { get; set; }
        public string? SHA256 { get; set; }
        public string? InitiatingProcessSHA1 { get; set; }
        public string? InitiatingProcessSHA256 { get; set; }
        public string? InitiatingProcessMD5 { get; set; }
        public string? InitiatingProcessFileName { get; set; }
        public string? InitiatingProcessFileSize { get; set; }
        public string? InitiatingProcessFolderPath { get; set; }
        public string? InitiatingProcessId { get; set; }
        public string? InitiatingProcessCommandLine { get; set; }
        public string? InitiatingProcessCreationTime { get; set; }
        public string? InitiatingProcessAccountDomain { get; set; }
        public string? InitiatingProcessAccountName { get; set; }
        public string? InitiatingProcessAccountSid { get; set; }
        public string? InitiatingProcessVersionInfoCompanyName { get; set; }
        public string? InitiatingProcessVersionInfoProductName { get; set; }
        public string? InitiatingProcessVersionInfoProductVersion { get; set; }
        public string? InitiatingProcessVersionInfoInternalFileName { get; set; }
        public string? InitiatingProcessVersionInfoOriginalFileName { get; set; }
        public string? InitiatingProcessVersionInfoFileDescription { get; set; }
        public string? InitiatingProcessParentId { get; set; }
        public string? InitiatingProcessParentFileName { get; set; }
        public string? InitiatingProcessParentCreationTime { get; set; }
        public string? InitiatingProcessLogonId { get; set; }
        public string? ReportId { get; set; }

        // Additional Fields JSON properties
        public string? PolicyID { get; set; }
        public string? PolicyName { get; set; }
        public string? RequestedSigningLevel { get; set; }
        public string? ValidatedSigningLevel { get; set; }
        public string? ProcessName { get; set; }
        public string? StatusCode { get; set; }
        public string? Sha1FlatHash { get; set; }
        public string? Sha256FlatHash { get; set; }
        public string? USN { get; set; }
        public string? SiSigningScenario { get; set; }
        public string? PolicyHash { get; set; }
        public string? PolicyGuid { get; set; }
        public bool? UserWriteable { get; set; }
        public string? OriginalFileName { get; set; }
        public string? InternalName { get; set; }
        public string? FileDescription { get; set; }
        public string? FileVersion { get; set; }
        public string? EtwActivityId { get; set; }
        public string? IssuerName { get; set; }
        public string? IssuerTBSHash { get; set; }
        public string? NotValidAfter { get; set; }
        public string? NotValidBefore { get; set; }
        public string? PublisherName { get; set; }
        public string? PublisherTBSHash { get; set; }
        public string? SignatureType { get; set; }
        public string? TotalSignatureCount { get; set; }
        public string? VerificationError { get; set; }
        public string? Signature { get; set; }
        public string? Hash { get; set; }
        public string? Flags { get; set; }
        public string? PolicyBits { get; set; }
    }
}
