
namespace AppControlManager.IntelGathering;

// an internal class to store the structure of the new CSV data
internal sealed class MDEAdvancedHuntingData
{
	internal string? Timestamp { get; set; }
	internal string? DeviceId { get; set; }
	internal string? DeviceName { get; set; }
	internal string? ActionType { get; set; }
	internal string? FileName { get; set; }
	internal string? FolderPath { get; set; }
	internal string? SHA1 { get; set; }
	internal string? SHA256 { get; set; }
	internal string? InitiatingProcessSHA1 { get; set; }
	internal string? InitiatingProcessSHA256 { get; set; }
	internal string? InitiatingProcessMD5 { get; set; }
	internal string? InitiatingProcessFileName { get; set; }
	internal string? InitiatingProcessFileSize { get; set; }
	internal string? InitiatingProcessFolderPath { get; set; }
	internal string? InitiatingProcessId { get; set; }
	internal string? InitiatingProcessCommandLine { get; set; }
	internal string? InitiatingProcessCreationTime { get; set; }
	internal string? InitiatingProcessAccountDomain { get; set; }
	internal string? InitiatingProcessAccountName { get; set; }
	internal string? InitiatingProcessAccountSid { get; set; }
	internal string? InitiatingProcessVersionInfoCompanyName { get; set; }
	internal string? InitiatingProcessVersionInfoProductName { get; set; }
	internal string? InitiatingProcessVersionInfoProductVersion { get; set; }
	internal string? InitiatingProcessVersionInfoInternalFileName { get; set; }
	internal string? InitiatingProcessVersionInfoOriginalFileName { get; set; }
	internal string? InitiatingProcessVersionInfoFileDescription { get; set; }
	internal string? InitiatingProcessParentId { get; set; }
	internal string? InitiatingProcessParentFileName { get; set; }
	internal string? InitiatingProcessParentCreationTime { get; set; }
	internal string? InitiatingProcessLogonId { get; set; }
	internal string? ReportId { get; set; }

	// Additional Fields JSON properties
	internal string? PolicyID { get; set; }
	internal string? PolicyName { get; set; }
	internal string? RequestedSigningLevel { get; set; }
	internal string? ValidatedSigningLevel { get; set; }
	internal string? ProcessName { get; set; }
	internal string? StatusCode { get; set; }
	internal string? Sha1FlatHash { get; set; }
	internal string? Sha256FlatHash { get; set; }
	internal string? USN { get; set; }
	internal string? SiSigningScenario { get; set; }
	internal string? PolicyHash { get; set; }
	internal string? PolicyGuid { get; set; }
	internal bool? UserWriteable { get; set; }
	internal string? OriginalFileName { get; set; }
	internal string? InternalName { get; set; }
	internal string? FileDescription { get; set; }
	internal string? FileVersion { get; set; }
	internal string? EtwActivityId { get; set; }
	internal string? IssuerName { get; set; }
	internal string? IssuerTBSHash { get; set; }
	internal string? NotValidAfter { get; set; }
	internal string? NotValidBefore { get; set; }
	internal string? PublisherName { get; set; }
	internal string? PublisherTBSHash { get; set; }
	internal string? SignatureType { get; set; }
	internal string? TotalSignatureCount { get; set; }
	internal string? VerificationError { get; set; }
	internal string? Signature { get; set; }
	internal string? Hash { get; set; }
	internal string? Flags { get; set; }
	internal string? PolicyBits { get; set; }
}
