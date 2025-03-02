using System;

namespace AppControlManager.IntelGathering;

internal sealed class FileSignerInfo
{
	internal int? TotalSignatureCount { get; set; }
	internal int? Signature { get; set; }
	internal string? Hash { get; set; }
	internal bool? PageHash { get; set; }
	internal string? SignatureType { get; set; }
	internal string? ValidatedSigningLevel { get; set; }
	internal string? VerificationError { get; set; }
	internal int? Flags { get; set; }
	internal DateTime? NotValidBefore { get; set; }
	internal DateTime? NotValidAfter { get; set; }
	internal string? PublisherName { get; set; }
	internal string? IssuerName { get; set; }
	internal string? PublisherTBSHash { get; set; }
	internal string? IssuerTBSHash { get; set; }
	internal string? OPUSInfo { get; set; }
	internal string? EKUs { get; set; }
	internal int? KnownRoot { get; set; }
	internal bool? IsWHQL { get; set; }
}
