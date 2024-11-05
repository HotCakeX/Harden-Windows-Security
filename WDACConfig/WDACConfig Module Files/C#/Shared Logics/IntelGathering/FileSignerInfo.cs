using System;

#nullable enable

namespace WDACConfig.IntelGathering
{
    public sealed class FileSignerInfo
    {
        public int? TotalSignatureCount { get; set; }
        public int? Signature { get; set; }
        public string? Hash { get; set; }
        public bool? PageHash { get; set; }
        public string? SignatureType { get; set; }
        public string? ValidatedSigningLevel { get; set; }
        public string? VerificationError { get; set; }
        public int? Flags { get; set; }
        public DateTime? NotValidBefore { get; set; }
        public DateTime? NotValidAfter { get; set; }
        public string? PublisherName { get; set; }
        public string? IssuerName { get; set; }
        public string? PublisherTBSHash { get; set; }
        public string? IssuerTBSHash { get; set; }
        public string? OPUSInfo { get; set; }
        public string? EKUs { get; set; }
        public int? KnownRoot { get; set; }
        public bool? IsWHQL { get; set; }
    }

}
