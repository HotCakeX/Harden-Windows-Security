using System;
using System.Collections.Generic;
using System.Linq;

namespace AppControlManager.IntelGathering
{
    public sealed class FileIdentity
    {
        // The origin of this File Identity object, where it came from and how it was compiled
        public FileIdentityOrigin Origin { get; set; }

        // Whether the file is signed or unsigned
        public SignatureStatus SignatureStatus { get; set; }

        // Properties related to logs
        public EventAction Action { get; set; }
        public int EventID { get; set; }
        public DateTime? TimeCreated { get; set; }
        public string? ComputerName { get; set; }
        public Guid? PolicyGUID { get; set; }
        public bool? UserWriteable { get; set; }
        public string? ProcessName { get; set; }
        public string? RequestedSigningLevel { get; set; }
        public string? ValidatedSigningLevel { get; set; }
        public string? Status { get; set; }
        public long? USN { get; set; }
        public string? PolicyName { get; set; }
        public string? PolicyID { get; set; }
        public string? PolicyHash { get; set; }
        public string? UserID { get; set; }


        // Properties applicable to files in general
        public string? FilePath { get; set; }
        public string? FileName { get; set; }
        public string? SHA1Hash { get; set; } // SHA1 Authenticode Hash with fallback to Flat hash for incompatible files
        public string? SHA256Hash { get; set; } // SHA256 Authenticode Hash with fallback to Flat hash for incompatible files
        public string? SHA1PageHash { get; set; } // 1st Page hash - Local file scanning provides this
        public string? SHA256PageHash { get; set; } // 1st Page hash - Local file scanning provides this
        public string? SHA1FlatHash { get; set; } // Flat file hashes - Event logs provide this
        public string? SHA256FlatHash { get; set; } // Flat file hashes - Event logs provide this
        public int SISigningScenario { get; set; } // 1 for user mode files - 0 for kernel mode files
        public string? OriginalFileName { get; set; }
        public string? InternalName { get; set; }
        public string? FileDescription { get; set; }
        public string? ProductName { get; set; }
        public Version? FileVersion { get; set; }
        public string? PackageFamilyName { get; set; }

        // Signer and certificate information with a custom comparer to ensure data with the same PublisherTBSHash and IssuerTBSHash do not exist
        public HashSet<FileSignerInfo> FileSignerInfos { get; set; } = new HashSet<FileSignerInfo>(new FileSignerInfoComparer());


        // Just for display purposes, only contains CNs of the signers
        // FileSignerInfos is the one that has actual signing data.
        public HashSet<string> FilePublishers { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Computed property to join FilePublishers into a comma-separated string
        public string FilePublishersToDisplay => string.Join(", ", FilePublishers);

        // If the file has a WHQL signer
        public bool? HasWHQLSigner { get; set; }


        // Determines whether the file is signed by ECC algorithm or not
        // AppControl does not support ECC Signed files yet
        public bool? IsECCSigned { get; set; }


        // Computed property to gather all OPUSInfo from FileSignerInfos and save them in a comma-separated string for displaying purposes only
        public string Opus => string.Join(", ", FileSignerInfos
            .Where(signerInfo => !string.IsNullOrEmpty(signerInfo.OPUSInfo))
            .Select(signerInfo => signerInfo.OPUSInfo));

    }

}
