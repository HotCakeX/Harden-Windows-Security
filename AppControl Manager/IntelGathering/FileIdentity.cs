// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System;
using System.Collections.Generic;
using System.Linq;
using AppControlManager.ViewModels;

namespace AppControlManager.IntelGathering;

internal sealed class FileIdentity
{
	// The origin of this File Identity object, where it came from and how it was compiled
	internal FileIdentityOrigin Origin { get; set; }

	// Whether the file is signed or unsigned
	internal SignatureStatus SignatureStatus { get; set; }

	// Properties related to logs
	internal EventAction Action { get; set; }
	internal int EventID { get; set; }
	internal DateTime? TimeCreated { get; set; }
	internal string? ComputerName { get; set; }
	internal Guid? PolicyGUID { get; set; }
	internal bool? UserWriteable { get; set; }
	internal string? ProcessName { get; set; }
	internal string? RequestedSigningLevel { get; set; }
	internal string? ValidatedSigningLevel { get; set; }
	internal string? Status { get; set; }
	internal long? USN { get; set; }
	internal string? PolicyName { get; set; }
	internal string? PolicyID { get; set; }
	internal string? PolicyHash { get; set; }
	internal string? UserID { get; set; }


	// Properties applicable to files in general
	internal string? FilePath { get; set; }
	internal string? FileName { get; set; }
	internal string? SHA1Hash { get; set; } // SHA1 Authenticode Hash with fallback to Flat hash for incompatible files
	internal string? SHA256Hash { get; set; } // SHA256 Authenticode Hash with fallback to Flat hash for incompatible files
	internal string? SHA1PageHash { get; set; } // 1st Page hash - Local file scanning provides this
	internal string? SHA256PageHash { get; set; } // 1st Page hash - Local file scanning provides this
	internal string? SHA1FlatHash { get; set; } // Flat file hashes - Event logs provide this
	internal string? SHA256FlatHash { get; set; } // Flat file hashes - Event logs provide this
	internal int SISigningScenario { get; set; } // 1 for user mode files - 0 for kernel mode files
	internal string? OriginalFileName { get; set; }
	internal string? InternalName { get; set; }
	internal string? FileDescription { get; set; }
	internal string? ProductName { get; set; }
	internal Version? FileVersion { get; set; }
	internal string? PackageFamilyName { get; set; }

	// Signer and certificate information with a custom comparer to ensure data with the same PublisherTBSHash and IssuerTBSHash do not exist
	internal HashSet<FileSignerInfo> FileSignerInfos { get; set; } = new HashSet<FileSignerInfo>(new FileSignerInfoComparer());


	// Just for display purposes, only contains CNs of the signers
	// FileSignerInfos is the one that has actual signing data.
	internal HashSet<string> FilePublishers { get; set; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

	// Computed property to join FilePublishers into a comma-separated string
	internal string FilePublishersToDisplay => string.Join(", ", FilePublishers);

	// If the file has a WHQL signer
	internal bool? HasWHQLSigner { get; set; }


	// Determines whether the file is signed by ECC algorithm or not
	// AppControl does not support ECC Signed files yet
	internal bool? IsECCSigned { get; set; }


	// Computed property to gather all OPUSInfo from FileSignerInfos and save them in a comma-separated string for displaying purposes only
	internal string Opus => string.Join(", ", FileSignerInfos
		.Where(signerInfo => !string.IsNullOrEmpty(signerInfo.OPUSInfo))
		.Select(signerInfo => signerInfo.OPUSInfo));



	// Properties for the parent view model of every page that hosts ListViews for FileIdentity.
	// They store references to the view model classes so we can access them via compiled binding in XAML.
	internal AllowNewAppsVM? ParentViewModelAllowNewApps { get; set; }
	internal CreateDenyPolicyVM? ParentViewModelCreateDenyPolicyVM { get; set; }
	internal CreateSupplementalPolicyVM? ParentViewModelCreateSupplementalPolicyVM { get; set; }
	internal EventLogsPolicyCreationVM? ParentViewModelEventLogsPolicyCreationVM { get; set; }
	internal MDEAHPolicyCreationVM? ParentViewModelMDEAHPolicyCreationVM { get; set; }

}
