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

namespace AppControlManager.IntelGathering;

internal sealed class FileSignerInfo(
	int? totalSignatureCount,
	int? signature = null,
	string? hash = null,
	bool? pageHash = null,
	string? signatureType = null,
	string? validatedSigningLevel = null,
	string? verificationError = null,
	int? flags = null,
	DateTime? notValidBefore = null,
	DateTime? notValidAfter = null,
	string? publisherName = null,
	string? issuerName = null,
	string? publisherTBSHash = null,
	string? issuerTBSHash = null,
	string? oPUSInfo = null,
	string? eKUs = null,
	int? knownRoot = null,
	bool? isWHQL = null
	)
{
	internal int? TotalSignatureCount => totalSignatureCount;
	internal int? Signature => signature;
	internal string? Hash => hash;
	internal bool? PageHash => pageHash;
	internal string? SignatureType => signatureType;
	internal string? ValidatedSigningLevel => validatedSigningLevel;
	internal string? VerificationError => verificationError;
	internal int? Flags => flags;
	internal DateTime? NotValidBefore => notValidBefore;
	internal DateTime? NotValidAfter => notValidAfter;
	internal string? PublisherName => publisherName;
	internal string? IssuerName => issuerName;
	internal string? PublisherTBSHash => publisherTBSHash;
	internal string? IssuerTBSHash => issuerTBSHash;
	internal string? OPUSInfo => oPUSInfo;
	internal string? EKUs => eKUs;
	internal int? KnownRoot => knownRoot;
	internal bool? IsWHQL => isWHQL;
}
