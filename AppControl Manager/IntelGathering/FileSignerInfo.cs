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
