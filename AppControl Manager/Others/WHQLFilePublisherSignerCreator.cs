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

using System.Collections.Generic;

namespace AppControlManager.Others;

internal sealed class WHQLFilePublisherSignerCreator(
	List<CertificateDetailsCreator> certificateDetails,
	Version? fileVersion,
	string? fileDescription,
	string? internalName,
	string? originalFileName,
	string? packageFamilyName,
	string? productName,
	string? fileName,
	string? authenticodeSHA256,
	string? authenticodeSHA1,
	SiPolicyIntel.SSType siSigningScenario,
	string opus)
{
	internal List<CertificateDetailsCreator> CertificateDetails => certificateDetails;
	internal Version? FileVersion => fileVersion;
	internal string? FileDescription => fileDescription;
	internal string? InternalName => internalName;
	internal string? OriginalFileName => originalFileName;
	internal string? PackageFamilyName => packageFamilyName;
	internal string? ProductName => productName;
	internal string? FileName => fileName;
	internal string? AuthenticodeSHA256 => authenticodeSHA256;
	internal string? AuthenticodeSHA1 => authenticodeSHA1;
	internal SiPolicyIntel.SSType SiSigningScenario => siSigningScenario;
	internal string Opus => opus;
}
