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
using AppControlManager.SiPolicyIntel;

namespace AppControlManager.Others;

/// <summary>
/// Used to create FilePublisher rule for a file.
/// </summary>
/// <param name="certificateDetails"></param>
/// <param name="fileVersion"></param>
/// <param name="fileDescription"></param>
/// <param name="internalName"></param>
/// <param name="originalFileName"></param>
/// <param name="packageFamilyName"></param>
/// <param name="productName"></param>
/// <param name="fileName"></param>
/// <param name="authenticodeSHA256"></param>
/// <param name="authenticodeSHA1"></param>
/// <param name="siSigningScenario"></param>
internal sealed class FilePublisherSignerCreator(
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
	SSType siSigningScenario)
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
	internal SSType SiSigningScenario => siSigningScenario;

}
