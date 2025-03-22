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

/// <summary>
/// Contains information relevant to an App Control policy regarding a signer element. Information that's included in an App Control policy
/// </summary>
/// <param name="id">Identifies the signer uniquely within the policy.</param>
/// <param name="name">Represents the name associated with the signer.</param>
/// <param name="certRoot">Indicates the root certificate authority for the signer.</param>
/// <param name="certPublisher">Specifies the publisher of the certificate, if applicable.</param>
/// <param name="certIssuer">Denotes the issuer of the certificate, if provided.</param>
/// <param name="certEKU">Lists the enhanced key usages associated with the certificate.</param>
/// <param name="certOemID">Represents the OEM identifier related to the certificate, if any.</param>
/// <param name="fileAttribRef">References attributes related to files associated with the signer.</param>
/// <param name="fileAttrib">Contains a dictionary of file attributes linked to the signer.</param>
/// <param name="signerScope">Defines the scope of the signer within the policy.</param>
/// <param name="isWHQL">Indicates whether the signer is Windows Hardware Quality Labs certified.</param>
/// <param name="isAllowed">Specifies if the signer is permitted under the policy.</param>
/// <param name="hasEKU">Indicates whether the signer has enhanced key usages defined.</param>
internal sealed class SignerX(
	string id,
	string name,
	string certRoot,
	string? certPublisher,
	string? certIssuer,
	List<string>? certEKU,
	string? certOemID,
	List<string> fileAttribRef,
	Dictionary<string, Dictionary<string, string>> fileAttrib,
	string signerScope,
	bool isWHQL,
	bool isAllowed,
	bool hasEKU
	)
{
	internal string ID { get; } = id;
	internal string Name { get; } = name;
	internal string CertRoot { get; } = certRoot;
	internal string? CertPublisher { get; } = certPublisher;
	internal string? CertIssuer { get; } = certIssuer;
	internal List<string>? CertEKU { get; } = certEKU;
	internal string? CertOemID { get; } = certOemID;
	internal List<string> FileAttribRef { get; } = fileAttribRef;
	internal Dictionary<string, Dictionary<string, string>> FileAttrib { get; } = fileAttrib;
	internal string SignerScope { get; } = signerScope;
	internal bool IsWHQL { get; } = isWHQL;
	internal bool IsAllowed { get; } = isAllowed;
	internal bool HasEKU { get; } = hasEKU;
}
