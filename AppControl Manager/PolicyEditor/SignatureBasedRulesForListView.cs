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

namespace AppControlManager.PolicyEditor;

/// <summary>
/// Data model for the Signature Based Rules list view.
/// </summary>
/// <param name="certRoot">Specifies the root certificate used for validation.</param>
/// <param name="certEKU">Indicates the extended key usage for the certificate.</param>
/// <param name="certIssuer">Identifies the issuer of the certificate.</param>
/// <param name="certPublisher">Denotes the publisher associated with the certificate.</param>
/// <param name="certOemID">Represents the OEM identifier linked to the certificate.</param>
/// <param name="name">Holds the name associated with the signature-based rule.</param>
/// <param name="id">Contains a unique identifier for the signature-based rule.</param>
/// <param name="sourceType">Defines the type of source for the signature-based rule.</param>
/// <param name="source">Stores the actual source object related to the rule.</param>
internal sealed class SignatureBasedRulesForListView(
	string? certRoot,
	string? certEKU,
	string? certIssuer,
	string? certPublisher,
	string? certOemID,
	string? name,
	string? id,
	SignatureBasedRuleType sourceType,
	object source
	)
{
	internal string? CertRoot => certRoot;
	internal string? CertificateEKU => certEKU;
	internal string? CertIssuer => certIssuer;
	internal string? CertPublisher => certPublisher;
	internal string? CertOemID => certOemID;
	internal string? Name => name;
	internal string? Id => id;
	internal SignatureBasedRuleType SourceType => sourceType;
	internal object Source => source;
}
