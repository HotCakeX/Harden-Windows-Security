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
using System.Text.Json.Serialization;

namespace AppControlManager.Others;

/// <summary>
/// A class that represents each certificate in a chain
/// Used by the ListView in the View File Certificates page
/// </summary>
internal sealed class FileCertificateInfoCol(
		int signerNumber,
		CertificateType type,
		string? subjectCN,
		string? issuerCN,
		DateTime notBefore,
		DateTime notAfter,
		string? hashingAlgorithm,
		string? serialNumber,
		string? thumbprint,
		string? tBSHash,
		string? oIDs,
		int? version,
		bool? hasPrivateKey,
		bool? archived,
		string? certificatePolicies,
		string? authorityInformationAccess,
		string? crlDistributionPoints,
		string? basicConstraints,
		string? keyUsage,
		string? authorityKeyIdentifier,
		string? subjectKeyIdentifier,
		int rawDataLength,
		int publicKeyLength
	)
{
	[JsonInclude]
	internal int SignerNumber => signerNumber;
	[JsonInclude]
	internal CertificateType Type => type;
	[JsonInclude]
	internal string? SubjectCN => subjectCN;
	[JsonInclude]
	internal string? IssuerCN => issuerCN;
	[JsonInclude]
	internal DateTime NotBefore => notBefore;
	[JsonInclude]
	internal DateTime NotAfter => notAfter;
	[JsonInclude]
	internal string? HashingAlgorithm => hashingAlgorithm;
	[JsonInclude]
	internal string? SerialNumber => serialNumber;
	[JsonInclude]
	internal string? Thumbprint => thumbprint;
	[JsonInclude]
	internal string? TBSHash => tBSHash;
	[JsonInclude]
	internal string? OIDs => oIDs;
	[JsonInclude]
	internal int? Version => version;
	[JsonInclude]
	internal bool? HasPrivateKey => hasPrivateKey;
	[JsonInclude]
	internal bool? Archived => archived;
	[JsonInclude]
	internal string? CertificatePolicies => certificatePolicies;
	[JsonInclude]
	internal string? AuthorityInformationAccess => authorityInformationAccess;
	[JsonInclude]
	internal string? CRLDistributionPoints => crlDistributionPoints;
	[JsonInclude]
	internal string? BasicConstraints => basicConstraints;
	[JsonInclude]
	internal string? KeyUsage => keyUsage;
	[JsonInclude]
	internal string? AuthorityKeyIdentifier => authorityKeyIdentifier;
	[JsonInclude]
	internal string? SubjectKeyIdentifier => subjectKeyIdentifier;
	[JsonInclude]
	internal int RawDataLength => rawDataLength;
	[JsonInclude]
	internal int PublicKeyLength => publicKeyLength;
}

/// <summary>
/// JSON source generated context for <see cref="FileCertificateInfoCol"/> type.
/// </summary>
[JsonSourceGenerationOptions(
	WriteIndented = true
)]
[JsonSerializable(typeof(FileCertificateInfoCol))]
[JsonSerializable(typeof(List<FileCertificateInfoCol>))]
internal sealed partial class FileCertificateInfoColJsonSerializationContext : JsonSerializerContext
{
}
