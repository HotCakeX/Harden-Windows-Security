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
using AppControlManager.ViewModels;

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
		string? oIDs
	)
{
	internal int SignerNumber => signerNumber;
	internal CertificateType Type => type;
	internal string? SubjectCN => subjectCN;
	internal string? IssuerCN => issuerCN;
	internal DateTime NotBefore => notBefore;
	internal DateTime NotAfter => notAfter;
	internal string? HashingAlgorithm => hashingAlgorithm;
	internal string? SerialNumber => serialNumber;
	internal string? Thumbprint => thumbprint;
	internal string? TBSHash => tBSHash;
	internal string? OIDs => oIDs;

	internal ViewFileCertificatesVM? ParentViewModel { get; set; }
}
