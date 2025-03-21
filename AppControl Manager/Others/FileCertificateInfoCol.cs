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

// a class that represents each certificate in a chain
// Used by the ListView in the View File Certificates page
internal sealed class FileCertificateInfoCol
{
	internal int SignerNumber { get; set; }
	internal CertificateType Type { get; set; }
	internal string? SubjectCN { get; set; }
	internal string? IssuerCN { get; set; }
	internal DateTime NotBefore { get; set; }
	internal DateTime NotAfter { get; set; }
	internal string? HashingAlgorithm { get; set; }
	internal string? SerialNumber { get; set; }
	internal string? Thumbprint { get; set; }
	internal string? TBSHash { get; set; }
	internal string? OIDs { get; set; }

	internal ViewFileCertificatesVM? ParentViewModel { get; set; }
}
