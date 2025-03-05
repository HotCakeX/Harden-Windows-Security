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
using System.Security.Cryptography.X509Certificates;

namespace AppControlManager.Others;

// the enum for CertificateType
internal enum CertificateType
{
	Root = 0,
	Intermediate = 1,
	Leaf = 2
}

internal sealed class ChainElement(string subjectCN, string issuerCN, DateTime notAfter, DateTime notBefore, string tbsValue, X509Certificate2 certificate, CertificateType type, X509Certificate2 issuer)
{
	internal string SubjectCN { get; set; } = subjectCN;
	internal string IssuerCN { get; set; } = issuerCN;
	internal DateTime NotAfter { get; set; } = notAfter;
	internal DateTime NotBefore { get; set; } = notBefore;
	internal string TBSValue { get; set; } = tbsValue;
	internal X509Certificate2 Certificate { get; set; } = certificate;
	internal CertificateType Type { get; set; } = type;
	internal X509Certificate2 Issuer { get; set; } = issuer;
}
