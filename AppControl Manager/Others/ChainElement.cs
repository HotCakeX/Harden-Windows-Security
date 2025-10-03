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

using System.Security.Cryptography.X509Certificates;

namespace AppControlManager.Others;

/// <summary>
/// Defines an enumeration for different types of certificates: Root, Intermediate, and Leaf. Each type is associated
/// with a unique integer value.
/// </summary>
internal enum CertificateType
{
	Root = 0,
	Intermediate = 1,
	Leaf = 2
}

internal sealed class ChainElement(string subjectCN, string issuerCN, DateTime notAfter, DateTime notBefore, string tbsValue, X509Certificate2 certificate, CertificateType type, X509Certificate2 issuer)
{
	internal string SubjectCN => subjectCN;
	internal string IssuerCN => issuerCN;
	internal DateTime NotAfter => notAfter;
	internal DateTime NotBefore => notBefore;
	internal string TBSValue => tbsValue;
	internal X509Certificate2 Certificate => certificate;
	internal CertificateType Type => type;
	internal X509Certificate2 Issuer => issuer;
}
