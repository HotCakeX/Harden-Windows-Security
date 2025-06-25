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
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace AppControlManager.Others;

/// <summary>
/// The full chain package of a signed file, includes all of the signature information
/// </summary>
/// <param name="certificatechain"></param>
/// <param name="signedcms"></param>
/// <param name="rootcertificate"></param>
/// <param name="intermediatecertificates"></param>
/// <param name="leafcertificate"></param>
internal sealed class ChainPackage(
	X509Chain certificatechain,
	SignedCms signedcms,
	ChainElement rootcertificate,
	List<ChainElement>? intermediatecertificates,
	ChainElement? leafcertificate)
{
	internal X509Chain CertificateChain => certificatechain;
	internal SignedCms SignedCms => signedcms;
	internal ChainElement RootCertificate => rootcertificate;
	internal List<ChainElement>? IntermediateCertificates => intermediatecertificates;
	internal ChainElement? LeafCertificate => leafcertificate;
}

