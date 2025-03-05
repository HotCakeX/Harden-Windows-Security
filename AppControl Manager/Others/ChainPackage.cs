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

using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace AppControlManager.Others;

internal sealed class ChainPackage(X509Chain certificatechain, SignedCms signedcms, ChainElement rootcertificate,
 ChainElement[]? intermediatecertificates,
  ChainElement? leafcertificate)
{
	internal X509Chain CertificateChain { get; set; } = certificatechain;
	internal SignedCms SignedCms { get; set; } = signedcms;
	internal ChainElement RootCertificate { get; set; } = rootcertificate;
	internal ChainElement[]? IntermediateCertificates { get; set; } = intermediatecertificates;
	internal ChainElement? LeafCertificate { get; set; } = leafcertificate;
}

