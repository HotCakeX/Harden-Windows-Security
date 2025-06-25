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

using AppControlManager.SiPolicy;

namespace AppControlManager.SiPolicyIntel;

/// <summary>
/// For Levels: Publisher, LeafCertificate, PcaCertificate, RootCertificate,
/// </summary>
internal sealed class SignerRule(
	Signer signerElement,
	AllowedSigner? allowedSignerElement,
	DeniedSigner? deniedSignerElement,
	CiSigner? ciSignerElement,
	SSType signingScenario,
	Authorization auth)
{
	internal Signer SignerElement => signerElement;
	internal AllowedSigner? AllowedSignerElement => allowedSignerElement;
	internal DeniedSigner? DeniedSignerElement => deniedSignerElement;
	internal CiSigner? CiSignerElement => ciSignerElement;
	internal SSType SigningScenario => signingScenario;
	internal Authorization Auth => auth;
}
