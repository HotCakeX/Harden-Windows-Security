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
using AppControlManager.SiPolicy;

namespace AppControlManager.SiPolicyIntel;

/// <summary>
/// For Levels: WHQLFilePublisher
/// </summary>
/// <param name="fileAttribElements"></param>
/// <param name="allowedSignerElement"></param>
/// <param name="deniedSignerElement"></param>
/// <param name="ciSignerElement"></param>
/// <param name="signerElement"></param>
/// <param name="ekus"></param>
/// <param name="signingScenario"></param>
/// <param name="auth"></param>
internal sealed class WHQLFilePublisher(
	List<FileAttrib> fileAttribElements,
	AllowedSigner? allowedSignerElement,
	DeniedSigner? deniedSignerElement,
	CiSigner? ciSignerElement,
	Signer signerElement,
	List<EKU> ekus,
	SSType signingScenario,
	Authorization auth)
{
	internal List<FileAttrib> FileAttribElements => fileAttribElements;
	internal AllowedSigner? AllowedSignerElement => allowedSignerElement;
	internal DeniedSigner? DeniedSignerElement => deniedSignerElement;
	internal CiSigner? CiSignerElement => ciSignerElement;
	internal Signer SignerElement => signerElement;
	internal List<EKU> Ekus => ekus;
	internal SSType SigningScenario => signingScenario;
	internal Authorization Auth => auth;
}
