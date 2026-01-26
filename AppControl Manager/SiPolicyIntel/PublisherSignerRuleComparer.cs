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
/// Provides custom equality comparison for <see cref="SignerRule"/> objects.
/// Two SignerRule objects are considered equal if:
/// - Their SigningScenario and Auth properties are equal.
/// - Their Signer elements have matching properties based on the <see cref="Merger.IsSignerRuleMatch(Signer, Signer)"/>
/// </summary>

internal sealed class PublisherSignerRuleComparer : IEqualityComparer<SignerRule>
{
	public bool Equals(SignerRule? x, SignerRule? y)
	{
		if (x is null || y is null)
		{
			return false;
		}

		// First check: SSType and Authorization must be equal
		if (x.SigningScenario != y.SigningScenario || x.Auth != y.Auth)
		{
			return false;
		}

		return Merger.IsSignerRuleMatch(x.SignerElement, y.SignerElement);
	}

	public int GetHashCode(SignerRule obj)
	{
		HashCode hash = new();

		// Include SSType and Authorization in the hash calculation
		hash.Add(obj.SigningScenario);
		hash.Add(obj.Auth);

		Signer signer = obj.SignerElement;
		hash.Add(signer.Name, StringComparer.OrdinalIgnoreCase);

		if (!signer.CertRoot.Value.IsEmpty)
		{
			hash.AddBytes(signer.CertRoot.Value.Span);
		}

		hash.Add(signer.CertPublisher?.Value, StringComparer.OrdinalIgnoreCase);
		hash.Add(signer.CertOemID?.Value, StringComparer.OrdinalIgnoreCase);
		hash.Add(signer.CertIssuer?.Value, StringComparer.OrdinalIgnoreCase);

		return hash.ToHashCode();
	}
}
