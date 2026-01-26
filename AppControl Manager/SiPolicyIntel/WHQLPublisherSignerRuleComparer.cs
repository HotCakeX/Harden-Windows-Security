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
using System.Runtime.InteropServices;
using AppControlManager.SiPolicy;

namespace AppControlManager.SiPolicyIntel;

/// <summary>
/// Provides custom equality comparison for <see cref="WHQLPublisher"/> objects.
/// Two WHQLPublisher objects are considered equal if:
/// - Their SigningScenario and Auth properties match.
/// - Their Signer elements have matching properties based on the <see cref="Merger.IsSignerRuleMatch(Signer, Signer)"/>
/// - Their EKU lists are equivalent.
/// </summary>

internal sealed class WHQLPublisherSignerRuleComparer : IEqualityComparer<WHQLPublisher>
{
	public bool Equals(WHQLPublisher? x, WHQLPublisher? y)
	{
		if (x is null || y is null)
		{
			return false;
		}

		// First check: SSType and Authorization must be equal
		// Both signers must belong to the same signing scenario and must be either Allow or Block
		if (x.SigningScenario != y.SigningScenario || x.Auth != y.Auth)
		{
			return false;
		}

		return Merger.IsSignerRuleMatch(x.SignerElement, y.SignerElement) && Merger.DoEKUsMatch(x.Ekus, y.Ekus);
	}

	/// <summary>
	/// Generates a hash code for a WHQLPublisher object.
	/// </summary>
	public int GetHashCode(WHQLPublisher obj)
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

		// Include EKU Values
		foreach (EKU eku in CollectionsMarshal.AsSpan(obj.Ekus))
		{
			if (!eku.Value.IsEmpty)
			{
				hash.AddBytes(eku.Value.Span);
			}
		}

		return hash.ToHashCode();
	}
}
