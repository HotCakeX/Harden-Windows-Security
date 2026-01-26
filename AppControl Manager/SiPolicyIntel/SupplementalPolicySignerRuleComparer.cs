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
/// Provides comparison logic for SupplementalPolicySignerRule objects based on their SignerElement.
/// This comparer supports two matching rules to determine equality.
/// </summary>
internal sealed class SupplementalPolicySignerRuleComparer : IEqualityComparer<SupplementalPolicySignerRule>
{
	/// <summary>
	/// Determines whether two SupplementalPolicySignerRule objects are equal based on their SignerElement.
	/// </summary>
	/// <param name="x">First SupplementalPolicySignerRule object.</param>
	/// <param name="y">Second SupplementalPolicySignerRule object.</param>
	/// <returns>True if the objects are considered equal, otherwise false.</returns>
	public bool Equals(SupplementalPolicySignerRule? x, SupplementalPolicySignerRule? y)
	{
		// Null checks
		if (x is null || y is null)
		{
			return false;
		}

		return Merger.IsSignerRuleMatch(x.SignerElement, y.SignerElement);
	}

	/// <summary>
	/// Generates a hash code for a SupplementalPolicySignerRule based on its SignerElement.
	/// </summary>
	/// <param name="obj">The SupplementalPolicySignerRule object.</param>
	/// <returns>A hash code for the object.</returns>
	public int GetHashCode(SupplementalPolicySignerRule obj)
	{
		HashCode hash = new();
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
