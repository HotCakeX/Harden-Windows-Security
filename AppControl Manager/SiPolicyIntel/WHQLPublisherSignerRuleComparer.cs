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
using System.Collections.Generic;
using AppControlManager.SiPolicy;

namespace AppControlManager.SiPolicyIntel;

/// <summary>
/// Provides custom equality comparison for <see cref="WHQLPublisher"/> objects.
/// Two WHQLPublisher objects are considered equal if:
/// - Their SigningScenario and Auth properties match.
/// - Their signer elements match based on either:
///   Rule 1: Name, CertRoot.Value, and CertPublisher.Value match and their EKU lists are equivalent, or
///   Rule 2: Name and CertRoot.Value match and their EKU lists are equivalent.
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

		// Extract the signer elements from the packages
		Signer signerX = x.SignerElement;
		Signer signerY = y.SignerElement;

		// Rule 1: Check if Name, CertRoot.Value, and CertPublisher.Value are equal
		// And CertEKUs match
		// For intermediate certificate type that uses full proper chain in signer
		if (Merger.IsSignerRule1Match(signerX, signerY) && Merger.DoEKUsMatch(x.Ekus, y.Ekus))
		{
			return true;
		}

		// Rule 2: Check if Name and CertRoot.Value are equal
		// And CertEKUs match
		// For WHQL but PCA/Root/Leaf certificate signer types
		if (Merger.IsSignerRule2Match(signerX, signerY) && Merger.DoEKUsMatch(x.Ekus, y.Ekus))
		{
			return true;
		}


		// If none of the rules match, the WHQLPublisher objects are not equal
		return false;
	}

	/// <summary>
	/// Generates a hash code for a WHQLPublisher object.
	/// </summary>
	public int GetHashCode(WHQLPublisher obj)
	{
		Signer signer = obj.SignerElement;
		long hash = 17;  // Start with an initial value

		// First: Include SSType and Authorization in the hash calculation
		hash = (hash * 31 + obj.SigningScenario.GetHashCode()) % Merger.modulus;
		hash = (hash * 31 + obj.Auth.GetHashCode()) % Merger.modulus;

		// Rule 1: Use Name, CertRoot.Value, and CertPublisher.Value for hash calculation
		if (!string.IsNullOrWhiteSpace(signer.Name))
		{
			hash = (hash * 31 + signer.Name.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		if (signer.CertRoot?.Value is not null)
		{
			hash = (hash * 31 + CustomMethods.GetByteArrayHashCode(signer.CertRoot.Value)) % Merger.modulus;
		}

		if (!string.IsNullOrWhiteSpace(signer.CertPublisher?.Value))
		{
			hash = (hash * 31 + signer.CertPublisher.Value.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		// Rule 2: Use Name and CertRoot.Value for hash calculation
		if (!string.IsNullOrWhiteSpace(signer.Name))
		{
			hash = (hash * 31 + signer.Name.GetHashCode(StringComparison.OrdinalIgnoreCase)) % Merger.modulus;
		}

		if (signer.CertRoot?.Value is not null)
		{
			hash = (hash * 31 + CustomMethods.GetByteArrayHashCode(signer.CertRoot.Value)) % Merger.modulus;
		}


		// Rule 3: Include EKU Values
		foreach (EKU eku in obj.Ekus)
		{
			if (eku.Value is not null)
			{
				hash = (hash * 31 + CustomMethods.GetByteArrayHashCode(eku.Value)) % Merger.modulus;
			}
		}

		// Ensure non-negative hash value
		return (int)(hash & 0x7FFFFFFF);
	}
}
