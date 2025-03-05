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
using System.Linq;
using AppControlManager.SiPolicy;

namespace AppControlManager.SiPolicyIntel;

/// <summary>
/// Custom HashSet comparer to de-duplicate WHQLFilePublisher Signers
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
		if (IsSignerRule1Match(signerX, signerY) && DoEKUsMatch(x.Ekus, y.Ekus))
		{
			return true;
		}

		// Rule 2: Check if Name and CertRoot.Value are equal
		// And CertEKUs match
		// For WHQL but PCA/Root/Leaf certificate signer types
		if (IsSignerRule2Match(signerX, signerY) && DoEKUsMatch(x.Ekus, y.Ekus))
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
		ArgumentNullException.ThrowIfNull(obj);

		Signer signer = obj.SignerElement;
		long hash = 17;  // Start with an initial value

		const long modulus = 0x7FFFFFFF; // Max value for int

		// First: Include SSType and Authorization in the hash calculation
		hash = (hash * 31 + obj.SigningScenario.GetHashCode()) % modulus;
		hash = (hash * 31 + obj.Auth.GetHashCode()) % modulus;

		// Rule 1: Use Name, CertRoot.Value, and CertPublisher.Value for hash calculation
		if (!string.IsNullOrWhiteSpace(signer.Name))
		{
			hash = (hash * 31 + signer.Name.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		if (signer.CertRoot?.Value != null)
		{
			hash = (hash * 31 + CustomMethods.GetByteArrayHashCode(signer.CertRoot.Value)) % modulus;
		}

		if (!string.IsNullOrWhiteSpace(signer.CertPublisher?.Value))
		{
			hash = (hash * 31 + signer.CertPublisher.Value.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		// Rule 2: Use Name and CertRoot.Value for hash calculation
		if (!string.IsNullOrWhiteSpace(signer.Name))
		{
			hash = (hash * 31 + signer.Name.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		if (signer.CertRoot?.Value != null)
		{
			hash = (hash * 31 + CustomMethods.GetByteArrayHashCode(signer.CertRoot.Value)) % modulus;
		}


		// Rule 3: Include EKU Values
		foreach (EKU eku in obj.Ekus)
		{
			if (eku.Value != null)
			{
				hash = (hash * 31 + CustomMethods.GetByteArrayHashCode(eku.Value)) % modulus;
			}
		}

		// Ensure non-negative hash value
		return (int)(hash & 0x7FFFFFFF);
	}

	/// <summary>
	/// Rule 1: Name, CertRoot.Value, CertPublisher.Value must match
	/// </summary>
	private static bool IsSignerRule1Match(Signer signerX, Signer signerY)
	{
		return !string.IsNullOrWhiteSpace(signerX.Name) &&
			   !string.IsNullOrWhiteSpace(signerY.Name) &&
			   string.Equals(signerX.Name, signerY.Name, StringComparison.OrdinalIgnoreCase) &&
			   BytesArrayComparer.AreByteArraysEqual(signerX.CertRoot?.Value, signerY.CertRoot?.Value) &&
			   string.Equals(signerX.CertPublisher?.Value, signerY.CertPublisher?.Value, StringComparison.OrdinalIgnoreCase);
	}


	/// <summary>
	/// Rule 2: Name and CertRoot.Value must match
	/// </summary>
	private static bool IsSignerRule2Match(Signer signerX, Signer signerY)
	{
		return !string.IsNullOrWhiteSpace(signerX.Name) &&
			   !string.IsNullOrWhiteSpace(signerY.Name) &&
			   string.Equals(signerX.Name, signerY.Name, StringComparison.OrdinalIgnoreCase) &&
			   BytesArrayComparer.AreByteArraysEqual(signerX.CertRoot?.Value, signerY.CertRoot?.Value);
	}


	/// <summary>
	/// Rule 3: Compare EKU lists based on Value only (ignore IDs)
	/// </summary>
	/// <param name="ekusX">EKU list for first signer</param>
	/// <param name="ekusY">EKU list for second signer</param>
	/// <returns>True if EKU values match</returns>
	private static bool DoEKUsMatch(List<EKU> ekusX, List<EKU> ekusY)
	{

		// Extract EKU values and ignore IDs
		HashSet<int> ekuValuesX = [.. ekusX.Where(e => e.Value != null).Select(e => CustomMethods.GetByteArrayHashCode(e.Value))];

		HashSet<int> ekuValuesY = [.. ekusY.Where(e => e.Value != null).Select(e => CustomMethods.GetByteArrayHashCode(e.Value))];

		// Compare sets of EKU values
		return ekuValuesX.SetEquals(ekuValuesY);
	}


}
