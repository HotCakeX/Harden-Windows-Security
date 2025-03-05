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
/// Provides comparison logic for UpdatePolicySignerRule objects based on their SignerElement.
/// This comparer supports two matching rules to determine equality.
/// </summary>
internal sealed class UpdatePolicySignerRuleComparer : IEqualityComparer<UpdatePolicySignerRule>
{
	/// <summary>
	/// Determines whether two UpdatePolicySignerRule objects are equal based on their SignerElement.
	/// </summary>
	/// <param name="x">First UpdatePolicySignerRule object.</param>
	/// <param name="y">Second UpdatePolicySignerRule object.</param>
	/// <returns>True if the objects are considered equal, otherwise false.</returns>
	public bool Equals(UpdatePolicySignerRule? x, UpdatePolicySignerRule? y)
	{
		// Null checks
		if (x is null || y is null)
		{
			return false;
		}

		// Extract signer elements for comparison
		Signer signerX = x.SignerElement;
		Signer signerY = y.SignerElement;

		// Rule 1: Check if Name, CertRoot.Value, and CertPublisher.Value are equal
		if (IsSignerRule1Match(signerX, signerY))
		{
			return true;
		}

		// Rule 2: Check if Name and CertRoot.Value are equal
		if (IsSignerRule2Match(signerX, signerY))
		{
			return true;
		}

		// If none of the rules match, return false
		return false;
	}

	/// <summary>
	/// Generates a hash code for an UpdatePolicySignerRule based on its SignerElement.
	/// </summary>
	/// <param name="obj">The UpdatePolicySignerRule object.</param>
	/// <returns>A hash code for the object.</returns>
	public int GetHashCode(UpdatePolicySignerRule obj)
	{
		ArgumentNullException.ThrowIfNull(obj);

		Signer signer = obj.SignerElement;
		long hash = 17;  // Initial hash value
		const long modulus = 0x7FFFFFFF; // Maximum positive integer

		// Include Name in hash calculation if present
		if (!string.IsNullOrWhiteSpace(signer.Name))
		{
			hash = (hash * 31 + signer.Name.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		// Include CertRoot.Value in hash calculation if present
		if (signer.CertRoot?.Value != null)
		{
			hash = (hash * 31 + CustomMethods.GetByteArrayHashCode(signer.CertRoot.Value)) % modulus;
		}

		// Include CertPublisher.Value in hash calculation if present
		if (!string.IsNullOrWhiteSpace(signer.CertPublisher?.Value))
		{
			hash = (hash * 31 + signer.CertPublisher.Value.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
		}

		return (int)(hash & 0x7FFFFFFF); // Ensure non-negative hash
	}

	/// <summary>
	/// Rule 1: Name, CertRoot.Value, and CertPublisher.Value must match.
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
	/// Rule 2: Name and CertRoot.Value must match.
	/// </summary>
	private static bool IsSignerRule2Match(Signer signerX, Signer signerY)
	{
		return !string.IsNullOrWhiteSpace(signerX.Name) &&
			   !string.IsNullOrWhiteSpace(signerY.Name) &&
			   string.Equals(signerX.Name, signerY.Name, StringComparison.OrdinalIgnoreCase) &&
			   BytesArrayComparer.AreByteArraysEqual(signerX.CertRoot?.Value, signerY.CertRoot?.Value);
	}
}
