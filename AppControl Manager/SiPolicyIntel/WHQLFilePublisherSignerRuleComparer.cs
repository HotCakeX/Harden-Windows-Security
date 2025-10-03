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
/// Provides custom equality comparison for <see cref="WHQLFilePublisher"/> objects.
/// Two WHQLFilePublisher objects are considered equal if:
/// - Their SigningScenario and Auth properties match.
/// - Their Signer elements match based on either:
///   Rule 1: Name, CertRoot.Value, and CertPublisher.Value match and their EKU lists are equivalent, or
///   Rule 2: Name and CertRoot.Value match and their EKU lists are equivalent.
///
/// When a match is detected, the FileAttribElements from the duplicate rule are merged into the existing rule.
/// </summary>
internal sealed class WHQLFilePublisherSignerRuleComparer : IEqualityComparer<WHQLFilePublisher>
{
	public bool Equals(WHQLFilePublisher? x, WHQLFilePublisher? y)
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

		Signer signerX = x.SignerElement;
		Signer signerY = y.SignerElement;

		// Rule 1: Check if Name, CertRoot.Value, and CertPublisher.Value are equal
		// And certEKUs match
		// For WHQLFilePublisher
		if (Merger.IsSignerRule1Match(signerX, signerY) && Merger.DoEKUsMatch(x.Ekus, y.Ekus))
		{
			// Merge the FileAttribElements of the ignored rule into the existing one
			MergeFileAttribElements(x, y);
			return true;
		}

		// Rule 2: Check if Name and CertRoot.Value are equal
		// And certEKUs match
		// For WHQL but PCA/Root/Leaf certificate signer types
		if (Merger.IsSignerRule2Match(signerX, signerY) && Merger.DoEKUsMatch(x.Ekus, y.Ekus))
		{
			// Merge the FileAttribElements of the ignored rule into the existing one
			MergeFileAttribElements(x, y);
			return true;
		}


		// If none of the rules match, the WHQLFilePublisher objects are not equal
		return false;
	}

	public int GetHashCode(WHQLFilePublisher obj)
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

		return (int)(hash & 0x7FFFFFFF); // Ensure non-negative hash value
	}

	/// <summary>
	/// Merge FileAttribElements of the ignored rule into the existing one
	/// </summary>
	/// <param name="existing"></param>
	/// <param name="newRule"></param>
	private static void MergeFileAttribElements(WHQLFilePublisher existing, WHQLFilePublisher newRule)
	{
		if (newRule.FileAttribElements is null || existing.FileAttribElements is null)
			return;

		foreach (FileAttrib fileAttrib in newRule.FileAttribElements)
		{
			existing.FileAttribElements.Add(fileAttrib);

			FileAttribRef fileAttribRef = new()
			{
				RuleID = fileAttrib.ID
			};

			List<FileAttribRef> List1 = [.. existing.SignerElement.FileAttribRef];

			List1.Add(fileAttribRef);

			existing.SignerElement.FileAttribRef = [.. List1];
		}
	}
}
