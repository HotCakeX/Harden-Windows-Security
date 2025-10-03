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
/// Provides custom equality comparison for <see cref="FilePublisherSignerRule"/> objects.
/// Two FilePublisherSignerRule objects are considered equal if:
/// - Their SigningScenario and Auth properties match.
/// - Depending on the signer properties, either Rule 1 or Rule 2 conditions are met:
///   Rule 1: Signer.Name, Signer.CertRoot.Value, and Signer.CertPublisher.Value are equal.
///   Rule 2: Signer.Name and Signer.CertRoot.Value are equal.
///
/// When a match is found, the FileAttribElements of the new rule are merged into the existing rule.
/// </summary>

internal sealed class FilePublisherSignerRuleComparer : IEqualityComparer<FilePublisherSignerRule>
{
	public bool Equals(FilePublisherSignerRule? x, FilePublisherSignerRule? y)
	{
		// If at least one of them is null then they are not the same
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
		// For intermediate certificate type that uses full proper chain in signer
		if (Merger.IsSignerRule1Match(signerX, signerY))
		{
			// Merge the FileAttribElements of the ignored rule into the existing one
			MergeFileAttribElements(x, y);
			return true;
		}

		// Rule 2: Check if Name and CertRoot.Value are equal
		// For PCA/Root/Leaf certificate signer types
		if (Merger.IsSignerRule2Match(signerX, signerY))
		{
			// Merge the FileAttribElements of the ignored rule into the existing one
			MergeFileAttribElements(x, y);
			return true;
		}

		// If none of the rules match, the FilePublisherSignerRule objects are not equal
		return false;
	}

	public int GetHashCode(FilePublisherSignerRule obj)
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

		return (int)(hash & 0x7FFFFFFF); // Ensure non-negative hash value
	}


	// Merge FileAttribElements of the ignored rule into the existing one
	// To determine whether the fileAttrib we're adding to the <FileRules> node already exists there or not
	private static void MergeFileAttribElements(FilePublisherSignerRule existing, FilePublisherSignerRule newRule)
	{
		if (newRule.FileAttribElements is null || existing.FileAttribElements is null)
			return;

		foreach (FileAttrib newFileAttrib in newRule.FileAttribElements)
		{

			// Add the new rule's file attrib to the existing rule
			existing.FileAttribElements.Add(newFileAttrib);

			FileAttribRef fileAttribRef = new()
			{
				RuleID = newFileAttrib.ID
			};

			// Convert the array to list for easy modification
			List<FileAttribRef> List1 = [.. existing.SignerElement.FileAttribRef];

			List1.Add(fileAttribRef);

			// Convert the list back to array
			existing.SignerElement.FileAttribRef = [.. List1];
		}
	}
}
