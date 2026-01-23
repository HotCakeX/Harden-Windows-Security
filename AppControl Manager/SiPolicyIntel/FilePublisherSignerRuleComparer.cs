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
/// Provides custom equality comparison for <see cref="FilePublisherSignerRule"/> objects.
/// Two FilePublisherSignerRule objects are considered equal if:
/// - Their SigningScenario and Auth properties match.
/// - Their Signer elements have matching properties based on the <see cref="Merger.IsSignerRuleMatch(Signer, Signer)"/>
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

		if (Merger.IsSignerRuleMatch(x.SignerElement, y.SignerElement))
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


	// Merge FileAttribElements of the ignored rule into the existing one
	// To determine whether the fileAttrib we're adding to the <FileRules> node already exists there or not
	private static void MergeFileAttribElements(FilePublisherSignerRule existing, FilePublisherSignerRule newRule)
	{
		if (newRule.FileAttribElements is null || existing.FileAttribElements is null)
			return;

		if (existing.SignerElement.FileAttribRef is null)
			existing.SignerElement.FileAttribRef = [];

		foreach (FileAttrib newFileAttrib in CollectionsMarshal.AsSpan(newRule.FileAttribElements))
		{
			// Add the new rule's file attrib to the existing rule
			existing.FileAttribElements.Add(newFileAttrib);

			existing.SignerElement.FileAttribRef.Add(new(ruleID: newFileAttrib.ID));
		}
	}
}
