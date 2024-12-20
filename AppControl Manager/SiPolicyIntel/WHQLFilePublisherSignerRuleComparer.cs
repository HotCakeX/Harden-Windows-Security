using System;
using System.Collections.Generic;
using System.Linq;
using AppControlManager.SiPolicy;

namespace AppControlManager.SiPolicyIntel;

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
		if (IsSignerRule1Match(signerX, signerY) && DoCertEKUsMatch(signerX, signerY))
		{
			// Merge the FileAttribElements of the ignored rule into the existing one
			MergeFileAttribElements(x, y);
			return true;
		}

		// Rule 2: Check if Name and CertRoot.Value are equal
		// And certEKUs match
		// For WHQL but PCA/Root/Leaf certificate signer types
		if (IsSignerRule2Match(signerX, signerY) && DoCertEKUsMatch(signerX, signerY))
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

		// Rule 3: Include CertEKU IDs in the hash
		foreach (CertEKU certEKU in signer.CertEKU ?? [])
		{
			if (!string.IsNullOrWhiteSpace(certEKU.ID))
			{
				hash = (hash * 31 + certEKU.ID.GetHashCode(StringComparison.OrdinalIgnoreCase)) % modulus;
			}
		}

		return (int)(hash & 0x7FFFFFFF); // Ensure non-negative hash value
	}


	/// <summary>
	/// Rule 1: Name, CertRoot.Value, CertPublisher.Value must match
	/// </summary>
	/// <param name="signerX"></param>
	/// <param name="signerY"></param>
	/// <returns></returns>
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
	/// <param name="signerX"></param>
	/// <param name="signerY"></param>
	/// <returns></returns>
	private static bool IsSignerRule2Match(Signer signerX, Signer signerY)
	{
		return !string.IsNullOrWhiteSpace(signerX.Name) &&
			   !string.IsNullOrWhiteSpace(signerY.Name) &&
			   string.Equals(signerX.Name, signerY.Name, StringComparison.OrdinalIgnoreCase) &&
			   BytesArrayComparer.AreByteArraysEqual(signerX.CertRoot?.Value, signerY.CertRoot?.Value);
	}


	/// <summary>
	/// Rule 3: CertEKU IDs must match
	/// </summary>
	/// <param name="signerX"></param>
	/// <param name="signerY"></param>
	/// <returns></returns>
	private static bool DoCertEKUsMatch(Signer signerX, Signer signerY)
	{
		HashSet<string> ekuIdsX = signerX.CertEKU?.Select(e => e.ID).Where(id => !string.IsNullOrWhiteSpace(id)).ToHashSet(StringComparer.OrdinalIgnoreCase)
					  ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);

		HashSet<string> ekuIdsY = signerY.CertEKU?.Select(e => e.ID).Where(id => !string.IsNullOrWhiteSpace(id)).ToHashSet(StringComparer.OrdinalIgnoreCase)
					  ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);

		return ekuIdsX.SetEquals(ekuIdsY);
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
			bool shouldAdd = true;

			foreach (FileAttrib existingFileAttrib in existing.FileAttribElements)
			{
				// Check Rule 4: MinimumFileVersion or MaximumFileVersion comparison
				bool hasMinX = !string.IsNullOrWhiteSpace(fileAttrib.MinimumFileVersion);
				bool hasMaxX = !string.IsNullOrWhiteSpace(fileAttrib.MaximumFileVersion);
				bool hasMinY = !string.IsNullOrWhiteSpace(existingFileAttrib.MinimumFileVersion);
				bool hasMaxY = !string.IsNullOrWhiteSpace(existingFileAttrib.MaximumFileVersion);

				// Rule: If both elements have MinimumFileVersion or both have MaximumFileVersion
				if (
					 ((hasMinX && hasMinY) || (hasMaxX && hasMaxY)) && (string.Equals(fileAttrib.MinimumFileVersion, existingFileAttrib.MinimumFileVersion, StringComparison.OrdinalIgnoreCase) || string.Equals(fileAttrib.MaximumFileVersion, existingFileAttrib.MaximumFileVersion, StringComparison.OrdinalIgnoreCase))
					 )
				{
					// Check if any of the name-related properties are the same
					bool nameMatch =
						(!string.IsNullOrWhiteSpace(fileAttrib.InternalName) && string.Equals(fileAttrib.InternalName, existingFileAttrib.InternalName, StringComparison.OrdinalIgnoreCase)) ||
						(!string.IsNullOrWhiteSpace(fileAttrib.FileDescription) && string.Equals(fileAttrib.FileDescription, existingFileAttrib.FileDescription, StringComparison.OrdinalIgnoreCase)) ||
						(!string.IsNullOrWhiteSpace(fileAttrib.ProductName) && string.Equals(fileAttrib.ProductName, existingFileAttrib.ProductName, StringComparison.OrdinalIgnoreCase)) ||
						(!string.IsNullOrWhiteSpace(fileAttrib.FileName) && string.Equals(fileAttrib.FileName, existingFileAttrib.FileName, StringComparison.OrdinalIgnoreCase));

					// If there's a name match, then don't add the FileAttrib
					if (nameMatch)
					{
						shouldAdd = false;
						break; // No need to add this FileAttrib, exit the loop
					}
				}
			}

			// If the FileAttrib should be added, then add it
			if (shouldAdd)
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
}
