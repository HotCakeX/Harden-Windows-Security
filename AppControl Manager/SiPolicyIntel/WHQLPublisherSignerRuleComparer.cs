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
		if (IsSignerRule1Match(signerX, signerY) && DoCertEKUsMatch(signerX, signerY))
		{
			return true;
		}

		// Rule 2: Check if Name and CertRoot.Value are equal
		// And CertEKUs match
		// For WHQL but PCA/Root/Leaf certificate signer types
		if (IsSignerRule2Match(signerX, signerY) && DoCertEKUsMatch(signerX, signerY))
		{
			return true;
		}


		// If none of the rules match, the WHQLPublisher objects are not equal
		return false;
	}

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


}
