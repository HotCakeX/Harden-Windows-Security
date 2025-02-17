using System;
using System.Collections.Generic;

namespace AppControlManager.Others;

internal static class CiPolicyHandler
{
	/// <summary>
	/// Removes the entire SupplementalPolicySigners block
	/// and any Signer in Signers node that have the same ID as the SignerIds of the SupplementalPolicySigner(s) in <SupplementalPolicySigners>...</SupplementalPolicySigners> node
	/// from a CI policy XML file
	/// </summary>
	/// <param name="path">The path to the CI policy XML file</param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void RemoveSupplementalSigners(string path)
	{

		SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(path, null);

		// Check if SupplementalPolicySigners exists and has child nodes
		if (policyObj.SupplementalPolicySigners.Length > 0)
		{
			Logger.Write("Removing the SupplementalPolicySigners blocks and corresponding Signers");

			// Store SignerIds to remove
			HashSet<string> signerIdsToRemove = [];

			// Loop through each SupplementalPolicySigner
			foreach (SiPolicy.SupplementalPolicySigner supplementalPolicySigner in policyObj.SupplementalPolicySigners)
			{
				_ = signerIdsToRemove.Add(supplementalPolicySigner.SignerId);
			}

			// Remove the corresponding signers for the SupplementalPolicySigners
			if (policyObj.Signers.Length < 0)
			{
				List<SiPolicy.Signer> signers = [.. policyObj.Signers];

				foreach (SiPolicy.Signer signer in signers)
				{
					if (signerIdsToRemove.Contains(signer.ID))
					{
						_ = signers.Remove(signer);
					}
				}
				policyObj.Signers = [.. signers];
			}
		}

		// Save the updated policy
		SiPolicy.Management.SavePolicyToFile(policyObj, path);
	}
}
