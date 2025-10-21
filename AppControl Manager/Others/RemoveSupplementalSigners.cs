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
			Logger.Write(
				GlobalVars.GetStr("RemovingSupplementalPolicySignersBlocksAndCorrespondingSignersMessage")
			);

			// Store SignerIds to remove
			HashSet<string> signerIdsToRemove = new(StringComparer.OrdinalIgnoreCase);

			// Loop through each SupplementalPolicySigner
			foreach (SiPolicy.SupplementalPolicySigner supplementalPolicySigner in policyObj.SupplementalPolicySigners)
			{
				_ = signerIdsToRemove.Add(supplementalPolicySigner.SignerId);
			}

			if (policyObj.Signers.Length > 0)
			{
				List<SiPolicy.Signer> signers = [.. policyObj.Signers];

				// Remove the corresponding signers for the SupplementalPolicySigners
				_ = signers.RemoveAll(signer => signerIdsToRemove.Contains(signer.ID));

				policyObj.Signers = [.. signers];
			}

			// Remove the entire SupplementalPolicySigners block by clearing its array.
			policyObj.SupplementalPolicySigners = [];
		}

		// Save the updated policy
		SiPolicy.Management.SavePolicyToFile(policyObj, path);
	}
}
