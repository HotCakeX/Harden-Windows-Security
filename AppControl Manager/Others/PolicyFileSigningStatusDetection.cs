using System;
using System.Collections.Generic;

namespace AppControlManager.Others;

internal static class PolicyFileSigningStatusDetection
{

	/// <summary>
	/// Check the signing status of an App Control policy file
	/// </summary>
	/// <param name="policyXMLPath"></param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static IntelGathering.SignatureStatus Check(string policyXMLPath)
	{
		HashSet<string> supplementalSignerIDs = [];
		HashSet<string> updatePolicySignerIDs = [];

		// Instantiate the policy
		SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(policyXMLPath, null);

		// Check if SupplementalPolicySigners exists and get their IDs	
		if (policyObj.SupplementalPolicySigners.Length > 0)
		{
			foreach (SiPolicy.SupplementalPolicySigner item in policyObj.SupplementalPolicySigners)
			{
				_ = supplementalSignerIDs.Add(item.SignerId);
			}
		}

		// Check if UpdatePolicySigners exists and get their IDs
		if (policyObj.UpdatePolicySigners.Length > 0)
		{
			foreach (SiPolicy.UpdatePolicySigner item in policyObj.UpdatePolicySigners)
			{
				_ = updatePolicySignerIDs.Add(item.SignerId);
			}
		}

		// Return a status
		return (supplementalSignerIDs.Count > 0 || updatePolicySignerIDs.Count > 0) ? IntelGathering.SignatureStatus.IsSigned : IntelGathering.SignatureStatus.IsUnsigned;
	}
}
