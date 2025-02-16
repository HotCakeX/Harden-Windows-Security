using System;

namespace AppControlManager.XMLOps;

internal static class PolicyEditor
{
	/// <summary>
	/// Swaps the PolicyID and BasePolicyID GUIDs in an App Control for Business policy XML file for Base policies.
	/// </summary>
	/// <param name="policyIdInput"></param>
	/// <param name="policyFilePathInput"></param>
	internal static void EditGuids(string policyIdInput, string policyFilePathInput)

	{
		// Instantiate the policy
		SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(policyFilePathInput, null);

		if (policyObj.PolicyType is SiPolicy.PolicyType.SupplementalPolicy)
		{
			throw new InvalidOperationException("Don't use this method for Supplemental policies");
		}

		string policyId = "{" + policyIdInput + "}";

		policyObj.BasePolicyID = policyId;
		policyObj.PolicyID = policyId;

		SiPolicy.Management.SavePolicyToFile(policyObj, policyFilePathInput);
	}
}
