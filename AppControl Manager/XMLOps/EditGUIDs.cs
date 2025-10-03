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
