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
