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
using System.Linq;
using AppControlManager.Others;
using AppControlManager.SiPolicy;

namespace AppControlManager.XMLOps;

internal static partial class PreDeploymentChecks
{
	/// <summary>
	/// Takes an <see cref="SiPolicy.SiPolicy"/> and checks whether it has an allow all rule.
	/// </summary>
	/// <param name="policyObj"></param>
	/// <returns></returns>
	internal static bool CheckForAllowAll(SiPolicy.SiPolicy policyObj)
	{
		// Check if the policy contains any FileRules
		if (policyObj.FileRules is { Count: > 0 })
		{
			// Check for any Allow rule that has FileName="*"
			return policyObj.FileRules
				.OfType<Allow>()
				.Any(rule => string.Equals(rule.FileName, "*", StringComparison.OrdinalIgnoreCase));
		}

		return false;
	}

	/// <summary>
	/// Throws an error if the system has a deployed Signed policy with the same PolicyID as the PolicyID of the PolicyObj that is provided to the method.
	/// We use it to make sure we don't deploy and Unsigned policy to the local system while there is already a Signed policy with the same PolicyID already deployed.
	/// </summary>
	/// <param name="policyObj"></param>
	internal static void CheckForSignatureConflict(SiPolicy.SiPolicy policyObj)
	{
		// If the policy is indeed Unsigned
		if (policyObj.Rules.Any(r => r.Item == OptionType.EnabledUnsignedSystemIntegrityPolicy))
		{
			// Get all of the deployed Base/AppIDTagging and Supplemental policies on the system
			List<CiPolicyInfo> policies = CiToolHelper.GetPolicies(false, true, true);

			CiPolicyInfo? possibleAlreadyDeployedSignedVersion = policies.
			FirstOrDefault(x => x.IsSignedPolicy && string.Equals(policyObj.PolicyID.Trim('{', '}'), x.PolicyID, StringComparison.OrdinalIgnoreCase));

			if (possibleAlreadyDeployedSignedVersion is not null)
			{
				throw new InvalidOperationException($"There is a Signed policy with the ID '{possibleAlreadyDeployedSignedVersion.PolicyID}' that's already deployed on the system. You cannot deploy an Unsigned policy with the same ID on the same system.");
			}
		}
	}

}
