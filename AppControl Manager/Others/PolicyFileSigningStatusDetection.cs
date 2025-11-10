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

namespace AppControlManager.Others;

internal static class PolicyFileSigningStatusDetection
{

	/// <summary>
	/// Check the signing status of an App Control policy file.	
	/// </summary>
	/// <param name="policyXMLPath">Path to the policy XML file.</param>
	/// <returns>IsSigned if either signer collection is non-empty; otherwise IsUnsigned.</returns>
	internal static IntelGathering.SignatureStatus Check(string policyXMLPath)
	{
		SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(policyXMLPath, null);

		return (policyObj.SupplementalPolicySigners.Length > 0 || policyObj.UpdatePolicySigners.Length > 0)
			? IntelGathering.SignatureStatus.IsSigned
			: IntelGathering.SignatureStatus.IsUnsigned;
	}
}
