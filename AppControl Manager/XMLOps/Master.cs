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

using AppControlManager.Others;
using AppControlManager.SiPolicy;

namespace AppControlManager.XMLOps;

internal static class Master
{

	/// <summary>
	/// Uses the scan data to generate an App Control policy and makes sure the data are unique
	/// </summary>
	/// <param name="incomingData">Contains information about file publisher signers, publisher signers, complete hashes, file paths, and PFN rules.</param>
	/// <param name="authorization">Determines whether to allow or deny the specified rules during the merging process.</param>
	/// <param name="noAllowAllWildCards">If true, the policy containing the 2 Allow all rules for user mode and kernel mode file authorization will not be merged with the final policy.</param>
	internal static SiPolicy.SiPolicy Initiate(
		FileBasedInfoPackage incomingData,
		SiPolicyIntel.Authorization authorization,
		bool noAllowAllWildCards = false)
	{
		Logger.Write(GlobalVars.GetStr("MergingRulesMessage"));

		// Grab a copy of an empty policy object for data insertion
		SiPolicy.SiPolicy policyObj = CustomPolicyCreator.CreateEmpty();

		if (authorization is SiPolicyIntel.Authorization.Allow)
		{
			policyObj = NewWHQLFilePublisherLevelRules.CreateAllow(policyObj, incomingData.WHQLFilePublisherSigners);
			policyObj = NewFilePublisherLevelRules.CreateAllow(policyObj, incomingData.FilePublisherSigners);
			policyObj = NewPublisherLevelRules.CreateAllow(policyObj, incomingData.PublisherSigners);
			policyObj = NewHashLevelRules.CreateAllow(policyObj, incomingData.CompleteHashes);
			policyObj = NewFilePathRules.CreateAllow(policyObj, incomingData.FilePaths);
			policyObj = NewPFNLevelRules.CreateAllow(policyObj, incomingData.PFNRules);
			policyObj = NewFileNameLevelRules.CreateAllow(policyObj, incomingData.FileNameRules);

			policyObj = Merger.Merge(policyObj, null);
		}
		else
		{
			policyObj = NewWHQLFilePublisherLevelRules.CreateDeny(policyObj, incomingData.WHQLFilePublisherSigners);
			policyObj = NewFilePublisherLevelRules.CreateDeny(policyObj, incomingData.FilePublisherSigners);
			policyObj = NewPublisherLevelRules.CreateDeny(policyObj, incomingData.PublisherSigners);
			policyObj = NewHashLevelRules.CreateDenyEx(policyObj, incomingData.CompleteHashes);
			policyObj = NewFilePathRules.CreateDenyEx(policyObj, incomingData.FilePaths);
			policyObj = NewPFNLevelRules.CreateDenyEx(policyObj, incomingData.PFNRules);
			policyObj = NewFileNameLevelRules.CreateDeny(policyObj, incomingData.FileNameRules);

			if (noAllowAllWildCards)
			{
				policyObj = Merger.Merge(policyObj, null);
			}
			else
			{
				SiPolicy.SiPolicy allowAllPolicyObj = Management.Initialize(GlobalVars.AllowAllTemplatePolicyPath, null);

				// Merge the policy with the AllowAll XML policy since this is a Deny policy type
				policyObj = Merger.Merge(policyObj, [allowAllPolicyObj]);
			}
		}

		return policyObj;
	}
}
