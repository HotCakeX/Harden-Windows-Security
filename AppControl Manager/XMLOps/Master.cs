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

using System.IO;
using AppControlManager.Others;

namespace AppControlManager.XMLOps;

internal static class Master
{

	/// <summary>
	/// Uses the scan data to generate an App Control policy and makes sure the data are unique
	/// </summary>
	/// <param name="incomingData">Contains information about file publisher signers, publisher signers, complete hashes, file paths, and PFN rules.</param>
	/// <param name="xmlFilePath">Specifies the path to the XML file where the merged policy rules will be saved.</param>
	/// <param name="authorization">Determines whether to allow or deny the specified rules during the merging process.</param>
	/// <param name="stagingArea">Indicates the location where temporary files can be stored during the merging operation.</param>
	/// <param name="noAllowAllWildCards">If true, the policy containing the 2 Allow all rules for user mode and kernel mode file authorization will not be merged with the final policy.</param>
	internal static void Initiate(
		FileBasedInfoPackage incomingData,
		string xmlFilePath,
		SiPolicyIntel.Authorization authorization,
		string? stagingArea = null,
		bool noAllowAllWildCards = false)
	{
		Logger.Write(GlobalVars.GetStr("MergingRulesMessage"));

		if (authorization is SiPolicyIntel.Authorization.Allow)
		{
			NewWHQLFilePublisherLevelRules.CreateAllow(xmlFilePath, incomingData.WHQLFilePublisherSigners);
			NewFilePublisherLevelRules.CreateAllow(xmlFilePath, incomingData.FilePublisherSigners);
			NewPublisherLevelRules.CreateAllow(xmlFilePath, incomingData.PublisherSigners);
			NewHashLevelRules.CreateAllow(xmlFilePath, incomingData.CompleteHashes);
			NewFilePathRules.CreateAllow(xmlFilePath, incomingData.FilePaths);
			NewPFNLevelRules.CreateAllow(xmlFilePath, incomingData.PFNRules);

			SiPolicy.Merger.Merge(xmlFilePath, [xmlFilePath]);
		}
		else
		{
			NewWHQLFilePublisherLevelRules.CreateDeny(xmlFilePath, incomingData.WHQLFilePublisherSigners);
			NewFilePublisherLevelRules.CreateDeny(xmlFilePath, incomingData.FilePublisherSigners);
			NewPublisherLevelRules.CreateDeny(xmlFilePath, incomingData.PublisherSigners);
			NewHashLevelRules.CreateDeny(xmlFilePath, incomingData.CompleteHashes);
			NewFilePathRules.CreateDeny(xmlFilePath, incomingData.FilePaths);
			NewPFNLevelRules.CreateDeny(xmlFilePath, incomingData.PFNRules);

			string finalAllowAllFilePath = Path.Combine(stagingArea!, "AllowAll.xml");
			File.Copy(GlobalVars.AllowAllTemplatePolicyPath, finalAllowAllFilePath, true);

			if (noAllowAllWildCards)
			{
				SiPolicy.Merger.Merge(xmlFilePath, [xmlFilePath]);
			}
			else
			{
				// Merge the policy with the AllowAll XML policy since this is a Deny policy type
				SiPolicy.Merger.Merge(xmlFilePath, [xmlFilePath, finalAllowAllFilePath]);
			}
		}

	}
}
