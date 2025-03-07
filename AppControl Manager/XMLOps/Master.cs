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

using System;
using System.IO;
using AppControlManager.Others;

namespace AppControlManager.XMLOps;

internal static class Master
{

	/// <summary>
	/// Uses the scan data to generate an App Control policy and makes sure the data are unique
	/// </summary>
	/// <param name="incomingData"></param>
	/// <param name="xmlFilePath"></param>
	internal static void Initiate(FileBasedInfoPackage incomingData, string xmlFilePath, SiPolicyIntel.Authorization authorization, string? stagingArea = null)
	{
		Logger.Write("Merging");

		if (authorization is SiPolicyIntel.Authorization.Allow)
		{
			NewFilePublisherLevelRules.CreateAllow(xmlFilePath, incomingData.FilePublisherSigners);
			NewPublisherLevelRules.CreateAllow(xmlFilePath, incomingData.PublisherSigners);
			NewHashLevelRules.CreateAllow(xmlFilePath, incomingData.CompleteHashes);
			NewFilePathRules.CreateAllow(xmlFilePath, incomingData.FilePaths);
			NewPFNLevelRules.CreateAllow(xmlFilePath, incomingData.PFNRules);

			SiPolicy.Merger.Merge(xmlFilePath, [xmlFilePath]);
		}
		else
		{
			NewFilePublisherLevelRules.CreateDeny(xmlFilePath, incomingData.FilePublisherSigners);
			NewPublisherLevelRules.CreateDeny(xmlFilePath, incomingData.PublisherSigners);
			NewHashLevelRules.CreateDeny(xmlFilePath, incomingData.CompleteHashes);
			NewFilePathRules.CreateDeny(xmlFilePath, incomingData.FilePaths);
			NewPFNLevelRules.CreateDeny(xmlFilePath, incomingData.PFNRules);

			// Path to the AllowAll XML file on the system
			string AllowAllFilePath = Path.Combine(Path.GetPathRoot(Environment.SystemDirectory)!, @"Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml");

			// Copy it to the staging area since it's inaccessible in the system directory
			string finalAllowAllFilePath = Path.Combine(stagingArea!, "AllowAll.xml");
			File.Copy(AllowAllFilePath, finalAllowAllFilePath, true);

			// Merge the policy with the AllowAll XML policy since this is a Deny policy type
			SiPolicy.Merger.Merge(xmlFilePath, [xmlFilePath, finalAllowAllFilePath]);
		}

	}
}
