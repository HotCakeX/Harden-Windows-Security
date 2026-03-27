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
using System.Runtime.InteropServices;
using AppControlManager.Others;
using AppControlManager.SiPolicy;

namespace AppControlManager.XMLOps;

internal static class NewPFNLevelRules
{
	/// <summary>
	/// Creates PFN rules and adds them to the SiPolicy object
	/// </summary>
	/// <param name="siPolicy"></param>
	/// <param name="PFNData"></param>
	/// <returns>Modified SiPolicy object</returns>
	internal static SiPolicy.SiPolicy CreateAllow(SiPolicy.SiPolicy siPolicy, List<PFNRuleCreator> PFNData)
	{
		if (PFNData.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoPackageFamilyNamesDetectedAllowMessage"));
			return siPolicy;
		}

		// Ensure the lists are initialized
		siPolicy.FileRules ??= [];

		// Ensure Scenarios exist
		SigningScenario umciScenario = NewPublisherLevelRules.EnsureScenario(siPolicy, 12);

		umciScenario.ProductSigners.FileRulesRef ??= new FileRulesRef([]);

		foreach (PFNRuleCreator PFN in CollectionsMarshal.AsSpan(PFNData))
		{
			string ID = $"ID_ALLOW_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";

			// Create new PackageFamilyName rule
			Allow newPFNRule = new(id: ID)
			{
				FriendlyName = GlobalVars.GetStr("AllowingPackagedAppFriendlyName"),
				MinimumFileVersion = PFN.MinimumFileVersion,
				PackageFamilyName = PFN.PackageFamilyName
			};

			siPolicy.FileRules.Add(newPFNRule);

			// Create FileRuleRef for the PFN
			FileRuleRef newRef = new(ruleID: ID);

			umciScenario.ProductSigners.FileRulesRef.FileRuleRef.Add(newRef);
		}

		return siPolicy;
	}

	/// <summary>
	/// Creates PFN rules and adds them to the SiPolicy object
	/// </summary>
	/// <param name="siPolicy"></param>
	/// <param name="PFNData"></param>
	/// <returns>Modified SiPolicy object</returns>
	internal static SiPolicy.SiPolicy CreateDeny(SiPolicy.SiPolicy siPolicy, List<PFNRuleCreator> PFNData)
	{
		if (PFNData.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoPackageFamilyNamesDetectedDenyMessage"));
			return siPolicy;
		}

		// Ensure the lists are initialized
		siPolicy.FileRules ??= [];

		// Ensure Scenarios exist
		SigningScenario umciScenario = NewPublisherLevelRules.EnsureScenario(siPolicy, 12);

		umciScenario.ProductSigners.FileRulesRef ??= new FileRulesRef([]);

		foreach (PFNRuleCreator PFN in CollectionsMarshal.AsSpan(PFNData))
		{
			string ID = $"ID_DENY_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";

			// Create new PackageFamilyName rule
			Deny newPFNRule = new(id: ID)
			{
				FriendlyName = GlobalVars.GetStr("DenyingPackagedAppFriendlyName"),
				MinimumFileVersion = PFN.MinimumFileVersion,
				PackageFamilyName = PFN.PackageFamilyName
			};

			siPolicy.FileRules.Add(newPFNRule);

			// Create FileRuleRef for the PFN
			FileRuleRef newRef = new(ruleID: ID);

			umciScenario.ProductSigners.FileRulesRef.FileRuleRef.Add(newRef);
		}

		return siPolicy;
	}
}
