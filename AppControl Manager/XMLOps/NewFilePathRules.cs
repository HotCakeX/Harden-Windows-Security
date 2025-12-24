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
using System.Runtime.InteropServices;
using AppControlManager.Others;
using AppControlManager.SiPolicy;

namespace AppControlManager.XMLOps;

internal static class NewFilePathRules
{
	/// <summary>
	/// Create a new Allow FilePath rule (including Wildcards) in the SiPolicy object
	/// Rules will only be created for User-Mode files as Kernel-mode drivers do not support FilePath rules
	/// </summary>
	/// <param name="policyObj"></param>
	/// <param name="data"></param>
	/// <returns>SiPolicy</returns>
	internal static SiPolicy.SiPolicy CreateAllow(SiPolicy.SiPolicy policyObj, List<FilePathCreator> data)
	{
		if (data.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoFilePathRulesDetectedAllowMessage"));
			return policyObj;
		}

		Logger.Write(string.Format(GlobalVars.GetStr("FilePathRulesToAddMessage"), data.Count, "SiPolicy Object"));

		// Initialize FileRules list
		List<object> fileRules = policyObj.FileRules ?? [];

		// Ensure UMCI Scenario exists
		SigningScenario? umciScenario = policyObj.SigningScenarios?.FirstOrDefault(s => s.Value == 12);
		if (umciScenario is null)
		{
			umciScenario = new SigningScenario
			(
				value: 12,
				id: "ID_SIGNINGSCENARIO_UMCI",
				productSigners: new ProductSigners()
			)
			{ FriendlyName = "User Mode Signing Scenario" };

			List<SigningScenario> scenarios = policyObj.SigningScenarios ?? [];
			scenarios.Add(umciScenario);
			policyObj.SigningScenarios = scenarios;
		}

		// Ensure ProductSigners exists
		umciScenario.ProductSigners ??= new ProductSigners();

		// Ensure FileRulesRef exists
		umciScenario.ProductSigners.FileRulesRef ??= new FileRulesRef([]);

		// Prepare FileRuleRef list
		List<FileRuleRef> umciFileRuleRefs = umciScenario.ProductSigners.FileRulesRef.FileRuleRef ?? [];

		// Loop through each item and create a new FilePath rule for it
		foreach (FilePathCreator item in CollectionsMarshal.AsSpan(data))
		{
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();

			// Create a unique ID for the rule
			string allowRuleID = $"ID_ALLOW_A_{guid}";

			// Create a new Allow FilePath rule
			Allow newAllowRule = new(id: allowRuleID)
			{
				FriendlyName = GlobalVars.GetStr("FilePathRuleTypeFriendlyName"),
				MinimumFileVersion = item.MinimumFileVersion,
				FilePath = item.FilePath
			};

			fileRules.Add(newAllowRule);

			// For User-Mode files only as FilePath rules are not applicable to Kernel-Mode drivers
			if (item.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
			{
				umciFileRuleRefs.Add(new FileRuleRef(ruleID: allowRuleID));
			}
			else
			{
				Logger.Write(string.Format(GlobalVars.GetStr("KernelModeFilePathRuleWarningMessage"), item.FilePath));
			}
		}

		// Update the policy object
		policyObj.FileRules = fileRules;
		umciScenario.ProductSigners.FileRulesRef.FileRuleRef = umciFileRuleRefs;

		return policyObj;
	}


	/// <summary>
	/// Creates a new Deny FilePath rule (including Wildcards) in the SiPolicy object
	/// </summary>
	/// <param name="policyObj"></param>
	/// <param name="data"></param>
	/// <returns>SiPolicy</returns>
	internal static SiPolicy.SiPolicy CreateDenyEx(SiPolicy.SiPolicy policyObj, List<FilePathCreator> data)
	{
		if (data.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoFilePathRulesDetectedDenyMessage"));
			return policyObj;
		}

		Logger.Write(string.Format(GlobalVars.GetStr("FilePathRulesToAddMessage"), data.Count, "SiPolicy Object"));

		// Initialize FileRules list
		List<object> fileRules = policyObj.FileRules ?? [];

		// Ensure UMCI Scenario exists
		SigningScenario? umciScenario = policyObj.SigningScenarios?.FirstOrDefault(s => s.Value == 12);
		if (umciScenario is null)
		{
			umciScenario = new SigningScenario
			(
				value: 12,
				id: "ID_SIGNINGSCENARIO_UMCI",
				productSigners: new ProductSigners()
			)
			{ FriendlyName = "User Mode Signing Scenario" };

			List<SigningScenario> scenarios = policyObj.SigningScenarios ?? [];
			scenarios.Add(umciScenario);
			policyObj.SigningScenarios = scenarios;
		}

		// Ensure ProductSigners exists
		umciScenario.ProductSigners ??= new ProductSigners();

		// Ensure FileRulesRef exists
		umciScenario.ProductSigners.FileRulesRef ??= new FileRulesRef([]);

		// Prepare FileRuleRef list
		List<FileRuleRef> umciFileRuleRefs = umciScenario.ProductSigners.FileRulesRef.FileRuleRef ?? [];

		// Loop through each item and create a new FilePath rule for it
		foreach (FilePathCreator item in CollectionsMarshal.AsSpan(data))
		{
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();

			// Create a unique ID for the rule
			string denyRuleID = $"ID_DENY_A_{guid}";

			// Create a new Deny FilePath rule
			Deny newDenyRule = new(id: denyRuleID)
			{
				FriendlyName = GlobalVars.GetStr("FilePathRuleTypeFriendlyName"),
				FilePath = item.FilePath
			};

			fileRules.Add(newDenyRule);

			// For User-Mode files
			if (item.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
			{
				umciFileRuleRefs.Add(new FileRuleRef(ruleID: denyRuleID));
			}
			else
			{
				Logger.Write(string.Format(GlobalVars.GetStr("KernelModeFilePathRuleWarningMessage"), item.FilePath));
			}
		}

		// Update the policy object
		policyObj.FileRules = fileRules;
		umciScenario.ProductSigners.FileRulesRef.FileRuleRef = umciFileRuleRefs;

		return policyObj;
	}

}
