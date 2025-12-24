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

internal static class NewHashLevelRules
{

	/// <summary>
	/// Creates new Allow Hash level rules in the SiPolicy object
	/// </summary>
	/// <param name="siPolicy"></param>
	/// <param name="hashes"> The Hashes to be used for creating the rules </param>
	/// <returns>Modified SiPolicy object</returns>
	internal static SiPolicy.SiPolicy CreateAllow(SiPolicy.SiPolicy siPolicy, List<HashCreator> hashes)
	{
		if (hashes.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoHashesDetectedAllowMessage"));
			return siPolicy;
		}

		Logger.Write(string.Format(GlobalVars.GetStr("HashRulesToAddMessage"), hashes.Count, "SiPolicy Object"));

		// Ensure FileRules list
		List<object> fileRulesList = siPolicy.FileRules ?? [];

		// Ensure Signing Scenarios exist

		// UMCI (User Mode - 12)
		SigningScenario? umci = siPolicy.SigningScenarios?.FirstOrDefault(s => s.Value == 12);
		if (umci == null)
		{
			umci = new SigningScenario
			(
				value: 12,
				id: "ID_SIGNINGSCENARIO_UMCI",
				productSigners: new ProductSigners { FileRulesRef = new FileRulesRef([]) }
			)
			{ FriendlyName = "User Mode Signing Scenario" };
			List<SigningScenario> scenarios = siPolicy.SigningScenarios ?? [];
			scenarios.Add(umci);
			siPolicy.SigningScenarios = scenarios;
		}
		else
		{
			umci.ProductSigners ??= new ProductSigners();
			umci.ProductSigners.FileRulesRef ??= new FileRulesRef([]);
		}

		// KMCI (Kernel Mode - 131)
		SigningScenario? kmci = siPolicy.SigningScenarios?.FirstOrDefault(s => s.Value == 131);
		if (kmci == null)
		{
			kmci = new SigningScenario
			(
				value: 131,
				id: "ID_SIGNINGSCENARIO_KMCI",
				productSigners: new ProductSigners { FileRulesRef = new FileRulesRef([]) }
			)
			{ FriendlyName = "Kernel Mode Signing Scenario" };
			// Re-fetch scenarios as we might have updated the array above
			List<SigningScenario> scenarios = siPolicy.SigningScenarios ?? [];
			scenarios.Add(kmci);
			siPolicy.SigningScenarios = scenarios;
		}
		else
		{
			kmci.ProductSigners ??= new ProductSigners();
			kmci.ProductSigners.FileRulesRef ??= new FileRulesRef([]);
		}
		umci.ProductSigners.FileRulesRef ??= new FileRulesRef([]);
		kmci.ProductSigners.FileRulesRef ??= new FileRulesRef([]);

		// Prepare Ref Lists
		List<FileRuleRef> umciRefs = umci.ProductSigners.FileRulesRef.FileRuleRef ?? [];
		List<FileRuleRef> kmciRefs = kmci.ProductSigners.FileRulesRef.FileRuleRef ?? [];

		// Loop through each hash and create a new rule for it
		foreach (HashCreator hash in CollectionsMarshal.AsSpan(hashes))
		{
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();

			// Create a unique ID for the rule
			string HashSHA256RuleID = $"ID_ALLOW_A_{guid}";
			string HashSHA1RuleID = $"ID_ALLOW_B_{guid}";

			// Create new Allow Hash rule for Authenticode SHA256
			Allow newAuth256Rule = new(id: HashSHA256RuleID)
			{
				FriendlyName = string.Format(GlobalVars.GetStr("Sha256HashFriendlyName"), hash.FileName),
				Hash = Convert.FromHexString(hash.AuthenticodeSHA256)
			};
			fileRulesList.Add(newAuth256Rule);

			// Create new Allow Hash rule for Authenticode SHA1
			Allow newAuth1Rule = new(id: HashSHA1RuleID)
			{
				FriendlyName = string.Format(GlobalVars.GetStr("Sha1HashFriendlyName"), hash.FileName),
				Hash = Convert.FromHexString(hash.AuthenticodeSHA1)
			};
			fileRulesList.Add(newAuth1Rule);

			// For User-Mode files
			if (hash.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
			{
				umciRefs.Add(new FileRuleRef(ruleID: HashSHA256RuleID));
				umciRefs.Add(new FileRuleRef(ruleID: HashSHA1RuleID));
			}

			// For Kernel-Mode files
			else if (hash.SiSigningScenario is SiPolicyIntel.SSType.KernelMode)
			{
				// Display a warning if a hash rule for a kernel-mode file is being created and the file is not an MSI
				if (!hash.FilePath.EndsWith(".msi", StringComparison.OrdinalIgnoreCase))
				{
					Logger.Write(string.Format(GlobalVars.GetStr("KernelModeHashRuleWarningMessage"), hash.FilePath));
				}

				kmciRefs.Add(new FileRuleRef(ruleID: HashSHA256RuleID));
				kmciRefs.Add(new FileRuleRef(ruleID: HashSHA1RuleID));
			}
		}

		// Update the SiPolicy object
		siPolicy.FileRules = fileRulesList;
		umci.ProductSigners.FileRulesRef.FileRuleRef = umciRefs;
		kmci.ProductSigners.FileRulesRef.FileRuleRef = kmciRefs;

		return siPolicy;
	}

	/// <summary>
	/// Creates new Deny Hash level rules in the SiPolicy object
	/// </summary>
	/// <param name="siPolicy"></param>
	/// <param name="hashes"> The Hashes to be used for creating the rules </param>
	/// <returns>Modified SiPolicy object</returns>
	internal static SiPolicy.SiPolicy CreateDenyEx(SiPolicy.SiPolicy siPolicy, List<HashCreator> hashes)
	{
		if (hashes.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoHashesDetectedDenyMessage"));
			return siPolicy;
		}

		Logger.Write(string.Format(GlobalVars.GetStr("HashRulesToAddMessage"), hashes.Count, "SiPolicy Object"));

		// Ensure FileRules list
		List<object> fileRulesList = siPolicy.FileRules ?? [];

		// Ensure Signing Scenarios exist

		// UMCI (User Mode - 12)
		SigningScenario? umci = siPolicy.SigningScenarios?.FirstOrDefault(s => s.Value == 12);
		if (umci == null)
		{
			umci = new SigningScenario
			(
				value: 12,
				id: "ID_SIGNINGSCENARIO_UMCI",
				productSigners: new ProductSigners { FileRulesRef = new FileRulesRef([]) }
			)
			{ FriendlyName = "User Mode Signing Scenario" };
			List<SigningScenario> scenarios = siPolicy.SigningScenarios ?? [];
			scenarios.Add(umci);
			siPolicy.SigningScenarios = scenarios;
		}
		else
		{
			umci.ProductSigners ??= new ProductSigners();
			umci.ProductSigners.FileRulesRef ??= new FileRulesRef([]);
		}

		// KMCI (Kernel Mode - 131)
		SigningScenario? kmci = siPolicy.SigningScenarios?.FirstOrDefault(s => s.Value == 131);
		if (kmci == null)
		{
			kmci = new SigningScenario
			(
				value: 131,
				id: "ID_SIGNINGSCENARIO_KMCI",
				productSigners: new ProductSigners { FileRulesRef = new FileRulesRef([]) }
			)
			{ FriendlyName = "Kernel Mode Signing Scenario" };
			// Re-fetch scenarios as we might have updated the array above
			List<SigningScenario> scenarios = siPolicy.SigningScenarios ?? [];
			scenarios.Add(kmci);
			siPolicy.SigningScenarios = scenarios;
		}
		else
		{
			kmci.ProductSigners ??= new ProductSigners();
			kmci.ProductSigners.FileRulesRef ??= new FileRulesRef([]);
		}

		umci.ProductSigners.FileRulesRef ??= new FileRulesRef([]);
		kmci.ProductSigners.FileRulesRef ??= new FileRulesRef([]);

		// Prepare Ref Lists
		List<FileRuleRef> umciRefs = umci.ProductSigners.FileRulesRef.FileRuleRef ?? [];
		List<FileRuleRef> kmciRefs = kmci.ProductSigners.FileRulesRef.FileRuleRef ?? [];

		// Loop through each hash and create a new rule for it
		foreach (HashCreator hash in CollectionsMarshal.AsSpan(hashes))
		{
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();

			// Create a unique ID for the rule
			string HashSHA256RuleID = $"ID_DENY_A_{guid}";
			string HashSHA1RuleID = $"ID_DENY_B_{guid}";

			// Create new Deny Hash rule for Authenticode SHA256
			Deny newAuth256Rule = new(id: HashSHA256RuleID)
			{
				FriendlyName = string.Format(GlobalVars.GetStr("Sha256HashFriendlyName"), hash.FileName),
				Hash = Convert.FromHexString(hash.AuthenticodeSHA256)
			};
			fileRulesList.Add(newAuth256Rule);

			// Create new Deny Hash rule for Authenticode SHA1
			Deny newAuth1Rule = new(id: HashSHA1RuleID)
			{
				FriendlyName = string.Format(GlobalVars.GetStr("Sha1HashFriendlyName"), hash.FileName),
				Hash = Convert.FromHexString(hash.AuthenticodeSHA1)
			};
			fileRulesList.Add(newAuth1Rule);

			// For User-Mode files
			if (hash.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
			{
				umciRefs.Add(new FileRuleRef(ruleID: HashSHA256RuleID));
				umciRefs.Add(new FileRuleRef(ruleID: HashSHA1RuleID));
			}

			// For Kernel-Mode files
			else if (hash.SiSigningScenario is SiPolicyIntel.SSType.KernelMode)
			{
				// Display a warning if a hash rule for a kernel-mode file is being created and the file is not an MSI
				if (!hash.FilePath.EndsWith(".msi", StringComparison.OrdinalIgnoreCase))
				{
					Logger.Write(string.Format(GlobalVars.GetStr("KernelModeHashRuleWarningMessage"), hash.FilePath));
				}

				kmciRefs.Add(new FileRuleRef(ruleID: HashSHA256RuleID));
				kmciRefs.Add(new FileRuleRef(ruleID: HashSHA1RuleID));
			}
		}

		// Update the SiPolicy object
		siPolicy.FileRules = fileRulesList;
		umci.ProductSigners.FileRulesRef.FileRuleRef = umciRefs;
		kmci.ProductSigners.FileRulesRef.FileRuleRef = kmciRefs;

		return siPolicy;
	}

}
