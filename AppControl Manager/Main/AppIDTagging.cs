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
using AppControlManager.IntelGathering;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.XMLOps;

namespace AppControlManager.Main;

internal static class AppIDTagging
{
	/// <summary>
	/// Rule options that can be used for AppIDTagging policies.
	/// </summary>
	private static readonly List<OptionType> AppIDTaggingRules = [
		OptionType.EnabledAuditMode,
		OptionType.EnabledUMCI,
		OptionType.RequiredEnforceStoreApplications,
		OptionType.EnabledAdvancedBootOptionsMenu,
		OptionType.DisabledScriptEnforcement,
		OptionType.EnabledUnsignedSystemIntegrityPolicy,
		OptionType.EnabledUpdatePolicyNoReboot,
		OptionType.DisabledRuntimeFilePathRuleProtection
	];

	/// <summary>
	/// App ID Tagging only applies to user mode Exe files.
	/// Creationg explicit Allow rules for them improves system performance.
	/// </summary>
	private static readonly List<FileIdentity> AppIDTaggingFileTypeExceptions = [
		new(){FilePath = "*.sys", SISigningScenario = SiPolicyIntel.SSType.UserMode},
		new(){FilePath = "*.com", SISigningScenario = SiPolicyIntel.SSType.UserMode},
		new(){FilePath = "*.dll", SISigningScenario = SiPolicyIntel.SSType.UserMode},
		new(){FilePath = "*.ocx", SISigningScenario = SiPolicyIntel.SSType.UserMode},
		new(){FilePath = "*.rll", SISigningScenario = SiPolicyIntel.SSType.UserMode},
		new(){FilePath = "*.mst", SISigningScenario = SiPolicyIntel.SSType.UserMode},
		new(){FilePath = "*.msi", SISigningScenario = SiPolicyIntel.SSType.UserMode},
		new(){FilePath = "*.js", SISigningScenario = SiPolicyIntel.SSType.UserMode},
		new(){FilePath = "*.vbs", SISigningScenario = SiPolicyIntel.SSType.UserMode},
		new(){FilePath = "*.ps1", SISigningScenario = SiPolicyIntel.SSType.UserMode},
		new(){FilePath = "*.appx", SISigningScenario = SiPolicyIntel.SSType.UserMode},
		new(){FilePath = "*.bin", SISigningScenario = SiPolicyIntel.SSType.UserMode},
		new(){FilePath = "*.bat", SISigningScenario = SiPolicyIntel.SSType.UserMode},
		new(){FilePath = "*.hxs", SISigningScenario = SiPolicyIntel.SSType.UserMode},
		new(){FilePath = "*.mui", SISigningScenario = SiPolicyIntel.SSType.UserMode},
		new(){FilePath = "*.lex", SISigningScenario = SiPolicyIntel.SSType.UserMode},
		new(){FilePath = "*.mof", SISigningScenario = SiPolicyIntel.SSType.UserMode}
		];

	/// <summary>
	/// Converts any App Control policy to AppIDTagging policy.
	/// </summary>
	/// <param name="siPolicy"></param>
	/// <returns></returns>
	internal static SiPolicy.SiPolicy Convert(SiPolicy.SiPolicy siPolicy)
	{
		// Remove all kernel-mode stuff
		siPolicy = RemoveSigningScenarios.RemoveKernelMode(siPolicy);

		// Change policy type
		siPolicy.PolicyType = PolicyType.AppIDTaggingPolicy;

		// Ensure the IDs are the same
		if (!string.Equals(siPolicy.PolicyID, siPolicy.BasePolicyID, StringComparison.OrdinalIgnoreCase))
		{
			throw new InvalidOperationException("The PolicyID and BasePolicyID of an AppIDTagging policy must be the same");
		}

		#region Exception rules creation

		FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: AppIDTaggingFileTypeExceptions, level: ScanLevels.FilePath, folderPaths: null);

		// Create a new SiPolicy object with the data package.
		SiPolicy.SiPolicy newPolicyObj = Master.Initiate(DataPackage, SiPolicyIntel.Authorization.Allow);

		// Merge the new supplemental policy with the Pinned App ID Tagging Policy
		siPolicy = Merger.Merge(siPolicy, [newPolicyObj]);

		#endregion

		// Make sure the policy only has valid rule options
		_ = siPolicy.Rules.RemoveAll(r => !AppIDTaggingRules.Contains(r.Item));

		return siPolicy;
	}

	/// <summary>
	/// Adds pairs of Key/Value tags to a policy.
	/// </summary>
	/// <param name="siPolicy"></param>
	/// <param name="tags"></param>
	/// <returns></returns>
	internal static SiPolicy.SiPolicy AddTags(SiPolicy.SiPolicy siPolicy, Dictionary<string, string> tags)
	{
		// Ensure UMCI Scenario exists
		SigningScenario? umciScenario = siPolicy.SigningScenarios?.FirstOrDefault(s => s.Value == 12);
		if (umciScenario is null)
		{
			umciScenario = new SigningScenario
			(
				value: 12,
				id: "ID_SIGNINGSCENARIO_UMCI",
				productSigners: new ProductSigners()
			)
			{
				FriendlyName = "User Mode Signing Scenario",
				AppIDTags = new AppIDTags()
			};

			List<SigningScenario> scenarios = siPolicy.SigningScenarios ?? [];
			scenarios.Add(umciScenario);
			siPolicy.SigningScenarios = scenarios;
		}

		umciScenario.AppIDTags ??= new AppIDTags();
		umciScenario.AppIDTags.AppIDTag ??= [];

		HashSet<string> currentTagKeys = new(StringComparer.Ordinal);

		foreach (AppIDTag item in CollectionsMarshal.AsSpan(umciScenario.AppIDTags.AppIDTag))
		{
			_ = currentTagKeys.Add(item.Key);
		}

		foreach (KeyValuePair<string, string> kvp in tags)
		{
			if (currentTagKeys.Contains(kvp.Key))
			{
				Logger.Write($"Skipping adding an AppIDTag with the key '{kvp.Key}' and value '{kvp.Value}' to the policy because it already exists.");
				continue;
			}

			AppIDTag newTagPair = new(
				key: kvp.Key,
				value: kvp.Value
				);

			umciScenario.AppIDTags.AppIDTag.Add(newTagPair);
		}

		return siPolicy;
	}

}
