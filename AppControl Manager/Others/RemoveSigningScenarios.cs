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
using AppControlManager.SiPolicy;

namespace AppControlManager.Others;

internal static class RemoveSigningScenarios
{
	/// <summary>
	/// Removes the User-mode signing scenario block completely, as well as any associated Signers and other elements
	/// From an App Control policy object.
	/// </summary>
	/// <param name="policyObj"></param>
	internal static SiPolicy.SiPolicy RemoveUserMode(SiPolicy.SiPolicy policyObj)
	{
		// Signers that reference the User-Mode signing scenario
		HashSet<string> userModeSignerIDs = new(StringComparer.Ordinal);

		// FileRules that reference the User-Mode signing scenario
		HashSet<string> userModeFileRules = new(StringComparer.Ordinal);

		// FileAttribs that reference the User-Mode signing scenario Signers
		HashSet<string> userModeFileAttribsIDs = new(StringComparer.Ordinal);

		if (policyObj.SigningScenarios is not null)
		{
			foreach (SigningScenario sc in CollectionsMarshal.AsSpan(policyObj.SigningScenarios))
			{
				// User-Mode Signing Scenario
				if (string.Equals(sc.Value.ToString(), "12", StringComparison.OrdinalIgnoreCase))
				{
					foreach (AllowedSigner allowedSigner in CollectionsMarshal.AsSpan(sc.ProductSigners.AllowedSigners?.AllowedSigner))
					{
						_ = userModeSignerIDs.Add(allowedSigner.SignerId);
					}

					foreach (DeniedSigner deniedSigner in CollectionsMarshal.AsSpan(sc.ProductSigners.DeniedSigners?.DeniedSigner))
					{
						_ = userModeSignerIDs.Add(deniedSigner.SignerId);
					}

					foreach (FileRuleRef fileRuleRef in CollectionsMarshal.AsSpan(sc.ProductSigners.FileRulesRef?.FileRuleRef))
					{
						_ = userModeFileRules.Add(fileRuleRef.RuleID);
					}
				}
			}

			foreach (Signer signer in CollectionsMarshal.AsSpan(policyObj.Signers))
			{
				if (userModeSignerIDs.Contains(signer.ID))
				{
					foreach (FileAttribRef fileAttribRef in CollectionsMarshal.AsSpan(signer.FileAttribRef))
					{
						_ = userModeFileAttribsIDs.Add(fileAttribRef.RuleID);
					}
				}
			}

			// Remove any signing scenario with the value 12 representing User-Mode
			_ = policyObj.SigningScenarios?.RemoveAll(scenario => string.Equals(scenario.Value.ToString(), "12", StringComparison.OrdinalIgnoreCase));

			// Remove all Signers that are for User-Mode signing scenario
			_ = policyObj.Signers?.RemoveAll(s => userModeSignerIDs.Contains(s.ID));

			// Remove any Allow/Deny/FileRule/FileAttrib that belongs to User-Mode signing scenario
			_ = policyObj.FileRules?.RemoveAll(
				f => (f is Allow allowRule && userModeFileRules.Contains(allowRule.ID)) ||
					 (f is Deny denyRule && userModeFileRules.Contains(denyRule.ID)) ||
					 (f is FileRule fileRule && userModeFileRules.Contains(fileRule.ID)) ||
					 // Note: a single FileAttrib cannot be used by 2 Signers that belong to different signing scenarios so FileAttrib removal is safe here.
					 (f is FileAttrib fileAttrib && userModeFileAttribsIDs.Contains(fileAttrib.ID))
				);

			// When we remove User-Mode signers we better remove CiSigners as well.
			policyObj.CiSigners = null;
		}

		return policyObj;
	}

	/// <summary>
	/// Removes the Kernel-mode signing scenario block completely, as well as any associated Signers and other elements
	/// From an App Control policy object.
	/// </summary>
	/// <param name="policyObj"></param>
	internal static SiPolicy.SiPolicy RemoveKernelMode(SiPolicy.SiPolicy policyObj)
	{
		// Signers that reference the Kernel-Mode signing scenario
		HashSet<string> kernelModeSignerIDs = new(StringComparer.Ordinal);

		// FileRules that reference the Kernel-Mode signing scenario
		HashSet<string> kernelModeFileRules = new(StringComparer.Ordinal);

		// FileAttribs that reference the Kernel-Mode signing scenario Signers
		HashSet<string> kernelModeFileAttribsIDs = new(StringComparer.Ordinal);

		if (policyObj.SigningScenarios is not null)
		{
			foreach (SigningScenario sc in CollectionsMarshal.AsSpan(policyObj.SigningScenarios))
			{
				// kernel-Mode Signing Scenario
				if (string.Equals(sc.Value.ToString(), "131", StringComparison.OrdinalIgnoreCase))
				{
					foreach (AllowedSigner allowedSigner in CollectionsMarshal.AsSpan(sc.ProductSigners.AllowedSigners?.AllowedSigner))
					{
						_ = kernelModeSignerIDs.Add(allowedSigner.SignerId);
					}

					foreach (DeniedSigner deniedSigner in CollectionsMarshal.AsSpan(sc.ProductSigners.DeniedSigners?.DeniedSigner))
					{
						_ = kernelModeSignerIDs.Add(deniedSigner.SignerId);
					}

					foreach (FileRuleRef fileRuleRef in CollectionsMarshal.AsSpan(sc.ProductSigners.FileRulesRef?.FileRuleRef))
					{
						_ = kernelModeFileRules.Add(fileRuleRef.RuleID);
					}
				}
			}

			foreach (Signer signer in CollectionsMarshal.AsSpan(policyObj.Signers))
			{
				if (kernelModeSignerIDs.Contains(signer.ID))
				{
					foreach (FileAttribRef fileAttribRef in CollectionsMarshal.AsSpan(signer.FileAttribRef))
					{
						_ = kernelModeFileAttribsIDs.Add(fileAttribRef.RuleID);
					}
				}
			}

			// Remove any signing scenario with the value 131 representing kernel-Mode
			_ = policyObj.SigningScenarios?.RemoveAll(scenario => string.Equals(scenario.Value.ToString(), "131", StringComparison.OrdinalIgnoreCase));

			// Remove all Signers that are for kernel-Mode signing scenario
			_ = policyObj.Signers?.RemoveAll(s => kernelModeSignerIDs.Contains(s.ID));

			// Remove any Allow/Deny/FileRule/FileAttrib that belongs to kernel-Mode signing scenario
			_ = policyObj.FileRules?.RemoveAll(
				f => (f is Allow allowRule && kernelModeFileRules.Contains(allowRule.ID)) ||
					 (f is Deny denyRule && kernelModeFileRules.Contains(denyRule.ID)) ||
					 (f is FileRule fileRule && kernelModeFileRules.Contains(fileRule.ID)) ||
					 // Note: a single FileAttrib cannot be used by 2 Signers that belong to different signing scenarios so FileAttrib removal is safe here.
					 (f is FileAttrib fileAttrib && kernelModeFileAttribsIDs.Contains(fileAttrib.ID))
				);
		}

		return policyObj;
	}
}
