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
using CommonCore.IntelGathering;

namespace AppControlManager.XMLOps;

internal static class NewFileNameLevelRules
{
	/// <summary>
	/// Creates new Allow FileName level rules in the SiPolicy object
	/// Each rules includes the Allow element in the "FileRules" section,
	/// And a corresponding "FileRuleRef" in the "FileRulesRef" section.
	/// </summary>
	/// <param name="policyObj"></param>
	/// <param name="fileNameData"> The FileName data to be used for creating the rules, they are the output of the BuildSignerAndHashObjects Method </param>
	/// <returns>SiPolicy</returns>
	internal static SiPolicy.SiPolicy CreateAllow(SiPolicy.SiPolicy policyObj, List<FileNameRuleCreator> fileNameData)
	{
		if (fileNameData.Count is 0)
		{
			Logger.Write(Atlas.GetStr("NoFileNameDetectedAllowMessage"));
			return policyObj;
		}

		Logger.Write(string.Format(Atlas.GetStr("FileNameRulesToAddMessage"), fileNameData.Count));

		// Ensure the lists are Initialized.
		policyObj.FileRules ??= [];

		// Ensure Scenarios exist
		SigningScenario umciScenario = NewPublisherLevelRules.EnsureScenario(policyObj, 12);
		SigningScenario kmciScenario = NewPublisherLevelRules.EnsureScenario(policyObj, 131);

		umciScenario.ProductSigners.FileRulesRef ??= new FileRulesRef([]);
		kmciScenario.ProductSigners.FileRulesRef ??= new FileRulesRef([]);

		foreach (FileNameRuleCreator fileNameItem in CollectionsMarshal.AsSpan(fileNameData))
		{
			string allowID = $"ID_ALLOW_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";

			Allow newFileAttrib = new(id: allowID)
			{
				FriendlyName = Atlas.GetStr("FileNameRuleTypeFriendlyName"),
				MinimumFileVersion = fileNameItem.FileVersion?.ToString()
			};

			if (!string.IsNullOrWhiteSpace(fileNameItem.OriginalFileName))
			{
				newFileAttrib.FileName = fileNameItem.OriginalFileName;
			}
			else if (!string.IsNullOrWhiteSpace(fileNameItem.InternalName))
			{
				newFileAttrib.InternalName = fileNameItem.InternalName;
			}
			else if (!string.IsNullOrWhiteSpace(fileNameItem.FileDescription))
			{
				newFileAttrib.FileDescription = fileNameItem.FileDescription;
			}
			else if (!string.IsNullOrWhiteSpace(fileNameItem.ProductName))
			{
				newFileAttrib.ProductName = fileNameItem.ProductName;
			}

			policyObj.FileRules.Add(newFileAttrib);


			// For User-Mode files
			if (fileNameItem.SiSigningScenario is SSType.UserMode)
			{
				umciScenario.ProductSigners.FileRulesRef.FileRuleRef.Add(new FileRuleRef(ruleID: allowID));
			}

			// For Kernel-Mode files
			else if (fileNameItem.SiSigningScenario is SSType.KernelMode)
			{
				kmciScenario.ProductSigners.FileRulesRef.FileRuleRef.Add(new FileRuleRef(ruleID: allowID));
			}
		}

		return policyObj;
	}


	internal static SiPolicy.SiPolicy CreateDeny(SiPolicy.SiPolicy policyObj, List<FileNameRuleCreator> fileNameData)
	{
		if (fileNameData.Count is 0)
		{
			Logger.Write(Atlas.GetStr("NoFileNameDetectedDenyMessage"));
			return policyObj;
		}

		Logger.Write(string.Format(Atlas.GetStr("FileNameRulesToAddMessage"), fileNameData.Count));

		// Ensure the lists are Initialized.
		policyObj.FileRules ??= [];

		// Ensure Scenarios exist
		SigningScenario umciScenario = NewPublisherLevelRules.EnsureScenario(policyObj, 12);
		SigningScenario kmciScenario = NewPublisherLevelRules.EnsureScenario(policyObj, 131);

		umciScenario.ProductSigners.FileRulesRef ??= new FileRulesRef([]);
		kmciScenario.ProductSigners.FileRulesRef ??= new FileRulesRef([]);

		foreach (FileNameRuleCreator fileNameItem in CollectionsMarshal.AsSpan(fileNameData))
		{
			string denyID = $"ID_Deny_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";

			Deny newFileAttrib = new(id: denyID)
			{
				FriendlyName = Atlas.GetStr("FileNameRuleTypeFriendlyName"),
				MinimumFileVersion = fileNameItem.FileVersion?.ToString()
			};

			if (!string.IsNullOrWhiteSpace(fileNameItem.OriginalFileName))
			{
				newFileAttrib.FileName = fileNameItem.OriginalFileName;
			}
			else if (!string.IsNullOrWhiteSpace(fileNameItem.InternalName))
			{
				newFileAttrib.InternalName = fileNameItem.InternalName;
			}
			else if (!string.IsNullOrWhiteSpace(fileNameItem.FileDescription))
			{
				newFileAttrib.FileDescription = fileNameItem.FileDescription;
			}
			else if (!string.IsNullOrWhiteSpace(fileNameItem.ProductName))
			{
				newFileAttrib.ProductName = fileNameItem.ProductName;
			}

			policyObj.FileRules.Add(newFileAttrib);


			// For User-Mode files
			if (fileNameItem.SiSigningScenario is SSType.UserMode)
			{
				umciScenario.ProductSigners.FileRulesRef.FileRuleRef.Add(new FileRuleRef(ruleID: denyID));
			}

			// For Kernel-Mode files
			else if (fileNameItem.SiSigningScenario is SSType.KernelMode)
			{
				kmciScenario.ProductSigners.FileRulesRef.FileRuleRef.Add(new FileRuleRef(ruleID: denyID));
			}
		}

		return policyObj;
	}

}
