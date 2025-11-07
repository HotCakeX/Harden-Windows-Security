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
using AppControlManager.SiPolicy;

namespace AppControlManager.SiPolicyIntel;

internal static class FileAttribDeDuplication
{
	/// <summary>
	/// When 2 FilePublisher or WHQLFilePublisher level signers reference the same FileAttrib
	/// And they are in different Signing Scenarios and/or one of them allows and the other denies, the FileAttribs that they point to through FileAttribRefs must remain.
	/// However, if the signers belong to the same SigningScenario and/or they both allow or deny, both signers "can" reference the same FileAttrib.
	/// De-duplication is not necessary here but if it is to be done, each signer must have its context.
	/// Context: Whether signer is allowing or denying, or if it's kernel-mode or user-mode.
	///
	/// So 1 file attribute is enough for a single file to refer to all of its signers that are in the same signing scenario and authorization section.
	/// The only time when 2 file attributes for the same file (with same details) need to exist is when the same file is referenced in different signing scenarios and/or authorization sections, and for each signing scenario/authorization section there needs to be a different fileAttribute.
	/// </summary>
	/// <param name="fileRulesNode"></param>
	/// <param name="signers"></param>
	/// <param name="userModeAllowedSigners"></param>
	/// <param name="userModeDeniedSigners"></param>
	/// <param name="kernelModeAllowedSigners"></param>
	/// <param name="kernelModeDeniedSigners"></param>
	internal static void EnsureUniqueFileAttributes(
		ref List<object> fileRulesNode,
		List<Signer> signers,
		IEnumerable<AllowedSigner> userModeAllowedSigners,
		IEnumerable<DeniedSigner> userModeDeniedSigners,
		IEnumerable<AllowedSigner> kernelModeAllowedSigners,
		IEnumerable<DeniedSigner> kernelModeDeniedSigners
		)
	{

		// Step 1: a list of file attributes in the <FileRules> node
		List<FileAttrib> fileAttribs = fileRulesNode.OfType<FileAttrib>().ToList() ?? [];


		// Step 2: Group duplicate FileAttribs using custom equality logic.

		// Each group contains FileAttribs that are considered duplicates based on our custom rules.
		List<List<FileAttrib>> duplicateGroups = [];

		foreach (FileAttrib fileAttrib in fileAttribs)
		{
			bool addedToGroup = false;
			foreach (List<FileAttrib> group in duplicateGroups)
			{
				// Use the first element of the group as the representative.
				if (AreFileAttribsEqual(group[0], fileAttrib))
				{
					group.Add(fileAttrib);
					addedToGroup = true;
					break;
				}
			}
			if (!addedToGroup)
			{
				// Start a new group for a fileAttrib that doesn't match any existing group.
				duplicateGroups.Add([fileAttrib]);
			}
		}


		// Step 3: Build a dictionary of all Signers.

		// This dictionary indexes Signer objects by their ID for later lookup.
		Dictionary<string, Signer> signerDictionary = [];
		foreach (Signer signer in signers)
		{
			if (!signerDictionary.TryAdd(signer.ID, signer))
			{
				Logger.Write(string.Format(GlobalVars.GetStr("DuplicateSignerIdMessage"), signer.ID));
			}
		}


		// Step 4: Partition signers into four dictionaries based on their mode and type.

		// We create four dictionaries: Allowed and Denied for User Mode and Kernel Mode.
		Dictionary<string, Signer> allowedSignerUMCIDictionary = [];
		Dictionary<string, Signer> deniedSignerUMCIDictionary = [];
		Dictionary<string, Signer> allowedSignerKMCIDictionary = [];
		Dictionary<string, Signer> deniedSignerKMCIDictionary = [];

		// Process each SigningScenario from the policy.

		// For each User-Mode allowed signer, add it to the corresponding dictionary
		foreach (AllowedSigner item in userModeAllowedSigners)
		{
			if (signerDictionary.TryGetValue(item.SignerId, out Signer? signer))
			{
				allowedSignerUMCIDictionary.Add(item.SignerId, signer);
			}
		}

		// For each Kernel-Mode allowed signer, add it to the corresponding dictionary
		foreach (AllowedSigner item in kernelModeAllowedSigners)
		{
			if (signerDictionary.TryGetValue(item.SignerId, out Signer? signer))
			{
				allowedSignerKMCIDictionary.Add(item.SignerId, signer);
			}
		}

		// For each User-Mode denied signer, add it to the corresponding dictionary
		foreach (DeniedSigner item in userModeDeniedSigners)
		{
			if (signerDictionary.TryGetValue(item.SignerId, out Signer? signer))
			{
				deniedSignerUMCIDictionary.Add(item.SignerId, signer);
			}
		}

		// For each Kernel-Mode denied signer, add it to the corresponding dictionary
		foreach (DeniedSigner item in kernelModeDeniedSigners)
		{
			if (signerDictionary.TryGetValue(item.SignerId, out Signer? signer))
			{
				deniedSignerKMCIDictionary.Add(item.SignerId, signer);
			}
		}


		// Step 5: Process duplicate groups to update FileAttribRefs and mark duplicates.

		// We keep track of FileAttrib IDs that must be removed from FileRules.
		HashSet<string> fileAttribIdsToRemove = [];
		foreach (List<FileAttrib> group in duplicateGroups)
		{
			// Only groups with more than one FileAttrib need deduplication.
			if (group.Count > 1)
			{
				ProcessDuplicateGroup(
					group,
					allowedSignerUMCIDictionary,
					deniedSignerUMCIDictionary,
					allowedSignerKMCIDictionary,
					deniedSignerKMCIDictionary,
					fileAttribIdsToRemove);
			}
		}


		// Step 6: Update the FileRules collection to remove duplicate FileAttrib objects.
		List<object> fileRulesItems = [.. fileRulesNode];
		_ = fileRulesItems.RemoveAll(item => item is FileAttrib fa && fileAttribIdsToRemove.Contains(fa.ID));
		fileRulesNode = fileRulesItems.ToList();


		// Step 7: Post-process each signer to deduplicate FileAttribRef arrays.


		/*
			Why Duplicates Can Occur:

			During the processing in ProcessDuplicateGroup,
			for each duplicate FileAttrib (that is marked for removal),
			the code iterates over all signers in the corresponding dictionary
			and updates every FileAttribRef that points to the duplicate by setting its RuleID to the kept FileAttrib's ID.

			So in the following scenario:

			A signer originally has two FileAttribRef entries:
			One referencing the kept FileAttrib (ID = "A")
			Another referencing a duplicate FileAttrib (ID = "B")

			When ProcessDuplicateGroup runs, it updates the second reference
			so that its RuleID also becomes "A". As a result, the signer ends up
			with two FileAttribRefs that both point to the same FileAttrib (ID = "A").

		 */

		// If a signer ends up with multiple FileAttribRef objects pointing to the same FileAttrib,
		// this ensures only one reference is retained.
		foreach (Signer signer in signers)
		{
			if (signer.FileAttribRef is not null && signer.FileAttribRef.Length > 1)
			{
				signer.FileAttribRef = [.. signer.FileAttribRef
					.GroupBy(r => r.RuleID)
					.Select(g => g.First())];
			}
		}
	}

	/// <summary>
	/// Compares two FileAttrib objects based on custom duplicate detection logic.
	/// </summary>
	/// <param name="x"></param>
	/// <param name="y"></param>
	/// <returns></returns>
	private static bool AreFileAttribsEqual(FileAttrib x, FileAttrib y)
	{
		if (x is null || y is null)
		{
			return false;
		}

		return Merger.CompareCommonRuleProperties(
					null, null,
					null, null,
					x.PackageFamilyName, y.PackageFamilyName,
					x.Hash, y.Hash,
					x.FilePath, y.FilePath,
					x.FileName, y.FileName,
					x.MinimumFileVersion, y.MinimumFileVersion,
					x.MaximumFileVersion, y.MaximumFileVersion,
					x.InternalName, y.InternalName,
					x.FileDescription, y.FileDescription,
					x.ProductName, y.ProductName);
	}


	/// <summary>
	/// For a group of duplicate FileAttribs, this method deduplicates them within the same signer dictionary.
	/// It updates FileAttribRefs by swapping the RuleID from the duplicate to the one kept.
	/// Only duplicates that are referenced exclusively from a single dictionary (usage key without a comma) are deduplicated.
	/// </summary>
	/// <param name="group"></param>
	/// <param name="allowedSignerUMCIDictionary"></param>
	/// <param name="deniedSignerUMCIDictionary"></param>
	/// <param name="allowedSignerKMCIDictionary"></param>
	/// <param name="deniedSignerKMCIDictionary"></param>
	/// <param name="fileAttribIdsToRemove"></param>
	private static void ProcessDuplicateGroup(
		List<FileAttrib> group,
		Dictionary<string, Signer> allowedSignerUMCIDictionary,
		Dictionary<string, Signer> deniedSignerUMCIDictionary,
		Dictionary<string, Signer> allowedSignerKMCIDictionary,
		Dictionary<string, Signer> deniedSignerKMCIDictionary,
		HashSet<string> fileAttribIdsToRemove)
	{
		// Create a mapping of each FileAttrib to the set of signer dictionary keys in which it is referenced.
		// The keys can be: "allowedUMCI", "deniedUMCI", "allowedKMCI", "deniedKMCI".
		Dictionary<FileAttrib, HashSet<string>> usage = [];
		foreach (FileAttrib fa in group)
		{
			HashSet<string> dicts = [];

			// Check if any signer in Allowed User Mode references this FileAttrib.
			if (allowedSignerUMCIDictionary.Values.Any(signer => signer.FileAttribRef is not null && signer.FileAttribRef.Any(r => r.RuleID == fa.ID)))
			{
				_ = dicts.Add("allowedUMCI");
			}
			// Check if any signer in Denied User Mode references this FileAttrib.
			if (deniedSignerUMCIDictionary.Values.Any(signer => signer.FileAttribRef is not null && signer.FileAttribRef.Any(r => r.RuleID == fa.ID)))
			{
				_ = dicts.Add("deniedUMCI");
			}
			// Check if any signer in Allowed Kernel Mode references this FileAttrib.
			if (allowedSignerKMCIDictionary.Values.Any(signer => signer.FileAttribRef is not null && signer.FileAttribRef.Any(r => r.RuleID == fa.ID)))
			{
				_ = dicts.Add("allowedKMCI");
			}
			// Check if any signer in Denied Kernel Mode references this FileAttrib.
			if (deniedSignerKMCIDictionary.Values.Any(signer => signer.FileAttribRef is not null && signer.FileAttribRef.Any(r => r.RuleID == fa.ID)))
			{
				_ = dicts.Add("deniedKMCI");
			}
			usage[fa] = dicts;
		}

		// Partition the FileAttribs by their usage keys.
		// The key is a comma-separated string representing the set of dictionaries in which the FileAttrib is referenced.
		// The keys can be: "allowedUMCI", "deniedUMCI", "allowedKMCI", "deniedKMCI".
		Dictionary<string, List<FileAttrib>> partitions = [];
		foreach (KeyValuePair<FileAttrib, HashSet<string>> kvp in usage)
		{
			FileAttrib fa = kvp.Key;
			HashSet<string> dictSet = kvp.Value;
			string key = string.Join(",", dictSet.OrderBy(s => s)); // Sorting ensures consistent key ordering.
			if (!partitions.TryGetValue(key, out List<FileAttrib>? value))
			{
				value = [];
				partitions[key] = value;
			}

			value.Add(fa);
		}

		// Process each partition. Only partitions that refer to a single dictionary (no comma in key) are eligible.
		foreach (KeyValuePair<string, List<FileAttrib>> partition in partitions)
		{
			// if the generated key contains a comma, that indicates the file attribute is referenced
			// in multiple contexts(e.g., "allowedUMCI,deniedUMCI"), and the logic skips
			// deduplication for those cases. Deduplication is only applied when the key does not contain
			// a comma, meaning the attribute is used exclusively in one dictionary context.
			if (partition.Key.Contains(',', StringComparison.OrdinalIgnoreCase))
			{
				continue;
			}
			List<FileAttrib> fileAttribList = partition.Value;
			if (fileAttribList.Count > 1)
			{
				// Choose the FileAttrib to keep based on version criteria.
				// If the FileAttribs have MinimumFileVersion values, choose the one with the lowest version.
				// Otherwise, if they have MaximumFileVersion values, choose the one with the highest version.
				FileAttrib kept = fileAttribList[0];

				// If the FileAttribs use MinimumFileVersion, choose the one with the lowest version.
				if (!string.IsNullOrWhiteSpace(kept.MinimumFileVersion))
				{
					foreach (FileAttrib fa in fileAttribList)
					{
						if (!string.IsNullOrWhiteSpace(fa.MinimumFileVersion) &&
							CompareVersions(fa.MinimumFileVersion, kept.MinimumFileVersion) < 0)
						{
							kept = fa;
						}
					}
				}
				// Else if they use MaximumFileVersion, choose the one with the highest version.
				else if (!string.IsNullOrWhiteSpace(kept.MaximumFileVersion))
				{
					foreach (FileAttrib fa in fileAttribList)
					{
						if (!string.IsNullOrWhiteSpace(fa.MaximumFileVersion) &&
							CompareVersions(fa.MaximumFileVersion, kept.MaximumFileVersion) > 0)
						{
							kept = fa;
						}
					}
				}

				foreach (FileAttrib duplicate in fileAttribList.Where(fa => fa.ID != kept.ID))
				{
					// For each duplicate, update the FileAttribRefs in the affected signer dictionary.
					Dictionary<string, Signer>? dictionaryToProcess = partition.Key switch
					{
						"allowedUMCI" => allowedSignerUMCIDictionary,
						"deniedUMCI" => deniedSignerUMCIDictionary,
						"allowedKMCI" => allowedSignerKMCIDictionary,
						"deniedKMCI" => deniedSignerKMCIDictionary,
						_ => null
					};
					if (dictionaryToProcess is not null)
					{
						// Iterate through each signer in the target dictionary.
						foreach (Signer signer in dictionaryToProcess.Values)
						{
							if (signer.FileAttribRef is not null)
							{
								// Update each FileAttribRef that references the duplicate by swapping its RuleID.
								foreach (FileAttribRef fileAttribRef in signer.FileAttribRef)
								{
									if (fileAttribRef.RuleID == duplicate.ID)
									{
										fileAttribRef.RuleID = kept.ID;
									}
								}
							}
						}
					}
					// Mark the duplicate FileAttrib for removal later.
					_ = fileAttribIdsToRemove.Add(duplicate.ID);
				}
			}
		}
	}

	/// <summary>
	/// Compares two version strings using the System.Version class.
	/// Returns -1 if v1 is lower than v2, 1 if v1 is higher than v2, or 0 if they are equal or unparsable.
	/// </summary>
	/// <param name="v1"></param>
	/// <param name="v2"></param>
	/// <returns></returns>
	private static int CompareVersions(string v1, string v2)
	{
		if (Version.TryParse(v1, out Version? version1) && Version.TryParse(v2, out Version? version2))
		{
			return version1.CompareTo(version2);
		}
		// Fallback: treat unparsable strings as equal.
		return 0;
	}

}
