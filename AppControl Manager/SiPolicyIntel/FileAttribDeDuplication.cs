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
using AppControlManager.SiPolicy;

namespace AppControlManager.SiPolicyIntel;

/// <summary>
/// When 2 different <see cref="FilePublisherSignerRule"/> or <see cref="WHQLFilePublisher"/> level <see cref="Signer"/>s reference the same <see cref="FileAttrib"/> (i.e., the certificate details are the same but the file's properties are different)
/// And they are in different <see cref="SigningScenario"/> and/or one of them allows and the other denies, the <see cref="FileAttrib"/>s that they point to via <see cref="FileAttribRef"/>s MUST remain.
/// However, if the <see cref="Signer"/>s belong to the same <see cref="SigningScenario"/> and/or they both allow or deny, both <see cref="Signer"/>s CAN reference the same <see cref="FileAttrib"/>.
/// This kind of De-duplication is not necessary but if it is to be done, each <see cref="Signer"/> must have its context.
/// Context: Whether signer is allowing or denying, or if it's <see cref="SSType.KernelMode"/> or <see cref="SSType.UserMode"/>.
///
/// So 1 <see cref="FileAttrib"/> is enough for a single file to refer to all of its <see cref="Signer"/>s that are in the same <see cref="SigningScenario"/> and <see cref="Authorization"/> section.
/// The only time when 2 <see cref="FileAttrib"/> for the same file (with same details) need to exist is when the same file is referenced in different <see cref="SigningScenario"/>s and/or <see cref="Authorization"/> sections, and for each <see cref="SigningScenario"/>/<see cref="Authorization"/> section there needs to be a different <see cref="FileAttrib"/>.
/// </summary>
internal static class FileAttribDeDuplication
{

	internal static void EnsureUniqueFileAttributes(ref List<object> fileRulesNode, List<Signer> signers, List<AllowedSigner> userModeAllowedSigners, List<DeniedSigner> userModeDeniedSigners, List<AllowedSigner> kernelModeAllowedSigners, List<DeniedSigner> kernelModeDeniedSigners)
	{
		// Step 1: Group duplicate FileAttribs using custom equality logic.

		// Each group contains FileAttribs that are considered duplicates based on our custom rules.
		List<List<FileAttrib>> duplicateGroups = [];
		foreach (object item in CollectionsMarshal.AsSpan(fileRulesNode))
		{
			if (item is FileAttrib fileAttrib)
			{
				bool addedToGroup = false;
				foreach (List<FileAttrib> group in CollectionsMarshal.AsSpan(duplicateGroups))
				{
					// Use the first element of the group as the representative.
					FileAttrib group0 = group[0];

					if (Merger.CompareCommonRuleProperties(
						null, null,
						null, null,
						group0.PackageFamilyName, fileAttrib.PackageFamilyName,
						group0.Hash, fileAttrib.Hash,
						group0.FilePath, fileAttrib.FilePath,
						group0.FileName, fileAttrib.FileName,
						group0.MinimumFileVersion, fileAttrib.MinimumFileVersion,
						group0.MaximumFileVersion, fileAttrib.MaximumFileVersion,
						group0.InternalName, fileAttrib.InternalName,
						group0.FileDescription, fileAttrib.FileDescription,
						group0.ProductName, fileAttrib.ProductName))
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
		}


		// Step 2: Build a dictionary of all Signers.

		// This dictionary indexes Signer objects by their ID for later lookup.
		Dictionary<string, Signer> signerDictionary = new(signers.Count, StringComparer.OrdinalIgnoreCase);
		foreach (Signer signer in CollectionsMarshal.AsSpan(signers))
		{
			if (!signerDictionary.TryAdd(signer.ID, signer))
			{
				Logger.Write(string.Format(GlobalVars.GetStr("DuplicateSignerIdMessage"), signer.ID));
			}
		}


		// Step 3: Partition signers into four dictionaries based on their mode and type.

		// We create four dictionaries: Allowed and Denied for User Mode and Kernel Mode.
		Dictionary<string, Signer> allowedSignerUMCIDictionary = new(userModeAllowedSigners.Count, StringComparer.OrdinalIgnoreCase);
		Dictionary<string, Signer> allowedSignerKMCIDictionary = new(kernelModeAllowedSigners.Count, StringComparer.OrdinalIgnoreCase);
		Dictionary<string, Signer> deniedSignerUMCIDictionary = new(userModeDeniedSigners.Count, StringComparer.OrdinalIgnoreCase);
		Dictionary<string, Signer> deniedSignerKMCIDictionary = new(kernelModeDeniedSigners.Count, StringComparer.OrdinalIgnoreCase);

		// Process each SigningScenario from the policy.

		// For each User-Mode allowed signer, add it to the corresponding dictionary
		foreach (AllowedSigner item in CollectionsMarshal.AsSpan(userModeAllowedSigners))
		{
			if (signerDictionary.TryGetValue(item.SignerId, out Signer? signer))
			{
				allowedSignerUMCIDictionary.Add(item.SignerId, signer);
			}
		}

		// For each Kernel-Mode allowed signer, add it to the corresponding dictionary
		foreach (AllowedSigner item in CollectionsMarshal.AsSpan(kernelModeAllowedSigners))
		{
			if (signerDictionary.TryGetValue(item.SignerId, out Signer? signer))
			{
				allowedSignerKMCIDictionary.Add(item.SignerId, signer);
			}
		}

		// For each User-Mode denied signer, add it to the corresponding dictionary
		foreach (DeniedSigner item in CollectionsMarshal.AsSpan(userModeDeniedSigners))
		{
			if (signerDictionary.TryGetValue(item.SignerId, out Signer? signer))
			{
				deniedSignerUMCIDictionary.Add(item.SignerId, signer);
			}
		}

		// For each Kernel-Mode denied signer, add it to the corresponding dictionary
		foreach (DeniedSigner item in CollectionsMarshal.AsSpan(kernelModeDeniedSigners))
		{
			if (signerDictionary.TryGetValue(item.SignerId, out Signer? signer))
			{
				deniedSignerKMCIDictionary.Add(item.SignerId, signer);
			}
		}


		// Step 4: Process duplicate groups to update FileAttribRefs and mark duplicates.

		// We keep track of FileAttrib IDs that must be removed from FileRules.
		HashSet<string> fileAttribIdsToRemove = new(StringComparer.Ordinal);
		foreach (List<FileAttrib> group in CollectionsMarshal.AsSpan(duplicateGroups))
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


		// Step 5: Update the FileRules collection to remove duplicate FileAttrib objects.
		_ = fileRulesNode.RemoveAll(item => item is FileAttrib fa && fileAttribIdsToRemove.Contains(fa.ID));


		// Step 6: Post-process each signer to deduplicate FileAttribRef arrays.

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
		foreach (Signer signer in CollectionsMarshal.AsSpan(signers))
		{
			if (signer.FileAttribRef?.Count > 1)
			{
				signer.FileAttribRef = [.. signer.FileAttribRef
					.GroupBy(r => r.RuleID)
					.Select(g => g.First())];
			}
		}
	}

	/// <summary>
	/// For a group of duplicate <see cref="FileAttrib"/>s, this method deduplicates them within the same <see cref="Signer"/> dictionary.
	/// It updates <see cref="FileAttribRef"/>s by swapping the <see cref="FileAttribRef.RuleID"/> from the duplicate to the one kept.
	/// Only duplicates that are referenced exclusively from a <see cref="Signer"/> dictionary (usage key without a comma) are deduplicated.
	/// </summary>
	private static void ProcessDuplicateGroup(List<FileAttrib> group, Dictionary<string, Signer> allowedSignerUMCIDictionary, Dictionary<string, Signer> deniedSignerUMCIDictionary, Dictionary<string, Signer> allowedSignerKMCIDictionary, Dictionary<string, Signer> deniedSignerKMCIDictionary, HashSet<string> fileAttribIdsToRemove)
	{
		// Create a mapping of each FileAttrib to the set of signer dictionary keys in which it is referenced.
		// The keys can be: "allowedUMCI", "deniedUMCI", "allowedKMCI", "deniedKMCI".
		Dictionary<FileAttrib, HashSet<string>> usage = new(group.Count);
		foreach (FileAttrib fa in CollectionsMarshal.AsSpan(group))
		{
			HashSet<string> dicts = new(2, StringComparer.OrdinalIgnoreCase); // Average capacity initially

			// Check if any signer in Allowed User Mode references this FileAttrib.
			if (allowedSignerUMCIDictionary.Values.Any(signer => signer.FileAttribRef is not null && signer.FileAttribRef.Any(r => string.Equals(r.RuleID, fa.ID, StringComparison.OrdinalIgnoreCase))))
			{
				_ = dicts.Add("allowedUMCI");
			}
			// Check if any signer in Denied User Mode references this FileAttrib.
			if (deniedSignerUMCIDictionary.Values.Any(signer => signer.FileAttribRef is not null && signer.FileAttribRef.Any(r => string.Equals(r.RuleID, fa.ID, StringComparison.OrdinalIgnoreCase))))
			{
				_ = dicts.Add("deniedUMCI");
			}
			// Check if any signer in Allowed Kernel Mode references this FileAttrib.
			if (allowedSignerKMCIDictionary.Values.Any(signer => signer.FileAttribRef is not null && signer.FileAttribRef.Any(r => string.Equals(r.RuleID, fa.ID, StringComparison.OrdinalIgnoreCase))))
			{
				_ = dicts.Add("allowedKMCI");
			}
			// Check if any signer in Denied Kernel Mode references this FileAttrib.
			if (deniedSignerKMCIDictionary.Values.Any(signer => signer.FileAttribRef is not null && signer.FileAttribRef.Any(r => string.Equals(r.RuleID, fa.ID, StringComparison.OrdinalIgnoreCase))))
			{
				_ = dicts.Add("deniedKMCI");
			}
			usage[fa] = dicts;
		}

		// Partition the FileAttribs by their usage keys.
		// The key is a comma-separated string representing the set of dictionaries in which the FileAttrib is referenced.
		// The keys can be: "allowedUMCI", "deniedUMCI", "allowedKMCI", "deniedKMCI".
		Dictionary<string, List<FileAttrib>> partitions = new(usage.Count);
		foreach (KeyValuePair<FileAttrib, HashSet<string>> kvp in usage)
		{
			string key = string.Join(",", kvp.Value.OrderBy(s => s)); // Sorting ensures consistent key ordering.
			if (!partitions.TryGetValue(key, out List<FileAttrib>? value))
			{
				value = [];
				partitions[key] = value;
			}

			value.Add(kvp.Key);
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
					foreach (FileAttrib fa in CollectionsMarshal.AsSpan(fileAttribList))
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
					foreach (FileAttrib fa in CollectionsMarshal.AsSpan(fileAttribList))
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
								foreach (FileAttribRef fileAttribRef in CollectionsMarshal.AsSpan(signer.FileAttribRef))
								{
									if (string.Equals(fileAttribRef.RuleID, duplicate.ID, StringComparison.OrdinalIgnoreCase))
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
