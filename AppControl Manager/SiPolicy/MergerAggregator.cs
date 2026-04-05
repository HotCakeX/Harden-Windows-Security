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
using AppControlManager.SiPolicyIntel;
using CommonCore.IntelGathering;

namespace AppControlManager.SiPolicy;

internal static partial class Merger
{
	/// <summary>
	/// This is a context-aware method that collects all "Allow" elements or Allow rules in the policy from FileRules node/section.
	/// It de-duplicates them using a custom HashSet.
	/// </summary>
	/// <param name="siPolicies"></param>
	/// <returns></returns>
	private static HashSet<AllowRule> CollectAllowRules(List<SiPolicy> siPolicies)
	{
		// HashSet to store the unique Allow rules
		HashSet<AllowRule> allowRules = new(new AllowRuleComparer());

		// Loop over each policy input data
		foreach (SiPolicy siPolicy in CollectionsMarshal.AsSpan(siPolicies))
		{

			// Index Allow rules by their ID for quick lookup
			// ID will be key and Allow rule itself will be the value
			Dictionary<string, Allow>? allowRuleDictionary = siPolicy.FileRules?.OfType<Allow>()
				.ToDictionary(fileRule => fileRule.ID, fileRule => fileRule);

			// Skip if the policy doesn't have any Allow rules
			if (allowRuleDictionary is null)
			{
				continue;
			}

			// Find all FileRuleRefs in SigningScenarios and map them to Allow rules
			foreach (SigningScenario signingScenario in CollectionsMarshal.AsSpan(siPolicy.SigningScenarios))
			{
				// Get all possible FileRuleRef items from the current signing scenario
				List<FileRuleRef>? possibleFileRuleRef = signingScenario.ProductSigners.FileRulesRef?.FileRuleRef;

				// Determine SigningScenario type
				SSType scenarioType = signingScenario.Value == 12 ? SSType.UserMode : SSType.KernelMode;

				if (possibleFileRuleRef is { Count: > 0 })
				{
					// Loop over each FileRuleRef in the current Signing Scenario
					foreach (FileRuleRef fileRuleRef in CollectionsMarshal.AsSpan(possibleFileRuleRef))
					{
						// See if the current FileRuleRef has a corresponding Allow rule in the <FileRules> node so we know it's valid
						if (allowRuleDictionary.TryGetValue(fileRuleRef.RuleID, out Allow? allowElement))
						{
							// Create a new ID
							string rand = $"ID_ALLOW_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";

							// Create a new Allow rule
							// We don't wanna modify the original one, otherwise we end up with Allow rules with duplicate IDs
							Allow allowElementCopy = new(id: rand)
							{
								FriendlyName = allowElement.FriendlyName,
								FileName = allowElement.FileName,
								InternalName = allowElement.InternalName,
								FileDescription = allowElement.FileDescription,
								ProductName = allowElement.ProductName,
								PackageFamilyName = allowElement.PackageFamilyName,
								PackageVersion = allowElement.PackageVersion,
								MinimumFileVersion = allowElement.MinimumFileVersion,
								MaximumFileVersion = allowElement.MaximumFileVersion,
								Hash = allowElement.Hash,
								AppIDs = allowElement.AppIDs,
								FilePath = allowElement.FilePath,
								RequireHotpatchID = allowElement.RequireHotpatchID,
								MinimumHotpatchSequence = allowElement.MinimumHotpatchSequence,
								MaximumHotpatchSequence = allowElement.MaximumHotpatchSequence
							};

							// Create a new FileRuleRef
							FileRuleRef fileRuleRefCopy = new(ruleID: rand);

							AllowRule allowRule = new(
								allowElement: allowElementCopy,
								fileRuleRefElement: fileRuleRefCopy,
								signingScenario: scenarioType);

							_ = allowRules.Add(allowRule);

						}
					}
				}
			}
		}

		return allowRules;
	}

	/// <summary>
	/// This is a context-aware method that collects all "Deny" elements or Deny rules in the policy from FileRules node/section.
	/// It de-duplicates them using a custom HashSet.
	/// </summary>
	/// <param name="siPolicies"></param>
	/// <returns></returns>
	private static HashSet<DenyRule> CollectDenyRules(List<SiPolicy> siPolicies)
	{
		// HashSet to store the unique Deny rules
		HashSet<DenyRule> denyRules = new(new DenyRuleComparer());

		// Loop over each policy input data
		foreach (SiPolicy siPolicy in CollectionsMarshal.AsSpan(siPolicies))
		{
			// Index Deny rules by their ID for quick lookup
			// ID will be key and Deny rule itself will be the value
			Dictionary<string, Deny>? denyRuleDictionary = siPolicy.FileRules?.OfType<Deny>()
				.ToDictionary(fileRule => fileRule.ID, fileRule => fileRule);

			// Skip if the policy doesn't have any Deny rules
			if (denyRuleDictionary is null)
			{
				continue;
			}

			// Find all FileRuleRefs in SigningScenarios and map them to DenyRules
			foreach (SigningScenario signingScenario in CollectionsMarshal.AsSpan(siPolicy.SigningScenarios))
			{
				// Get all possible FileRuleRef items from the current signing scenario
				List<FileRuleRef>? possibleFileRuleRef = signingScenario.ProductSigners.FileRulesRef?.FileRuleRef;

				// Determine SigningScenario type
				SSType scenarioType = signingScenario.Value == 12 ? SSType.UserMode : SSType.KernelMode;

				if (possibleFileRuleRef is { Count: > 0 })
				{
					foreach (FileRuleRef fileRuleRef in CollectionsMarshal.AsSpan(possibleFileRuleRef))
					{
						if (denyRuleDictionary.TryGetValue(fileRuleRef.RuleID, out Deny? denyElement))
						{
							// Create a new ID
							string rand = $"ID_DENY_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";

							// Create a new Deny rule
							Deny denyElementCopy = new(id: rand)
							{
								FriendlyName = denyElement.FriendlyName,
								FileName = denyElement.FileName,
								InternalName = denyElement.InternalName,
								FileDescription = denyElement.FileDescription,
								ProductName = denyElement.ProductName,
								PackageFamilyName = denyElement.PackageFamilyName,
								PackageVersion = denyElement.PackageVersion,
								MinimumFileVersion = denyElement.MinimumFileVersion,
								MaximumFileVersion = denyElement.MaximumFileVersion,
								Hash = denyElement.Hash,
								AppIDs = denyElement.AppIDs,
								FilePath = denyElement.FilePath
							};

							// Create a new FileRuleRef
							FileRuleRef fileRuleRefCopy = new(ruleID: rand);

							DenyRule allowRule = new(
								denyElement: denyElementCopy,
								fileRuleRefElement: fileRuleRefCopy,
								signingScenario: scenarioType);

							_ = denyRules.Add(allowRule);
						}
					}
				}
			}

		}

		return denyRules;
	}

	/// <summary>
	/// This is a context-aware method that collects all "FileRule" elements or FileRule rules in the policy from FileRules node/section.
	/// It de-duplicates them using a custom HashSet.
	/// </summary>
	/// <param name="siPolicies"></param>
	/// <returns></returns>
	private static HashSet<FileRuleRule> CollectFileRules(List<SiPolicy> siPolicies)
	{
		// HashSet to store the unique FileRule rules
		HashSet<FileRuleRule> fileRuleRules = new(new FileRuleRuleComparer());

		// Loop over each policy input data
		foreach (SiPolicy siPolicy in CollectionsMarshal.AsSpan(siPolicies))
		{
			// Index FileRules by their ID for quick lookup
			// ID will be key and FileRule rule itself will be the value
			Dictionary<string, FileRule>? fileRuleDictionary = siPolicy.FileRules?.OfType<FileRule>()
				.ToDictionary(fileRule => fileRule.ID, fileRule => fileRule);

			// Skip if the policy doesn't have any FileRule rules
			if (fileRuleDictionary is null)
			{
				continue;
			}

			// Find all FileRuleRefs in SigningScenarios and map them to FileRules
			foreach (SigningScenario signingScenario in CollectionsMarshal.AsSpan(siPolicy.SigningScenarios))
			{
				// Get all possible FileRuleRef items from the current signing scenario
				List<FileRuleRef>? possibleFileRuleRef = signingScenario.ProductSigners.FileRulesRef?.FileRuleRef;

				// Determine SigningScenario type
				SSType scenarioType = signingScenario.Value == 12 ? SSType.UserMode : SSType.KernelMode;

				if (possibleFileRuleRef is { Count: > 0 })
				{
					foreach (FileRuleRef fileRuleRef in CollectionsMarshal.AsSpan(possibleFileRuleRef))
					{
						if (fileRuleDictionary.TryGetValue(fileRuleRef.RuleID, out FileRule? fileRuleElement))
						{
							// Create a new ID
							string rand = $"ID_FILE_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";

							FileRule fileRuleElementCopy = new(id: rand, type: fileRuleElement.Type)
							{
								FriendlyName = fileRuleElement.FriendlyName,
								FileName = fileRuleElement.FileName,
								InternalName = fileRuleElement.InternalName,
								FileDescription = fileRuleElement.FileDescription,
								ProductName = fileRuleElement.ProductName,
								PackageFamilyName = fileRuleElement.PackageFamilyName,
								PackageVersion = fileRuleElement.PackageVersion,
								MinimumFileVersion = fileRuleElement.MinimumFileVersion,
								MaximumFileVersion = fileRuleElement.MaximumFileVersion,
								Hash = fileRuleElement.Hash,
								AppIDs = fileRuleElement.AppIDs,
								FilePath = fileRuleElement.FilePath
							};

							// Create a new FileRuleRef
							FileRuleRef fileRuleRefCopy = new(ruleID: rand);

							FileRuleRule fileRuleNew = new(
								fileRuleElement: fileRuleElementCopy,
								fileRuleRefElement: fileRuleRefCopy,
								signingScenario: scenarioType);

							_ = fileRuleRules.Add(fileRuleNew);

						}
					}
				}
			}
		}

		return fileRuleRules;
	}

	/// <summary>
	/// This is a context-aware method that collects all "Signer" elements or Signer rules in the policy from Signers node/section.
	/// Each signer is complete and has all of the elements that can be used in the policy file independently.
	/// </summary>
	/// <param name="siPolicies"></param>
	/// <returns></returns>
	private static SignerCollection CollectSignerRules(List<SiPolicy> siPolicies)
	{
		// The output with HashSets to store unique data
		SignerCollection signerCollection = new
		(
			filePublisherSigners: new(new FilePublisherSignerRuleComparer()),
			signerRules: new(new PublisherSignerRuleComparer()),
			wHQLPublishers: new(new WHQLPublisherSignerRuleComparer()),
			wHQLFilePublishers: new(new WHQLFilePublisherSignerRuleComparer()),
			updatePolicySigners: new(new UpdatePolicySignerRuleComparer()),
			supplementalPolicySigners: new(new SupplementalPolicySignerRuleComparer())
		);

		// Loop over each policy input data
		foreach (SiPolicy siPolicy in CollectionsMarshal.AsSpan(siPolicies))
		{

			// Index elements for efficient lookup
			Dictionary<string, FileAttrib>? fileAttribDictionary = siPolicy.FileRules?.OfType<FileAttrib>()
				.ToDictionary(fileAttrib => fileAttrib.ID, fileAttrib => fileAttrib);

			// Get all of the <Signer> elements from the policy
			Dictionary<string, Signer> signerDictionary = new(siPolicy.Signers?.Count ?? 0, StringComparer.Ordinal);

			foreach (Signer signer in CollectionsMarshal.AsSpan(siPolicy.Signers))
			{
				if (!signerDictionary.TryAdd(signer.ID, signer))
				{
					Logger.Write(string.Format(Atlas.GetStr("DuplicateSignerIdMessage"), signer.ID));
				}
			}

			// ID of all of the CiSigners if they exist
			HashSet<string> ciSignerSet = [.. siPolicy.CiSigners?.Select(ciSigner => ciSigner.SignerId) ?? []];

			// Dictionary to store all of the EKUs
			Dictionary<string, EKU> ekuDictionary = siPolicy.EKUs?.ToDictionary(eku => eku.ID, eku => eku) ?? [];

			// ID of all of the SupplementalPolicySigners if they exist
			HashSet<string> supplementalPolicySignersSet = [.. siPolicy.SupplementalPolicySigners?.Select(supplementalPolicySigner => supplementalPolicySigner.SignerId) ?? []];

			// ID of all of the UpdatePolicySigners if they exist
			HashSet<string> updatePolicySignersSet = [.. siPolicy.UpdatePolicySigners?.Select(updatePolicySigner => updatePolicySigner.SignerId) ?? []];


			// Step 1: Collecting UpdatePolicySigners and SupplementalPolicySigners separately
			// Because they are not part of any SigningScenario and don't have Allowed/Denied signers
			ProcessSupplementalPolicySigners(supplementalPolicySignersSet, signerDictionary, signerCollection);

			ProcessUpdatePolicySigners(updatePolicySignersSet, signerDictionary, signerCollection);


			// Step 2: Process SigningScenarios
			foreach (SigningScenario signingScenario in CollectionsMarshal.AsSpan(siPolicy.SigningScenarios))
			{
				List<AllowedSigner>? allowedSigners = signingScenario.ProductSigners.AllowedSigners?.AllowedSigner;
				List<DeniedSigner>? deniedSigners = signingScenario.ProductSigners.DeniedSigners?.DeniedSigner;

				// Determine SigningScenario type
				SSType scenarioType = signingScenario.Value == 12 ? SSType.UserMode : SSType.KernelMode;

				if (allowedSigners is { Count: > 0 })
				{
					// Process Allowed Signers
					foreach (AllowedSigner item in CollectionsMarshal.AsSpan(allowedSigners))
					{
						// Get the Signer element associated with the current AllowedSigner
						if (signerDictionary.TryGetValue(item.SignerId, out Signer? signer))
						{
							AddSignerRule(
								signer,
								scenarioType,
								Authorization.Allow,
								item,
								null,
								ciSignerSet,
								fileAttribDictionary,
								signerCollection,
								ekuDictionary);
						}
					}
				}

				if (deniedSigners is { Count: > 0 })
				{
					// Process Denied Signers
					foreach (DeniedSigner item in CollectionsMarshal.AsSpan(deniedSigners))
					{
						if (signerDictionary.TryGetValue(item.SignerId, out Signer? signer))
						{
							AddSignerRule(
								signer,
								scenarioType,
								Authorization.Deny,
								null,
								item,
								ciSignerSet,
								fileAttribDictionary,
								signerCollection,
								ekuDictionary);
						}
					}
				}
			}
		}

		return signerCollection;
	}

	/// <summary>
	/// Helper method that categorizes each signer
	/// </summary>
	/// <param name="signer"></param>
	/// <param name="scenarioType"></param>
	/// <param name="auth"></param>
	/// <param name="allowedSigner"></param>
	/// <param name="deniedSigner"></param>
	/// <param name="ciSignerSet"></param>
	/// <param name="fileAttribDictionary"></param>
	/// <param name="signerCollection"></param>
	/// <param name="ekuDictionary"></param>
	private static void AddSignerRule(
	Signer signer,
	SSType scenarioType,
	Authorization auth,
	AllowedSigner? allowedSigner,
	DeniedSigner? deniedSigner,
	HashSet<string> ciSignerSet,
	Dictionary<string, FileAttrib>? fileAttribDictionary,
	SignerCollection signerCollection,
	Dictionary<string, EKU> ekuDictionary)
	{
		// Check if the signer is also a CiSigner
		bool isCiSigner = ciSignerSet.Contains(signer.ID);

		// Gather all associated FileAttribs
		List<FileAttrib> associatedFileAttribs = [];
		if (fileAttribDictionary is not null)
		{
			foreach (FileAttribRef fileAttribRef in CollectionsMarshal.AsSpan(signer.FileAttribRef))
			{
				if (fileAttribDictionary.TryGetValue(fileAttribRef.RuleID, out FileAttrib? fileAttrib))
				{
					associatedFileAttribs.Add(fileAttrib);
				}
			}
		}

		// Gather all associated EKUs
		List<EKU> associatedEKUs = [];
		foreach (CertEKU certEku in CollectionsMarshal.AsSpan(signer.CertEKU))
		{
			if (ekuDictionary.TryGetValue(certEku.ID, out EKU? eku))
			{
				associatedEKUs.Add(eku);
			}
		}

		// Generate a new ID
		string newSignerID = $"ID_SIGNER_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";

		// ------ Classification ------ \\

		// If the Signer has FileAttribs: WHQLFilePublisher or FilePublisher
		if (associatedFileAttribs.Count is not 0)
		{
			// If the Signer has EKU: WHQLFilePublisher
			if (associatedEKUs.Count is not 0)
			{
				// Create the new signer element
				Signer newSigner = new(
					id: newSignerID,
					name: signer.Name,
					certRoot: signer.CertRoot
					)
				{
					CertEKU = signer.CertEKU,
					CertIssuer = signer.CertIssuer,
					CertPublisher = signer.CertPublisher,
					CertOemID = signer.CertOemID,
					FileAttribRef = signer.FileAttribRef,
					SignTimeAfter = signer.SignTimeAfter
				};

				// Create the new AllowedSigner element
				AllowedSigner? newAllowedSigner = null;
				if (allowedSigner is not null)
				{
					newAllowedSigner = new(
						signerId: newSignerID,
						exceptDenyRule: allowedSigner.ExceptDenyRule
					);
				}

				// Create the new DeniedSigner element
				DeniedSigner? newDeniedSigner = null;
				if (deniedSigner is not null)
				{
					newDeniedSigner = new(
						signerId: newSignerID,
						exceptAllowRule: deniedSigner.ExceptAllowRule
					);
				}


				#region FileAttribs

				// Create a pre-sized collection to store the new FileAttribs associated with the Signer
				List<FileAttrib> newFileAttribs = new(associatedFileAttribs.Count);

				List<FileAttribRef> signerFileAttribRefs = new(associatedFileAttribs.Count);

				foreach (FileAttrib item in CollectionsMarshal.AsSpan(associatedFileAttribs))
				{
					string tempID = $"ID_FILEATTRIB_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";

					newFileAttribs.Add(new(id: tempID)
					{
						FriendlyName = item.FriendlyName,
						FileName = item.FileName,
						InternalName = item.InternalName,
						FileDescription = item.FileDescription,
						ProductName = item.ProductName,
						PackageFamilyName = item.PackageFamilyName,
						PackageVersion = item.PackageVersion,
						MinimumFileVersion = item.MinimumFileVersion,
						MaximumFileVersion = item.MaximumFileVersion,
						Hash = item.Hash,
						AppIDs = item.AppIDs,
						FilePath = item.FilePath
					});

					// Create a new FileAttribRef for the FileAttrib with the new RuleID
					signerFileAttribRefs.Add(new(ruleID: tempID));
				}

				// Replace the FileAttribRefs of the Signer with the new ones
				newSigner.FileAttribRef = signerFileAttribRefs;
				#endregion


				#region EKUs
				List<EKU> newEKUs = new(associatedEKUs.Count);
				List<CertEKU> signerCertEKUs = new(associatedEKUs.Count);

				foreach (EKU item in CollectionsMarshal.AsSpan(associatedEKUs))
				{
					string tempID = $"ID_EKU_E_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";

					// Clone the EKU to avoid modifying the original object
					newEKUs.Add(new(
						id: tempID,
						value: item.Value,
						friendlyName: item.FriendlyName
					));

					signerCertEKUs.Add(new(id: tempID));
				}

				// Replace the CertEKUs of the Signer with the new ones
				newSigner.CertEKU = signerCertEKUs;
				#endregion


				// WHQLFilePublisher
				_ = signerCollection.WHQLFilePublishers.Add(new WHQLFilePublisher(
					fileAttribElements: newFileAttribs,
					allowedSignerElement: newAllowedSigner,
					deniedSignerElement: newDeniedSigner,
					ciSignerElement: isCiSigner ? new CiSigner(signerID: newSignerID) : null,
					signerElement: newSigner,
					ekus: newEKUs,
					signingScenario: scenarioType,
					auth: auth));
			}
			else // FilePublisher
			{
				// Create the new signer element
				Signer newSigner = new(
					name: signer.Name,
					id: newSignerID,
					certRoot: signer.CertRoot
					)
				{
					CertEKU = signer.CertEKU,
					CertIssuer = signer.CertIssuer,
					CertPublisher = signer.CertPublisher,
					CertOemID = signer.CertOemID,
					FileAttribRef = signer.FileAttribRef,
					SignTimeAfter = signer.SignTimeAfter
				};

				// Create the new AllowedSigner element
				AllowedSigner? newAllowedSigner = null;
				if (allowedSigner is not null)
				{
					newAllowedSigner = new(
						signerId: newSignerID,
						exceptDenyRule: allowedSigner.ExceptDenyRule
					);
				}

				// Create the new DeniedSigner element
				DeniedSigner? newDeniedSigner = null;
				if (deniedSigner is not null)
				{
					newDeniedSigner = new(
						signerId: newSignerID,
						exceptAllowRule: deniedSigner.ExceptAllowRule
					);
				}


				#region FileAttribs

				// Create a pre-sized collection to store the new FileAttribs associated with the Signer
				List<FileAttrib> newFileAttribs = new(associatedFileAttribs.Count);

				List<FileAttribRef> signerFileAttribRefs = new(associatedFileAttribs.Count);

				foreach (FileAttrib item in CollectionsMarshal.AsSpan(associatedFileAttribs))
				{
					string tempID = $"ID_FILEATTRIB_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";

					newFileAttribs.Add(new(id: tempID)
					{
						FriendlyName = item.FriendlyName,
						FileName = item.FileName,
						InternalName = item.InternalName,
						FileDescription = item.FileDescription,
						ProductName = item.ProductName,
						PackageFamilyName = item.PackageFamilyName,
						PackageVersion = item.PackageVersion,
						MinimumFileVersion = item.MinimumFileVersion,
						MaximumFileVersion = item.MaximumFileVersion,
						Hash = item.Hash,
						AppIDs = item.AppIDs,
						FilePath = item.FilePath
					});

					// Create a new FileAttribRef for the FileAttrib with the new RuleID
					signerFileAttribRefs.Add(new(ruleID: tempID));
				}

				// Replace the FileAttribRefs of the Signer with the new ones
				newSigner.FileAttribRef = signerFileAttribRefs;
				#endregion


				// FilePublisherSignerRule
				_ = signerCollection.FilePublisherSigners.Add(new FilePublisherSignerRule
				(
					fileAttribElements: newFileAttribs,
					allowedSignerElement: newAllowedSigner,
					deniedSignerElement: newDeniedSigner,
					ciSignerElement: isCiSigner ? new CiSigner(signerID: newSignerID) : null,
					signerElement: newSigner,
					signingScenario: scenarioType,
					auth: auth
				));
			}
		}
		else if (associatedEKUs.Count is not 0) // WHQLPublisher
		{
			// Create the new signer element
			Signer newSigner = new(
				name: signer.Name,
				id: newSignerID,
				certRoot: signer.CertRoot
				)
			{
				CertEKU = signer.CertEKU,
				CertIssuer = signer.CertIssuer,
				CertPublisher = signer.CertPublisher,
				CertOemID = signer.CertOemID,
				FileAttribRef = signer.FileAttribRef,
				SignTimeAfter = signer.SignTimeAfter
			};

			// Create the new AllowedSigner element
			AllowedSigner? newAllowedSigner = null;
			if (allowedSigner is not null)
			{
				newAllowedSigner = new(
					signerId: newSignerID,
					exceptDenyRule: allowedSigner.ExceptDenyRule
				);
			}

			// Create the new DeniedSigner element
			DeniedSigner? newDeniedSigner = null;
			if (deniedSigner is not null)
			{
				newDeniedSigner = new(
					signerId: newSignerID,
					exceptAllowRule: deniedSigner.ExceptAllowRule
				);
			}

			#region EKUs
			List<EKU> newEKUs = new(associatedEKUs.Count);
			List<CertEKU> signerCertEKUs = new(associatedEKUs.Count);

			foreach (EKU item in CollectionsMarshal.AsSpan(associatedEKUs))
			{
				string tempID = $"ID_EKU_E_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";

				// Clone the EKU to avoid modifying the original object
				newEKUs.Add(new(
					id: tempID,
					value: item.Value,
					friendlyName: item.FriendlyName
				));

				signerCertEKUs.Add(new(id: tempID));
			}

			// Replace the CertEKUs of the Signer with the new ones
			newSigner.CertEKU = signerCertEKUs;
			#endregion


			// WHQLPublisher
			_ = signerCollection.WHQLPublishers.Add(new WHQLPublisher(
				allowedSignerElement: newAllowedSigner,
				deniedSignerElement: newDeniedSigner,
				ciSignerElement: isCiSigner ? new CiSigner(signerID: newSignerID) : null,
				signerElement: newSigner,
				ekus: newEKUs,
				signingScenario: scenarioType,
				auth: auth));
		}
		else // Publisher aka generic Signer rule
		{
			// Create the new signer element
			Signer newSigner = new(
				name: signer.Name,
				id: newSignerID,
				certRoot: signer.CertRoot
				)
			{
				CertEKU = signer.CertEKU,
				CertIssuer = signer.CertIssuer,
				CertPublisher = signer.CertPublisher,
				CertOemID = signer.CertOemID,
				FileAttribRef = signer.FileAttribRef,
				SignTimeAfter = signer.SignTimeAfter
			};

			// Create the new AllowedSigner element
			AllowedSigner? newAllowedSigner = null;
			if (allowedSigner is not null)
			{
				newAllowedSigner = new(
					signerId: newSignerID,
					exceptDenyRule: allowedSigner.ExceptDenyRule
				);
			}

			// Create the new DeniedSigner element
			DeniedSigner? newDeniedSigner = null;
			if (deniedSigner is not null)
			{
				newDeniedSigner = new(
					signerId: newSignerID,
					exceptAllowRule: deniedSigner.ExceptAllowRule
				);
			}

			// Generic SignerRule
			_ = signerCollection.SignerRules.Add(new SignerRule
			(
				signerElement: newSigner,
				allowedSignerElement: newAllowedSigner,
				deniedSignerElement: newDeniedSigner,
				ciSignerElement: isCiSigner ? new CiSigner(signerID: newSignerID) : null,
				signingScenario: scenarioType,
				auth: auth
			));
		}
	}

	/// <summary>
	/// Processes SupplementalPolicySigners
	/// </summary>
	/// <param name="supplementalPolicySignerIDs"></param>
	/// <param name="Signers"></param>
	/// <param name="signerCollection"></param>
	private static void ProcessSupplementalPolicySigners(
		HashSet<string> supplementalPolicySignerIDs,
		Dictionary<string, Signer> Signers,
		SignerCollection signerCollection)
	{
		foreach (string ID in supplementalPolicySignerIDs)
		{
			if (Signers.TryGetValue(ID, out Signer? possibleSupplementalPolicySigner))
			{
				// Create random ID for the signer and its corresponding SupplementalPolicySigner element
				string newSignerID = $"ID_SIGNER_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";

				// Create the new signer element
				Signer newSigner = new(
					id: newSignerID,
					name: possibleSupplementalPolicySigner.Name,
					certRoot: possibleSupplementalPolicySigner.CertRoot
					)
				{
					CertEKU = possibleSupplementalPolicySigner.CertEKU,
					CertIssuer = possibleSupplementalPolicySigner.CertIssuer,
					CertPublisher = possibleSupplementalPolicySigner.CertPublisher,
					CertOemID = possibleSupplementalPolicySigner.CertOemID,
					FileAttribRef = possibleSupplementalPolicySigner.FileAttribRef,
					SignTimeAfter = possibleSupplementalPolicySigner.SignTimeAfter
				};

				// Create a new SupplementalPolicySigner element with the new ID
				SupplementalPolicySigner suppRule = new(signerID: newSignerID);

				_ = signerCollection.SupplementalPolicySigners.Add(new SupplementalPolicySignerRule(
					signerElement: newSigner,
					supplementalPolicySigner: suppRule));
			}
		}
	}

	/// <summary>
	/// Processes UpdatePolicySigners
	/// </summary>
	/// <param name="updatePolicySignerIDs"></param>
	/// <param name="Signers"></param>
	/// <param name="signerCollection"></param>
	private static void ProcessUpdatePolicySigners(
		HashSet<string> updatePolicySignerIDs,
		Dictionary<string, Signer> Signers,
		SignerCollection signerCollection)
	{
		foreach (string ID in updatePolicySignerIDs)
		{
			if (Signers.TryGetValue(ID, out Signer? possibleUpdatePolicySigner))
			{
				// Create random ID for the signer and its corresponding UpdatePolicySigner element
				string newSignerID = $"ID_SIGNER_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";

				// Create the new signer element
				Signer newSigner = new(
					id: newSignerID,
					name: possibleUpdatePolicySigner.Name,
					certRoot: possibleUpdatePolicySigner.CertRoot
					)
				{
					CertEKU = possibleUpdatePolicySigner.CertEKU,
					CertIssuer = possibleUpdatePolicySigner.CertIssuer,
					CertPublisher = possibleUpdatePolicySigner.CertPublisher,
					CertOemID = possibleUpdatePolicySigner.CertOemID,
					FileAttribRef = possibleUpdatePolicySigner.FileAttribRef,
					SignTimeAfter = possibleUpdatePolicySigner.SignTimeAfter
				};

				// Create a new UpdatePolicySigner element with the new ID
				UpdatePolicySigner uppRule = new(signerID: newSignerID);

				_ = signerCollection.UpdatePolicySigners.Add(new UpdatePolicySignerRule(
					signerElement: newSigner,
					updatePolicySigner: uppRule));
			}
		}
	}

}
