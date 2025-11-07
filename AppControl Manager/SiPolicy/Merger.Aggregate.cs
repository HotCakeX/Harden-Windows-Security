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
using AppControlManager.SiPolicyIntel;

namespace AppControlManager.SiPolicy;

internal static class Factory
{
	/// <summary>
	/// This is a context-aware method that collects all "Allow" elements or Allow rules in the policy from FileRules node/section.
	/// It de-duplicates them using a custom HashSet.
	/// </summary>
	/// <param name="siPolicies"></param>
	/// <returns></returns>
	internal static HashSet<AllowRule> CollectAllowRules(List<SiPolicy> siPolicies)
	{
		// HashSet to store the unique Allow rules
		HashSet<AllowRule> allowRules = new(new AllowRuleComparer());

		// Loop over each policy input data
		foreach (SiPolicy siPolicy in siPolicies)
		{

			// Index Allow rules by their ID for quick lookup
			// ID will be key and Allow rule itself will be the value
			Dictionary<string, Allow>? fileRuleDictionary = siPolicy.FileRules?.OfType<Allow>()
				.ToDictionary(fileRule => fileRule.ID, fileRule => fileRule);

			// Skip if the policy doesn't have any Allow rules
			if (fileRuleDictionary is null)
			{
				continue;
			}

			// Find all FileRuleRefs in SigningScenarios and map them to Allow rules
			foreach (SigningScenario signingScenario in siPolicy.SigningScenarios)
			{
				// Get all possible FileRuleRef items from the current signing scenario
				FileRuleRef[]? possibleFileRuleRef = signingScenario.ProductSigners?.FileRulesRef?.FileRuleRef;

				if (possibleFileRuleRef is { Length: > 0 })
				{
					// Loop over each FileRuleRef in the current Signing Scenario
					foreach (FileRuleRef fileRuleRef in possibleFileRuleRef)
					{
						// See if the current FileRuleRef has a corresponding Allow rule in the <FileRules> node so we know it's valid
						if (fileRuleDictionary.TryGetValue(fileRuleRef.RuleID, out Allow? allowElement))
						{
							// Create a new ID
							string rand = $"ID_ALLOW_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";

							// Create a new Allow rule
							// We don't wanna modify the original one, otherwise we end up with Allow rules with duplicate IDs
							Allow allowElementCopy = new()
							{
								ID = rand,
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
								FilePath = allowElement.FilePath
							};

							// Create a new FileRuleRef
							FileRuleRef fileRuleRefCopy = new()
							{
								RuleID = rand
							};

							AllowRule allowRule = new(
								allowElement: allowElementCopy,
								fileRuleRefElement: fileRuleRefCopy,
								signingScenario: signingScenario.Value == 12 ? SSType.UserMode : SSType.KernelMode);

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
	internal static HashSet<DenyRule> CollectDenyRules(List<SiPolicy> siPolicies)
	{
		// HashSet to store the unique Deny rules
		HashSet<DenyRule> denyRules = new(new DenyRuleComparer());

		// Loop over each policy input data
		foreach (SiPolicy siPolicy in siPolicies)
		{
			// Index Deny rules by their ID for quick lookup
			// ID will be key and Deny rule itself will be the value
			Dictionary<string, Deny>? fileRuleDictionary = siPolicy.FileRules?.OfType<Deny>()
				.ToDictionary(fileRule => fileRule.ID, fileRule => fileRule);

			// Skip if the policy doesn't have any Deny rules
			if (fileRuleDictionary is null)
			{
				continue;
			}

			// Find all FileRuleRefs in SigningScenarios and map them to DenyRules
			foreach (SigningScenario signingScenario in siPolicy.SigningScenarios)
			{
				// Get all possible FileRuleRef items from the current signing scenario
				FileRuleRef[]? possibleFileRuleRef = signingScenario.ProductSigners?.FileRulesRef?.FileRuleRef;

				if (possibleFileRuleRef is { Length: > 0 })
				{
					foreach (FileRuleRef fileRuleRef in possibleFileRuleRef)
					{
						if (fileRuleDictionary.TryGetValue(fileRuleRef.RuleID, out Deny? denyElement))
						{

							string rand = $"ID_DENY_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";

							// Create a new Deny rule
							Deny denyElementCopy = new()
							{
								ID = rand,
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
							FileRuleRef fileRuleRefCopy = new()
							{
								RuleID = rand
							};

							DenyRule allowRule = new(
								denyElement: denyElementCopy,
								fileRuleRefElement: fileRuleRefCopy,
								signingScenario: signingScenario.Value == 12 ? SSType.UserMode : SSType.KernelMode);

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
	internal static HashSet<FileRuleRule> CollectFileRules(List<SiPolicy> siPolicies)
	{
		// HashSet to store the unique FileRule rules
		HashSet<FileRuleRule> fileRuleRules = new(new FileRuleRuleComparer());

		// Loop over each policy input data
		foreach (SiPolicy siPolicy in siPolicies)
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
			foreach (SigningScenario signingScenario in siPolicy.SigningScenarios)
			{
				// Get all possible FileRuleRef items from the current signing scenario
				FileRuleRef[]? possibleFileRuleRef = signingScenario.ProductSigners?.FileRulesRef?.FileRuleRef;

				if (possibleFileRuleRef is { Length: > 0 })
				{
					foreach (FileRuleRef fileRuleRef in possibleFileRuleRef)
					{
						if (fileRuleDictionary.TryGetValue(fileRuleRef.RuleID, out FileRule? fileRuleElement))
						{

							string rand = $"ID_FILE_A_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}";

							FileRule fileRuleElementCopy = new()
							{
								ID = rand,
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
								FilePath = fileRuleElement.FilePath,
								Type = fileRuleElement.Type
							};

							// Create a new FileRuleRef
							FileRuleRef fileRuleRefCopy = new()
							{
								RuleID = rand
							};

							FileRuleRule fileRuleNew = new(
								fileRuleElement: fileRuleElementCopy,
								fileRuleRefElement: fileRuleRefCopy,
								signingScenario: signingScenario.Value == 12 ? SSType.UserMode : SSType.KernelMode
							);
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
	internal static SignerCollection CollectSignerRules(List<SiPolicy> siPolicies)
	{

		// HashSets to store unique data
		HashSet<FilePublisherSignerRule> filePublisherSigners = new(new FilePublisherSignerRuleComparer());
		HashSet<SignerRule> signerRules = new(new PublisherSignerRuleComparer());
		HashSet<WHQLFilePublisher> whqlFilePublishers = new(new WHQLFilePublisherSignerRuleComparer());
		HashSet<WHQLPublisher> wHQLPublishers = new(new WHQLPublisherSignerRuleComparer());
		HashSet<UpdatePolicySignerRule> updatePolicySignerRules = new(new UpdatePolicySignerRuleComparer());
		HashSet<SupplementalPolicySignerRule> supplementalPolicySignerRules = new(new SupplementalPolicySignerRuleComparer());

		// Loop over each policy input data
		foreach (SiPolicy siPolicy in siPolicies)
		{

			// Index elements for efficient lookup
			Dictionary<string, FileAttrib>? fileAttribDictionary = siPolicy.FileRules?.OfType<FileAttrib>()
				.ToDictionary(fileAttrib => fileAttrib.ID, fileAttrib => fileAttrib);

			// Get all of the <Signer> elements from the policy
			Dictionary<string, Signer> signerDictionary = [];

			foreach (Signer signer in siPolicy.Signers)
			{
				if (!signerDictionary.TryAdd(signer.ID, signer))
				{
					Logger.Write(string.Format(GlobalVars.GetStr("DuplicateSignerIdMessage"), signer.ID));
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


			// Collecting UpdatePolicySigners and SupplementalPolicySigners separately
			// Because they are not part of any SigningScenario and don't have Allowed/Denied signers
			ProcessSupplementalPolicySigners(supplementalPolicySignersSet, signerDictionary, supplementalPolicySignerRules);

			ProcessUpdatePolicySigners(updatePolicySignersSet, signerDictionary, updatePolicySignerRules);


			// Step 2: Process SigningScenarios
			foreach (SigningScenario signingScenario in siPolicy.SigningScenarios)
			{
				// If the signing scenario has product signers
				ProductSigners? possibleProdSigners = signingScenario.ProductSigners;

				if (possibleProdSigners is not null)
				{
					AllowedSigner[]? allowedSigners = possibleProdSigners.AllowedSigners?.AllowedSigner;
					DeniedSigner[]? deniedSigners = possibleProdSigners.DeniedSigners?.DeniedSigner;

					if (allowedSigners is { Length: > 0 })
					{
						// Process Allowed Signers
						foreach (AllowedSigner item in allowedSigners)
						{
							// Get the Signer element associated with the current AllowedSigner
							if (signerDictionary.TryGetValue(item.SignerId, out Signer? signer))
							{
								AddSignerRule(
									signer,
									signingScenario,
									Authorization.Allow,
									item,
									null,
									ciSignerSet,
									fileAttribDictionary,
									filePublisherSigners,
									signerRules,
									wHQLPublishers,
									whqlFilePublishers,
									ekuDictionary);
							}
						}
					}

					if (deniedSigners is { Length: > 0 })
					{
						// Process Denied Signers
						foreach (DeniedSigner item in deniedSigners)
						{
							if (signerDictionary.TryGetValue(item.SignerId, out Signer? signer))
							{
								AddSignerRule(
									signer,
									signingScenario,
									Authorization.Deny,
									null,
									item,
									ciSignerSet,
									fileAttribDictionary,
									filePublisherSigners,
									signerRules,
									wHQLPublishers,
									whqlFilePublishers,
									ekuDictionary);
							}
						}
					}
				}
			}

		}

		return new SignerCollection
		(
			filePublisherSigners: filePublisherSigners,
			signerRules: signerRules,
			wHQLPublishers: wHQLPublishers,
			wHQLFilePublishers: whqlFilePublishers,
			updatePolicySigners: updatePolicySignerRules,
			supplementalPolicySigners: supplementalPolicySignerRules
		);
	}


	/// <summary>
	/// Helper method that categorizes each signer
	/// </summary>
	/// <param name="signer"></param>
	/// <param name="signingScenario"></param>
	/// <param name="auth"></param>
	/// <param name="allowedSigner"></param>
	/// <param name="deniedSigner"></param>
	/// <param name="ciSignerSet"></param>
	/// <param name="fileAttribDictionary"></param>
	/// <param name="filePublisherSigners"></param>
	/// <param name="signerRules"></param>
	/// <param name="WHQLPublishers"></param>
	/// <param name="WHQLFilePublishers"></param>
	/// <param name="ekuDictionary"></param>
	private static void AddSignerRule(
	Signer signer,
	SigningScenario signingScenario,
	Authorization auth,
	AllowedSigner? allowedSigner,
	DeniedSigner? deniedSigner,
	HashSet<string> ciSignerSet,
	Dictionary<string, FileAttrib>? fileAttribDictionary,
	HashSet<FilePublisherSignerRule> filePublisherSigners,
	HashSet<SignerRule> signerRules,
	HashSet<WHQLPublisher> WHQLPublishers,
	HashSet<WHQLFilePublisher> WHQLFilePublishers,
	Dictionary<string, EKU> ekuDictionary)
	{
		// Determine SigningScenario type
		SSType scenarioType = signingScenario.Value == 12 ? SSType.UserMode : SSType.KernelMode;

		// Check if the signer is also a CiSigner
		bool isCiSigner = ciSignerSet.Contains(signer.ID);

		// Gather all associated FileAttribs
		List<FileAttrib> associatedFileAttribs = signer.FileAttribRef?
			.Select(fileAttribRef => fileAttribDictionary?.GetValueOrDefault(fileAttribRef.RuleID))
			.Where(fileAttrib => fileAttrib is not null) // Ensure no nulls
			.Cast<FileAttrib>()                         // Safe cast to non-nullable type
			.ToList() ?? [];

		// Gather all associated EKUs
		List<EKU> associatedEKUs = signer.CertEKU?
			.Select(certEku => ekuDictionary.GetValueOrDefault(certEku.ID))
			.Where(eku => eku is not null)             // Ensure no nulls
			.Cast<EKU>()                               // Safe cast to non-nullable type
			.ToList() ?? [];

		// Generate a new ID
		string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
		string newSignerID = $"ID_SIGNER_A_{guid}";

		// ------ Classification ------ \\

		// If the Signer has FileAttribs
		if (associatedFileAttribs.Count is not 0)
		{
			// If the Signer has EKU
			if (associatedEKUs.Count is not 0)
			{
				// Create the new signer element
				Signer newSigner = new()
				{
					CertRoot = signer.CertRoot,
					CertEKU = signer.CertEKU,
					CertIssuer = signer.CertIssuer,
					CertPublisher = signer.CertPublisher,
					CertOemID = signer.CertOemID,
					FileAttribRef = signer.FileAttribRef,
					Name = signer.Name,
					ID = newSignerID,
					SignTimeAfter = signer.SignTimeAfter,
					SignTimeAfterSpecified = signer.SignTimeAfterSpecified
				};

				// Create the new AllowedSigner element
				AllowedSigner? newAllowedSigner = null;
				if (allowedSigner is not null)
				{
					newAllowedSigner = new()
					{
						SignerId = newSignerID,
						ExceptDenyRule = allowedSigner.ExceptDenyRule
					};
				}

				// Create the new DeniedSigner element
				DeniedSigner? newDeniedSigner = null;
				if (deniedSigner is not null)
				{
					newDeniedSigner = new()
					{
						SignerId = newSignerID,
						ExceptAllowRule = deniedSigner.ExceptAllowRule
					};
				}


				#region FileAttribs

				// Create a fixed size collection to store the new FileAttribs associated with the Signer
				List<FileAttrib> newFileAttribs = new(associatedFileAttribs.Count);

				List<FileAttribRef> signerFileAttribRefs = new(associatedFileAttribs.Count);

				foreach (FileAttrib item in associatedFileAttribs)
				{
					string tempGuid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
					string tempID = $"ID_FILEATTRIB_A_{tempGuid}";

					newFileAttribs.Add(new()
					{
						ID = tempID,
						FriendlyName = item.FriendlyName,
						FileName = item.FileName,
						InternalName = item.InternalName,
						FileDescription = item.FileDescription,
						ProductName = item.ProductName,
						PackageFamilyName = item.PackageFamilyName,
						PackageVersion = item.PackageVersion,
						MinimumFileVersion = item.MinimumFileVersion,
						MaximumFileVersion = item.MaximumFileVersion,
						Hash = item.Hash is null ? null : (byte[])item.Hash.Clone(),
						AppIDs = item.AppIDs,
						FilePath = item.FilePath
					});

					// Create a new FileAttribRef for the FileAttrib with the new RuleID
					signerFileAttribRefs.Add(new()
					{
						RuleID = tempID
					});
				}

				// Replace the FileAttribRefs of the Signer with the new ones
				newSigner.FileAttribRef = [.. signerFileAttribRefs];
				#endregion


				#region EKUs
				List<EKU> newEKUs = new(associatedEKUs.Count);
				List<CertEKU> signerCertEKUs = new(associatedEKUs.Count);

				foreach (EKU item in associatedEKUs)
				{
					string tempGuid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
					string tempID = $"ID_EKU_E_{tempGuid}";

					// Clone the EKU to avoid modifying the original object
					newEKUs.Add(new()
					{
						ID = tempID,
						Value = item.Value,
						FriendlyName = item.FriendlyName
					});

					signerCertEKUs.Add(new()
					{
						ID = tempID
					});
				}

				// Replace the CertEKUs of the Signer with the new ones
				newSigner.CertEKU = [.. signerCertEKUs];
				#endregion


				// WHQLFilePublisher
				_ = WHQLFilePublishers.Add(new WHQLFilePublisher(
					fileAttribElements: newFileAttribs,
					allowedSignerElement: newAllowedSigner,
					deniedSignerElement: newDeniedSigner,
					ciSignerElement: isCiSigner ? new CiSigner { SignerId = newSignerID } : null,
					signerElement: newSigner,
					ekus: newEKUs,
					signingScenario: scenarioType,
					auth: auth));
			}
			else
			{
				// Create the new signer element
				Signer newSigner = new()
				{
					CertRoot = signer.CertRoot,
					CertEKU = signer.CertEKU,
					CertIssuer = signer.CertIssuer,
					CertPublisher = signer.CertPublisher,
					CertOemID = signer.CertOemID,
					FileAttribRef = signer.FileAttribRef,
					Name = signer.Name,
					ID = newSignerID,
					SignTimeAfter = signer.SignTimeAfter,
					SignTimeAfterSpecified = signer.SignTimeAfterSpecified
				};

				// Create the new AllowedSigner element
				AllowedSigner? newAllowedSigner = null;
				if (allowedSigner is not null)
				{
					newAllowedSigner = new()
					{
						SignerId = newSignerID,
						ExceptDenyRule = allowedSigner.ExceptDenyRule
					};
				}

				// Create the new DeniedSigner element
				DeniedSigner? newDeniedSigner = null;
				if (deniedSigner is not null)
				{
					newDeniedSigner = new()
					{
						SignerId = newSignerID,
						ExceptAllowRule = deniedSigner.ExceptAllowRule
					};
				}


				#region FileAttribs

				// Create a fixed size collection to store the new FileAttribs associated with the Signer
				List<FileAttrib> newFileAttribs = new(associatedFileAttribs.Count);

				List<FileAttribRef> signerFileAttribRefs = new(associatedFileAttribs.Count);

				foreach (FileAttrib item in associatedFileAttribs)
				{

					string tempGuid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
					string tempID = $"ID_FILEATTRIB_A_{tempGuid}";

					newFileAttribs.Add(new()
					{
						ID = tempID,
						FriendlyName = item.FriendlyName,
						FileName = item.FileName,
						InternalName = item.InternalName,
						FileDescription = item.FileDescription,
						ProductName = item.ProductName,
						PackageFamilyName = item.PackageFamilyName,
						PackageVersion = item.PackageVersion,
						MinimumFileVersion = item.MinimumFileVersion,
						MaximumFileVersion = item.MaximumFileVersion,
						Hash = item.Hash is null ? null : (byte[])item.Hash.Clone(),
						AppIDs = item.AppIDs,
						FilePath = item.FilePath
					});

					// Create a new FileAttribRef for the FileAttrib with the new RuleID
					signerFileAttribRefs.Add(new()
					{
						RuleID = tempID
					});
				}

				// Replace the FileAttribRefs of the Signer with the new ones
				newSigner.FileAttribRef = [.. signerFileAttribRefs];
				#endregion


				// FilePublisherSignerRule
				_ = filePublisherSigners.Add(new FilePublisherSignerRule
				(
					fileAttribElements: newFileAttribs,
					allowedSignerElement: newAllowedSigner,
					deniedSignerElement: newDeniedSigner,
					ciSignerElement: isCiSigner ? new CiSigner { SignerId = newSignerID } : null,
					signerElement: newSigner,
					signingScenario: scenarioType,
					auth: auth
				));
			}
		}
		else if (associatedEKUs.Count is not 0)
		{
			// Create the new signer element
			Signer newSigner = new()
			{
				CertRoot = signer.CertRoot,
				CertEKU = signer.CertEKU,
				CertIssuer = signer.CertIssuer,
				CertPublisher = signer.CertPublisher,
				CertOemID = signer.CertOemID,
				FileAttribRef = signer.FileAttribRef,
				Name = signer.Name,
				ID = newSignerID,
				SignTimeAfter = signer.SignTimeAfter,
				SignTimeAfterSpecified = signer.SignTimeAfterSpecified
			};

			// Create the new AllowedSigner element
			AllowedSigner? newAllowedSigner = null;
			if (allowedSigner is not null)
			{
				newAllowedSigner = new()
				{
					SignerId = newSignerID,
					ExceptDenyRule = allowedSigner.ExceptDenyRule
				};
			}

			// Create the new DeniedSigner element
			DeniedSigner? newDeniedSigner = null;
			if (deniedSigner is not null)
			{
				newDeniedSigner = new()
				{
					SignerId = newSignerID,
					ExceptAllowRule = deniedSigner.ExceptAllowRule
				};
			}

			#region EKUs
			List<EKU> newEKUs = new(associatedEKUs.Count);
			List<CertEKU> signerCertEKUs = new(associatedEKUs.Count);

			foreach (EKU item in associatedEKUs)
			{
				string tempGuid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
				string tempID = $"ID_EKU_E_{tempGuid}";

				// Clone the EKU to avoid modifying the original object
				newEKUs.Add(new()
				{
					ID = tempID,
					Value = item.Value,
					FriendlyName = item.FriendlyName
				});

				signerCertEKUs.Add(new()
				{
					ID = tempID
				});
			}

			// Replace the CertEKUs of the Signer with the new ones
			newSigner.CertEKU = [.. signerCertEKUs];
			#endregion


			// WHQLPublisher
			_ = WHQLPublishers.Add(new WHQLPublisher(
				allowedSignerElement: newAllowedSigner,
				deniedSignerElement: newDeniedSigner,
				ciSignerElement: isCiSigner ? new CiSigner { SignerId = newSignerID } : null,
				signerElement: newSigner,
				ekus: newEKUs,
				signingScenario: scenarioType,
				auth: auth));
		}
		else
		{
			// Create the new signer element
			Signer newSigner = new()
			{
				CertRoot = signer.CertRoot,
				CertEKU = signer.CertEKU,
				CertIssuer = signer.CertIssuer,
				CertPublisher = signer.CertPublisher,
				CertOemID = signer.CertOemID,
				FileAttribRef = signer.FileAttribRef,
				Name = signer.Name,
				ID = newSignerID,
				SignTimeAfter = signer.SignTimeAfter,
				SignTimeAfterSpecified = signer.SignTimeAfterSpecified
			};

			// Create the new AllowedSigner element
			AllowedSigner? newAllowedSigner = null;
			if (allowedSigner is not null)
			{
				newAllowedSigner = new()
				{
					SignerId = newSignerID,
					ExceptDenyRule = allowedSigner.ExceptDenyRule
				};
			}

			// Create the new DeniedSigner element
			DeniedSigner? newDeniedSigner = null;
			if (deniedSigner is not null)
			{
				newDeniedSigner = new()
				{
					SignerId = newSignerID,
					ExceptAllowRule = deniedSigner.ExceptAllowRule
				};
			}

			// Generic SignerRule
			_ = signerRules.Add(new SignerRule
			(
				signerElement: newSigner,
				allowedSignerElement: newAllowedSigner,
				deniedSignerElement: newDeniedSigner,
				ciSignerElement: isCiSigner ? new CiSigner { SignerId = newSignerID } : null,
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
	/// <param name="supplementalPolicySignersSet"></param>
	private static void ProcessSupplementalPolicySigners(
		HashSet<string> supplementalPolicySignerIDs,
		Dictionary<string, Signer> Signers,
		HashSet<SupplementalPolicySignerRule> supplementalPolicySignersSet)
	{
		foreach (string ID in supplementalPolicySignerIDs)
		{
			if (Signers.TryGetValue(ID, out Signer? possibleSupplementalPolicySigner))
			{

				// Create random ID for the signer and its corresponding SupplementalPolicySigner element
				string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
				string newSignerID = $"ID_SIGNER_A_{guid}";

				// Create the new signer element
				Signer newSigner = new()
				{
					CertRoot = possibleSupplementalPolicySigner.CertRoot,
					CertEKU = possibleSupplementalPolicySigner.CertEKU,
					CertIssuer = possibleSupplementalPolicySigner.CertIssuer,
					CertPublisher = possibleSupplementalPolicySigner.CertPublisher,
					CertOemID = possibleSupplementalPolicySigner.CertOemID,
					FileAttribRef = possibleSupplementalPolicySigner.FileAttribRef,
					Name = possibleSupplementalPolicySigner.Name,
					ID = newSignerID,
					SignTimeAfter = possibleSupplementalPolicySigner.SignTimeAfter,
					SignTimeAfterSpecified = possibleSupplementalPolicySigner.SignTimeAfterSpecified
				};

				// Create a new SupplementalPolicySigner element with the new ID
				SupplementalPolicySigner suppRule = new()
				{
					SignerId = newSignerID
				};

				_ = supplementalPolicySignersSet.Add(new SupplementalPolicySignerRule(
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
	/// <param name="updatePolicySignersSet"></param>
	private static void ProcessUpdatePolicySigners(
		HashSet<string> updatePolicySignerIDs,
		Dictionary<string, Signer> Signers,
		HashSet<UpdatePolicySignerRule> updatePolicySignersSet)
	{
		foreach (string ID in updatePolicySignerIDs)
		{
			if (Signers.TryGetValue(ID, out Signer? possibleUpdatePolicySigner))
			{

				// Create random ID for the signer and its corresponding UpdatePolicySigner element
				string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
				string newSignerID = $"ID_SIGNER_A_{guid}";

				// Create the new signer element
				Signer newSigner = new()
				{
					CertRoot = possibleUpdatePolicySigner.CertRoot,
					CertEKU = possibleUpdatePolicySigner.CertEKU,
					CertIssuer = possibleUpdatePolicySigner.CertIssuer,
					CertPublisher = possibleUpdatePolicySigner.CertPublisher,
					CertOemID = possibleUpdatePolicySigner.CertOemID,
					FileAttribRef = possibleUpdatePolicySigner.FileAttribRef,
					Name = possibleUpdatePolicySigner.Name,
					ID = newSignerID,
					SignTimeAfter = possibleUpdatePolicySigner.SignTimeAfter,
					SignTimeAfterSpecified = possibleUpdatePolicySigner.SignTimeAfterSpecified
				};

				// Create a new UpdatePolicySigner element with the new ID
				UpdatePolicySigner uppRule = new()
				{
					SignerId = newSignerID
				};

				_ = updatePolicySignersSet.Add(new UpdatePolicySignerRule(
					signerElement: newSigner,
					updatePolicySigner: uppRule));
			}
		}
	}

}
