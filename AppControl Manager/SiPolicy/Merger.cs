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
using System.Threading.Tasks;
using AppControlManager.Others;
using AppControlManager.SiPolicyIntel;

namespace AppControlManager.SiPolicy;

/// <summary>
/// --- EXTRA information regarding the overall merge operation and what needs to happen ---
///
/// The FilePublisher and Publisher Signers in an XML file must be based on their TBS, Name, and/or CertPublisher values.
/// For each FilePublisher signer, if two signers are found with the same TBS, Name, and CertPublisher, only one of them shall be kept, and their FileAttribRefs shall be merged.
/// For each Publisher signer, if two signers are found with the same TBS, Name, and/or CertPublisher, only one of them shall be kept.
///
/// Distinction shall be made between FilePublisher and Publisher signers: If two signers have the same TBS, Name, and/or CertPublisher but only one of them has FileAttribRefs, then they are not the same.
/// A signer can only be associated with a single SigningScenario at a time. So if a Signer needs to be allowed for both user and kernel mode, it should be mentioned twice, with different IDs.
/// So there are 4 different Signer types to consider.
///
///
/// Each "Allow" node in "FileRules" nodes is associated only with one Signing scenario at a time. Same goes for "Deny" nodes.
///
/// In the "EKUs" node there must be unique EKUs only based on their value. If 2 Signers need to reference the same EKU value, they must use same EKU's ID in their CertEKU section.
///
/// </summary>
internal static class Merger
{
	/// <summary>
	/// This is the Main method that is responsible for merging 2 or more App Control policies,
	/// Or only acting on 1 policy which will result in de-duplication.
	/// The result will be saved in the first policy and there will be no duplicate data.
	/// The first policy's data that are non-collections will be maintained.
	/// Only the data that are collections will be merged.
	/// No date is lost in the merge process.
	/// </summary>
	/// <param name="mainPolicy"></param>
	/// <param name="otherPolicies"></param>
	internal static SiPolicy Merge(SiPolicy mainPolicy, List<SiPolicy>? otherPolicies)
	{
		// Create a list of all SiPolicy objects that will participate in the merge process.
		// Add the main policy.
		List<SiPolicy> allPolicies = [mainPolicy];

		// Add any other policies
		if (otherPolicies is not null)
			allPolicies.AddRange(otherPolicies);

		// Collections used to store the data and pass between methods
		List<EKU> ekusToUse = [];
		List<object> fileRulesNode = [];
		List<Signer> signers = [];
		IEnumerable<CiSigner> ciSigners = [];
		IEnumerable<AllowedSigner> userModeAllowedSigners = [];
		IEnumerable<DeniedSigner> userModeDeniedSigners = [];
		IEnumerable<AllowedSigner> kernelModeAllowedSigners = [];
		IEnumerable<DeniedSigner> kernelModeDeniedSigners = [];
		List<SupplementalPolicySigner> supplementalPolicySignersCol = [];
		List<UpdatePolicySigner> updatePolicySignersCol = [];
		HashSet<FileRuleRule> fileRules = []; // Not used by the policy generator method in here
		HashSet<DenyRule> denyRules = []; // Not used by the policy generator method in here
		HashSet<AllowRule> allowRules = []; // Not used by the policy generator method in here
		SignerCollection? signerCollection = null; // Not used by the policy generator method in here
		List<FileRuleRef> kernelModeFileRulesRefs = [];
		List<FileRuleRef> userModeFileRulesRefs = [];
		AppIDTags? userModeAppIDTags = null;
		AppIDTags? kernelModeAppIDTags = null;

		// Deserialize, de-duplicate, merge
		// Doesn't return anything and only acts on the referenced collections.
		PolicyDeserializer(
		   allPolicies,
		   ref ekusToUse,
		   ref fileRulesNode,
		   ref signers,
		   ref ciSigners,
		   ref userModeAllowedSigners,
		   ref userModeDeniedSigners,
		   ref kernelModeAllowedSigners,
		   ref kernelModeDeniedSigners,
		   ref supplementalPolicySignersCol,
		   ref updatePolicySignersCol,
		   ref fileRules,
		   ref denyRules,
		   ref allowRules,
		   ref signerCollection,
		   ref kernelModeFileRulesRefs,
		   ref userModeFileRulesRefs,
		   ref userModeAppIDTags,
		   ref kernelModeAppIDTags
		   );


		// Generate the policy and return it
		return PolicyGenerator(
		   mainPolicy,
		   ekusToUse,
		   fileRulesNode,
		   signers,
		   ciSigners,
		   userModeAllowedSigners,
		   userModeDeniedSigners,
		   kernelModeAllowedSigners,
		   kernelModeDeniedSigners,
		   supplementalPolicySignersCol,
		   updatePolicySignersCol,
		   kernelModeFileRulesRefs,
		   userModeFileRulesRefs,
		   mainPolicy.Settings, // Pass the main policy's Settings for the merge unless there is a need to merge the Settings during a merge operation.
		   userModeAppIDTags,
		   kernelModeAppIDTags);
	}


	/// <summary>
	/// Accepts a list of SiPolicy objects, and accepts many other collections, fills them with data.
	/// </summary>
	/// <param name="allPolicies">Input data</param>
	/// <param name="ekusToUse">Output data</param>
	/// <param name="fileRulesNode">Output data</param>
	/// <param name="signers">Output data</param>
	/// <param name="ciSigners">Output data</param>
	/// <param name="userModeAllowedSigners">Output data</param>
	/// <param name="userModeDeniedSigners">Output data</param>
	/// <param name="kernelModeAllowedSigners">Output data</param>
	/// <param name="kernelModeDeniedSigners">Output data</param>
	/// <param name="supplementalPolicySignersCol">Output data</param>
	/// <param name="updatePolicySignersCol">Output data</param>
	/// <param name="fileRules">Output data</param>
	/// <param name="denyRules">Output data</param>
	/// <param name="allowRules">Output data</param>
	/// <param name="signerCollection">Output data</param>
	/// <param name="kernelModeFileRulesRefs">Output data</param>
	/// <param name="userModeFileRulesRefs">Output data</param>
	internal static void PolicyDeserializer(
		List<SiPolicy> allPolicies,
		ref List<EKU> ekusToUse,
		ref List<object> fileRulesNode,
		ref List<Signer> signers,
		ref IEnumerable<CiSigner> ciSigners,
		ref IEnumerable<AllowedSigner> userModeAllowedSigners,
		ref IEnumerable<DeniedSigner> userModeDeniedSigners,
		ref IEnumerable<AllowedSigner> kernelModeAllowedSigners,
		ref IEnumerable<DeniedSigner> kernelModeDeniedSigners,
		ref List<SupplementalPolicySigner> supplementalPolicySignersCol,
		ref List<UpdatePolicySigner> updatePolicySignersCol,
		ref HashSet<FileRuleRule> fileRules,
		ref HashSet<DenyRule> denyRules,
		ref HashSet<AllowRule> allowRules,
		ref SignerCollection? signerCollection,
		ref List<FileRuleRef> kernelModeFileRulesRefs,
		ref List<FileRuleRef> userModeFileRulesRefs,
		ref AppIDTags? userModeAppIDTags,
		ref AppIDTags? kernelModeAppIDTags
		)
	{
		// Data aggregation
		// ID randomization
		// De-duplication
		Task<HashSet<AllowRule>> taskAllowRules = Task.Run(() => Factory.CollectAllowRules(allPolicies));
		Task<HashSet<DenyRule>> taskDenyRules = Task.Run(() => Factory.CollectDenyRules(allPolicies));
		Task<HashSet<FileRuleRule>> taskFileRules = Task.Run(() => Factory.CollectFileRules(allPolicies));
		Task<SignerCollection> taskSignerRules = Task.Run(() => Factory.CollectSignerRules(allPolicies));

		// Await all tasks to complete
		Task.WaitAll(taskAllowRules, taskDenyRules, taskFileRules, taskSignerRules);

		// Retrieve the results
		// These are everything retrieved from the SiPolicy objects directly
		// That's why we need to await their results before proceeding further
		allowRules = taskAllowRules.Result;
		denyRules = taskDenyRules.Result;
		fileRules = taskFileRules.Result;
		signerCollection = taskSignerRules.Result;

		// Initialize temporary lists for output collections
		// Their ref types are IEnumerable because of HashSets
		List<CiSigner> tempCiSigners = [];
		List<AllowedSigner> tempUserModeAllowed = [];
		List<DeniedSigner> tempUserModeDenied = [];
		List<AllowedSigner> tempKernelModeAllowed = [];
		List<DeniedSigner> tempKernelModeDenied = [];


		// Process AllowRules
		//  - Add AllowElement to FileRulesNode
		//  - Add FileRuleRefElement to User/Kernel lists based on Scenario
		foreach (AllowRule item in allowRules)
		{
			fileRulesNode.Add(item.AllowElement);

			if (item.SigningScenario is SSType.UserMode)
			{
				userModeFileRulesRefs.Add(item.FileRuleRefElement);
			}
			else
			{
				kernelModeFileRulesRefs.Add(item.FileRuleRefElement);
			}
		}

		// Process DenyRules
		//  - Add DenyElement to FileRulesNode
		//  - Add FileRuleRefElement to User/Kernel lists based on Scenario
		foreach (DenyRule item in denyRules)
		{
			fileRulesNode.Add(item.DenyElement);

			if (item.SigningScenario is SSType.UserMode)
			{
				userModeFileRulesRefs.Add(item.FileRuleRefElement);
			}
			else
			{
				kernelModeFileRulesRefs.Add(item.FileRuleRefElement);
			}
		}

		// Process FileRuleRules (Base FileRules)
		//  - Add FileRuleElement to FileRulesNode
		//  - Add FileRuleRefElement to User/Kernel lists based on Scenario
		foreach (FileRuleRule item in fileRules)
		{
			fileRulesNode.Add(item.FileRuleElement);

			if (item.SigningScenario is SSType.UserMode)
			{
				userModeFileRulesRefs.Add(item.FileRuleRefElement);
			}
			else
			{
				kernelModeFileRulesRefs.Add(item.FileRuleRefElement);
			}
		}

		// Process FilePublisherSigners
		//  - Add SignerElement
		//  - Add FileAttribElements to FileRulesNode
		//  - Process Auth (Allow/Deny) and CiSigners for User/Kernel modes
		foreach (FilePublisherSignerRule item in signerCollection.FilePublisherSigners)
		{
			signers.Add(item.SignerElement);

			// Add associated file attributes
			fileRulesNode.AddRange(item.FileAttribElements);

			// Scenario-specific logic
			if (item.SigningScenario is SSType.UserMode)
			{
				if (item.CiSignerElement is not null)
				{
					tempCiSigners.Add(item.CiSignerElement);
				}

				if (item.Auth is Authorization.Allow && item.AllowedSignerElement is not null)
				{
					tempUserModeAllowed.Add(item.AllowedSignerElement);
				}
				else if (item.Auth is Authorization.Deny && item.DeniedSignerElement is not null)
				{
					tempUserModeDenied.Add(item.DeniedSignerElement);
				}
			}
			else // KernelMode
			{
				if (item.Auth is Authorization.Allow && item.AllowedSignerElement is not null)
				{
					tempKernelModeAllowed.Add(item.AllowedSignerElement);
				}
				else if (item.Auth is Authorization.Deny && item.DeniedSignerElement is not null)
				{
					tempKernelModeDenied.Add(item.DeniedSignerElement);
				}
			}
		}

		// Process WHQLFilePublishers
		//  - Add SignerElement
		//  - Add EKUs
		//  - Add FileAttribElements to FileRulesNode
		//  - Process Auth (Allow/Deny) and CiSigners for User/Kernel modes
		foreach (WHQLFilePublisher item in signerCollection.WHQLFilePublishers)
		{
			signers.Add(item.SignerElement);

			// Add associated EKUs
			ekusToUse.AddRange(item.Ekus);

			// Add associated file attributes
			fileRulesNode.AddRange(item.FileAttribElements);

			// Scenario-specific logic
			if (item.SigningScenario is SSType.UserMode)
			{
				if (item.CiSignerElement is not null)
				{
					tempCiSigners.Add(item.CiSignerElement);
				}

				if (item.Auth is Authorization.Allow && item.AllowedSignerElement is not null)
				{
					tempUserModeAllowed.Add(item.AllowedSignerElement);
				}
				else if (item.Auth is Authorization.Deny && item.DeniedSignerElement is not null)
				{
					tempUserModeDenied.Add(item.DeniedSignerElement);
				}
			}
			else // KernelMode
			{
				if (item.Auth is Authorization.Allow && item.AllowedSignerElement is not null)
				{
					tempKernelModeAllowed.Add(item.AllowedSignerElement);
				}
				else if (item.Auth is Authorization.Deny && item.DeniedSignerElement is not null)
				{
					tempKernelModeDenied.Add(item.DeniedSignerElement);
				}
			}
		}

		// Process WHQLPublishers
		//  - Add SignerElement
		//  - Add EKUs
		//  - Process Auth (Allow/Deny) and CiSigners for User/Kernel modes
		foreach (WHQLPublisher item in signerCollection.WHQLPublishers)
		{
			signers.Add(item.SignerElement);

			// Add associated EKUs
			ekusToUse.AddRange(item.Ekus);

			// Scenario-specific logic
			if (item.SigningScenario is SSType.UserMode)
			{
				if (item.CiSignerElement is not null)
				{
					tempCiSigners.Add(item.CiSignerElement);
				}

				if (item.Auth is Authorization.Allow && item.AllowedSignerElement is not null)
				{
					tempUserModeAllowed.Add(item.AllowedSignerElement);
				}
				else if (item.Auth is Authorization.Deny && item.DeniedSignerElement is not null)
				{
					tempUserModeDenied.Add(item.DeniedSignerElement);
				}
			}
			else // KernelMode
			{
				if (item.Auth is Authorization.Allow && item.AllowedSignerElement is not null)
				{
					tempKernelModeAllowed.Add(item.AllowedSignerElement);
				}
				else if (item.Auth is Authorization.Deny && item.DeniedSignerElement is not null)
				{
					tempKernelModeDenied.Add(item.DeniedSignerElement);
				}
			}
		}

		// Process Generic SignerRules
		//  - Add SignerElement
		//  - Process Auth (Allow/Deny) and CiSigners for User/Kernel modes
		foreach (SignerRule item in signerCollection.SignerRules)
		{
			signers.Add(item.SignerElement);

			// Scenario-specific logic
			if (item.SigningScenario is SSType.UserMode)
			{
				if (item.CiSignerElement is not null)
				{
					tempCiSigners.Add(item.CiSignerElement);
				}

				if (item.Auth is Authorization.Allow && item.AllowedSignerElement is not null)
				{
					tempUserModeAllowed.Add(item.AllowedSignerElement);
				}
				else if (item.Auth is Authorization.Deny && item.DeniedSignerElement is not null)
				{
					tempUserModeDenied.Add(item.DeniedSignerElement);
				}
			}
			else // KernelMode
			{
				if (item.Auth is Authorization.Allow && item.AllowedSignerElement is not null)
				{
					tempKernelModeAllowed.Add(item.AllowedSignerElement);
				}
				else if (item.Auth is Authorization.Deny && item.DeniedSignerElement is not null)
				{
					tempKernelModeDenied.Add(item.DeniedSignerElement);
				}
			}
		}

		// Process SupplementalPolicySigners
		foreach (SupplementalPolicySignerRule item in signerCollection.SupplementalPolicySigners)
		{
			signers.Add(item.SignerElement);
			supplementalPolicySignersCol.Add(item.SupplementalPolicySigner);
		}

		// Process UpdatePolicySigners
		foreach (UpdatePolicySignerRule item in signerCollection.UpdatePolicySigners)
		{
			signers.Add(item.SignerElement);
			updatePolicySignersCol.Add(item.UpdatePolicySigner);
		}

		// Assign aggregated results to ref parameters
		ciSigners = tempCiSigners;
		userModeAllowedSigners = tempUserModeAllowed;
		userModeDeniedSigners = tempUserModeDenied;
		kernelModeAllowedSigners = tempKernelModeAllowed;
		kernelModeDeniedSigners = tempKernelModeDenied;

		FileAttribDeDuplication.EnsureUniqueFileAttributes(
			ref fileRulesNode,
			signers,
			userModeAllowedSigners,
			userModeDeniedSigners,
			kernelModeAllowedSigners,
			kernelModeDeniedSigners
			);


		#region AppID Tags

		List<AppIDTag> userModeAppIDTagsCol = [];
		List<AppIDTag> kernelModeAppIDTagsCol = [];

		bool enforceDllUserMode = false;
		bool enforceDllKernelMode = false;

		HashSet<string> currentTagKeysUserMode = new(StringComparer.Ordinal);

		HashSet<string> currentTagKeysKernelMode = new(StringComparer.Ordinal);

		// Collect AppIDTags from all policies for each signing scenario
		foreach (SiPolicy policy in CollectionsMarshal.AsSpan(allPolicies))
		{
			foreach (SigningScenario sc in CollectionsMarshal.AsSpan(policy.SigningScenarios))
			{
				// User-Mode Signing Scenario
				if (string.Equals(sc.Value.ToString(), "12", StringComparison.OrdinalIgnoreCase))
				{
					// Only flip it from false to true
					if (!enforceDllUserMode)
					{
						enforceDllUserMode = sc.AppIDTags?.EnforceDLL == true;
					}

					foreach (AppIDTag appIDTag in CollectionsMarshal.AsSpan(sc.AppIDTags?.AppIDTag))
					{
						// Ensure only Unique keys for User-mode will be in the policy.
						if (currentTagKeysUserMode.Add(appIDTag.Key))
						{
							userModeAppIDTagsCol.Add(appIDTag);
						}
					}
				}

				// kernel-Mode Signing Scenario
				if (string.Equals(sc.Value.ToString(), "131", StringComparison.OrdinalIgnoreCase))
				{
					// Only flip it from false to true
					if (!enforceDllKernelMode)
					{
						enforceDllKernelMode = sc.AppIDTags?.EnforceDLL == true;
					}

					foreach (AppIDTag appIDTag in CollectionsMarshal.AsSpan(sc.AppIDTags?.AppIDTag))
					{
						// Ensure only Unique keys pairs for Kernel-mode will be in the policy.
						if (currentTagKeysKernelMode.Add(appIDTag.Key))
						{
							kernelModeAppIDTagsCol.Add(appIDTag);
						}
					}
				}
			}
		}


		if (userModeAppIDTagsCol.Count > 0)
		{
			// Assign the results to the Ref vars
			userModeAppIDTags = new()
			{
				EnforceDLL = enforceDllUserMode,
				AppIDTag = userModeAppIDTagsCol
			};
		}

		if (kernelModeAppIDTagsCol.Count > 0)
		{
			// Assign the results to the Ref vars
			kernelModeAppIDTags = new()
			{
				EnforceDLL = enforceDllKernelMode,
				AppIDTag = kernelModeAppIDTagsCol
			};
		}

		#endregion

	}

	/// <summary>
	/// Creates an App Control policy from the deserialized data
	/// </summary>
	/// <param name="mainPolicy">The deserialized SiPolicy object of the main policy</param>
	/// <param name="ekusToUse">EKUs collection of data used to generate the policy</param>
	/// <param name="fileRulesNode"></param>
	/// <param name="signers"></param>
	/// <param name="ciSigners"></param>
	/// <param name="userModeAllowedSigners"></param>
	/// <param name="userModeDeniedSigners"></param>
	/// <param name="kernelModeAllowedSigners"></param>
	/// <param name="kernelModeDeniedSigners"></param>
	/// <param name="supplementalPolicySignersCol"></param>
	/// <param name="updatePolicySignersCol"></param>
	/// <param name="kernelModeFileRulesRefs"></param>
	/// <param name="userModeFileRulesRefs"></param>
	internal static SiPolicy PolicyGenerator(
		SiPolicy mainPolicy,
		List<EKU> ekusToUse,
		List<object> fileRulesNode,
		List<Signer> signers,
		IEnumerable<CiSigner> ciSigners,
		IEnumerable<AllowedSigner> userModeAllowedSigners,
		IEnumerable<DeniedSigner> userModeDeniedSigners,
		IEnumerable<AllowedSigner> kernelModeAllowedSigners,
		IEnumerable<DeniedSigner> kernelModeDeniedSigners,
		List<SupplementalPolicySigner> supplementalPolicySignersCol,
		List<UpdatePolicySigner> updatePolicySignersCol,
		List<FileRuleRef> kernelModeFileRulesRefs,
		List<FileRuleRef> userModeFileRulesRefs,
		List<Setting>? policySettings,
		AppIDTags? userModeAppIDTags,
		AppIDTags? kernelModeAppIDTags
		)
	{
		// Get any possible SigningScenario from XML1 (main)
		// Will use some of its rare details when building the new policy
		SigningScenario? mainPolicyUserModeSigningScenario = mainPolicy.SigningScenarios?
		  .FirstOrDefault(s => s.Value == 12);

		SigningScenario? mainPolicyKernelModeSigningScenario = mainPolicy.SigningScenarios?
			.FirstOrDefault(s => s.Value == 131);

		// Construct the User Mode Signing Scenario
		SigningScenario UMCISigningScenario = new(
			value: 12,
			id: "ID_SIGNINGSCENARIO_WINDOWS",
			productSigners: new ProductSigners
			{
				AllowedSigners = new AllowedSigners
				(
					allowedSigner: [.. userModeAllowedSigners]
				),
				DeniedSigners = new DeniedSigners
				(
					deniedSigner: [.. userModeDeniedSigners]
				),
				FileRulesRef = new FileRulesRef
				(
					fileRuleRef: userModeFileRulesRefs
				)
			}
			)
		{
			FriendlyName = "User Mode Code Integrity",
			// Add miscellaneous settings to the User Mode Signing Scenario from the Main policy
			MinimumHashAlgorithm = mainPolicyUserModeSigningScenario?.MinimumHashAlgorithm
		};

		if (mainPolicyUserModeSigningScenario is { InheritedScenarios: not null })
			UMCISigningScenario.InheritedScenarios = mainPolicyUserModeSigningScenario.InheritedScenarios;

		if (userModeAppIDTags is not null)
			UMCISigningScenario.AppIDTags = userModeAppIDTags;

		if (mainPolicyUserModeSigningScenario is { TestSigners: not null })
			UMCISigningScenario.TestSigners = mainPolicyUserModeSigningScenario.TestSigners;

		if (mainPolicyUserModeSigningScenario is { TestSigningSigners: not null })
			UMCISigningScenario.TestSigningSigners = mainPolicyUserModeSigningScenario.TestSigningSigners;


		// Construct the Kernel Mode Signing Scenario
		SigningScenario KMCISigningScenario = new(
			value: 131,
			id: "ID_SIGNINGSCENARIO_DRIVERS_1",
			productSigners: new ProductSigners
			{
				AllowedSigners = new AllowedSigners
				(
					allowedSigner: [.. kernelModeAllowedSigners]
				),
				DeniedSigners = new DeniedSigners
				(
					deniedSigner: [.. kernelModeDeniedSigners]
				),
				FileRulesRef = new FileRulesRef
				(
					fileRuleRef: kernelModeFileRulesRefs
				)
			}
			)
		{
			FriendlyName = "Kernel Mode Code Integrity",
			// Add miscellaneous settings to the Kernel Mode Signing Scenario from the Main policy
			MinimumHashAlgorithm = mainPolicyKernelModeSigningScenario?.MinimumHashAlgorithm
		};

		if (mainPolicyKernelModeSigningScenario is { InheritedScenarios: not null })
			KMCISigningScenario.InheritedScenarios = mainPolicyKernelModeSigningScenario.InheritedScenarios;

		if (kernelModeAppIDTags is not null)
			KMCISigningScenario.AppIDTags = kernelModeAppIDTags;

		if (mainPolicyKernelModeSigningScenario is { TestSigners: not null })
			KMCISigningScenario.TestSigners = mainPolicyKernelModeSigningScenario.TestSigners;

		if (mainPolicyKernelModeSigningScenario is { TestSigningSigners: not null })
			KMCISigningScenario.TestSigningSigners = mainPolicyKernelModeSigningScenario.TestSigningSigners;


		// Create the final policy data, it will replace the content in the main policy
		SiPolicy output = new(
			versionEx: mainPolicy.VersionEx, // Main policy takes priority
			platformID: mainPolicy.PlatformID, // Main policy takes priority
			policyID: mainPolicy.PolicyID, // Main policy takes priority
			basePolicyID: mainPolicy.BasePolicyID, // Main policy takes priority
			rules: mainPolicy.Rules, // Main policy takes priority
			policyType: mainPolicy.PolicyType // Main policy takes priority
		)
		{
			PolicyTypeID = mainPolicy.PolicyTypeID, // Main policy takes priority
			EKUs = ekusToUse, // Aggregated data
			FileRules = fileRulesNode, // Aggregated data
			Signers = signers, // Aggregated data
			SigningScenarios = [UMCISigningScenario, KMCISigningScenario], // Aggregated data
			UpdatePolicySigners = updatePolicySignersCol, // Aggregated data
			CiSigners = [.. ciSigners], // Aggregated data
			HvciOptions = mainPolicy.HvciOptions, // Main policy takes priority
			Settings = policySettings, // Depends
			Macros = mainPolicy.Macros, // Main policy takes priority
			SupplementalPolicySigners = supplementalPolicySignersCol, // Aggregated data
			AppSettings = mainPolicy.AppSettings, // Main policy takes priority
			FriendlyName = mainPolicy.FriendlyName // Main policy takes priority
		};

		// Make sure no Kernel-mode stuff exists if the type is AppIDTagging
		if (output.PolicyType is PolicyType.AppIDTaggingPolicy)
		{
			output = RemoveSigningScenarios.RemoveKernelMode(output);
		}

		// The reason this method is being used to go over the policy object one more time and its logic wasn't implemented during policy creation
		// is because this operation needs the complete view of the policy, whereas the policy creation operation micro-manages things
		// And puts each element in their own box, so they don't have access to the complete view of the policy.
		// Another reason is because multiple different elements refer to the same EKU, which again can't be put in those specific element "boxes" since they don't have information about other "boxes".
		output = EnsureUniqueEKUs(output);

		return output;
	}

	/// <summary>
	/// Helper method to de-duplicate EKUs directly on the SiPolicy object.
	/// Identifies duplicate EKUs based on their Value, keeps one master,
	/// updates all Signer references to point to the master, and removes duplicates.
	/// </summary>
	/// <param name="policy">The SiPolicy object to process.</param>
	/// <returns>The modified SiPolicy object.</returns>
	private static SiPolicy EnsureUniqueEKUs(SiPolicy policy)
	{
		// If there are no EKUs or Signers, there is nothing to deduplicate or update.
		if (policy.EKUs is null || policy.EKUs.Count == 0)
		{
			return policy;
		}

		// 1. Group EKUs by their Value to find duplicates.
		Dictionary<string, string> ekuIdRemap = new(StringComparer.OrdinalIgnoreCase);

		// List to hold the unique EKUs that will remain in the policy.
		List<EKU> uniqueEKUs = [];

		// We use a dictionary to track unique values encountered so far: HexString -> Master EKU ID
		// Converting to Hex String is a safe way to use byte arrays as dictionary keys.
		Dictionary<string, string> uniqueValuesMap = new(StringComparer.Ordinal);

		foreach (EKU eku in CollectionsMarshal.AsSpan(policy.EKUs))
		{
			// Convert the memory to a hex string for easy comparison/keying
			string hexValue = CustomSerialization.ConvertByteArrayToHex(eku.Value);

			if (uniqueValuesMap.TryGetValue(hexValue, out string? masterId))
			{
				// This is a duplicate.
				// Map this EKU's ID to the Master ID.
				ekuIdRemap[eku.ID] = masterId;
			}
			else
			{
				// This is a new unique EKU.
				// Add it to the map.
				uniqueValuesMap[hexValue] = eku.ID;
				// Add to the final list.
				uniqueEKUs.Add(eku);
			}
		}

		// If no remapping is needed (no duplicates found), we can return early.
		if (ekuIdRemap.Count == 0)
		{
			return policy;
		}

		// 2. Update all Signers to use the new Master IDs.
		if (policy.Signers is not null)
		{
			foreach (Signer signer in CollectionsMarshal.AsSpan(policy.Signers))
			{
				if (signer.CertEKU is not null && signer.CertEKU.Count > 0)
				{
					// We need to iterate through the CertEKUs and update IDs if they are in the remap dictionary.
					// We might also end up with duplicate CertEKU entries within a single signer if multiple old IDs map to the same new ID,
					// so we should distinct them as well.

					// Create a set to track IDs for this signer to avoid duplicates within the signer itself
					HashSet<string> signerCertIds = [];
					List<CertEKU> newCertEkuList = [];

					foreach (CertEKU certEku in CollectionsMarshal.AsSpan(signer.CertEKU))
					{
						// Determine the effective ID (either remap it or keep original)
						string effectiveId = ekuIdRemap.TryGetValue(certEku.ID, out string? newId) ? newId : certEku.ID;

						// Only add if we haven't added this ID to this signer yet
						if (signerCertIds.Add(effectiveId))
						{
							newCertEkuList.Add(new CertEKU(effectiveId));
						}
					}

					// Update the signer's list
					signer.CertEKU = newCertEkuList;
				}
			}
		}

		// 3. Replace the policy's EKU list with the unique list.
		policy.EKUs = uniqueEKUs;

		return policy;
	}

	/// <summary>
	/// 2 Signers are equal if their following properties are equal:
	/// Name
	/// CertRoot
	/// CertPublisher
	/// CertOemID
	/// CertIssuer
	/// </summary>
	/// <param name="signerX"></param>
	/// <param name="signerY"></param>
	/// <returns></returns>
	internal static bool IsSignerRuleMatch(Signer signerX, Signer signerY)
	{
		return string.Equals(signerX.Name, signerY.Name, StringComparison.OrdinalIgnoreCase) &&
			   signerX.CertRoot.Value.Span.SequenceEqual(signerY.CertRoot.Value.Span) &&
			   string.Equals(signerX.CertPublisher?.Value, signerY.CertPublisher?.Value, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(signerX.CertOemID?.Value, signerY.CertOemID?.Value, StringComparison.OrdinalIgnoreCase) &&
			   string.Equals(signerX.CertIssuer?.Value, signerY.CertIssuer?.Value, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Rule 3: Compare EKU lists based on Value only (ignore IDs)
	/// </summary>
	/// <param name="ekusX">EKU list for first signer</param>
	/// <param name="ekusY">EKU list for second signer</param>
	/// <returns>True if EKU values match</returns>
	internal static bool DoEKUsMatch(List<EKU> ekusX, List<EKU> ekusY)
	{
		// Extract EKU values and ignore IDs
		HashSet<int> ekuValuesX = [.. ekusX.Where(e => !e.Value.IsEmpty).Select(e => CustomMethods.GetByteArrayHashCode(e.Value.Span))];

		HashSet<int> ekuValuesY = [.. ekusY.Where(e => !e.Value.IsEmpty).Select(e => CustomMethods.GetByteArrayHashCode(e.Value.Span))];

		// Compare sets of EKU values
		return ekuValuesX.SetEquals(ekuValuesY);
	}


	/// <summary>
	/// Compares the common properties of two rule objects.
	/// For properties that aren't applicable in a given rule type, pass null.
	/// </summary>
	/// <returns>True if the rules are considered equal according to the common logic; otherwise false.</returns>
	internal static bool CompareCommonRuleProperties(
	SSType? signingScenarioX, SSType? signingScenarioY,
	RuleTypeType? ruleTypeX, RuleTypeType? ruleTypeY, // Ony for FileRule type
	string? packageFamilyNameX, string? packageFamilyNameY,
	ReadOnlyMemory<byte> hashX, ReadOnlyMemory<byte> hashY,
	string? filePathX, string? filePathY,
	string? fileNameX, string? fileNameY,
	string? minimumFileVersionX, string? minimumFileVersionY,
	string? maximumFileVersionX, string? maximumFileVersionY,
	string? internalNameX, string? internalNameY,
	string? fileDescriptionX, string? fileDescriptionY,
	string? productNameX, string? productNameY)
	{
		// If signing scenarios are provided, they must match.
		if (signingScenarioX is not null || signingScenarioY is not null)
		{
			if (signingScenarioX != signingScenarioY)
			{
				return false;
			}
		}

		// If rule types are provided, they must match.
		if (ruleTypeX is not null || ruleTypeY is not null)
		{
			if (ruleTypeX != ruleTypeY)
			{
				return false;
			}
		}

		// Rule 1: If both have a non-empty PackageFamilyName that is equal (ignoring case), consider them equal.
		if (!string.IsNullOrWhiteSpace(packageFamilyNameX) &&
			!string.IsNullOrWhiteSpace(packageFamilyNameY) &&
			string.Equals(packageFamilyNameX, packageFamilyNameY, StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		// Rule 2: If both have non-empty Hash values that are byte-for-byte equal, consider them equal.
		if (!hashX.Span.IsEmpty && !hashY.Span.IsEmpty && hashX.Span.SequenceEqual(hashY.Span))
		{
			return true;
		}

		// Rule 3: If both have a non-empty FilePath that is equal (ignoring case), consider them equal.
		if (!string.IsNullOrWhiteSpace(filePathX) &&
			!string.IsNullOrWhiteSpace(filePathY) &&
			string.Equals(filePathX, filePathY, StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		// Special Case: If both FileName values are "*" (ignoring case), consider them equal.
		if (string.Equals(fileNameX, "*", StringComparison.OrdinalIgnoreCase) &&
			string.Equals(fileNameY, "*", StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		// Rule 4: If both have MinimumFileVersion or both have MaximumFileVersion,
		// and one of the name-related properties (InternalName, FileDescription, ProductName, or FileName) match,
		// then consider them equal.
		bool hasMinX = !string.IsNullOrWhiteSpace(minimumFileVersionX);
		bool hasMaxX = !string.IsNullOrWhiteSpace(maximumFileVersionX);
		bool hasMinY = !string.IsNullOrWhiteSpace(minimumFileVersionY);
		bool hasMaxY = !string.IsNullOrWhiteSpace(maximumFileVersionY);

		if ((hasMinX && hasMinY) || (hasMaxX && hasMaxY))
		{
			bool nameMatch =
				BothAreWhitespaceOrEqual(internalNameX, internalNameY) ||
				BothAreWhitespaceOrEqual(fileDescriptionX, fileDescriptionY) ||
				BothAreWhitespaceOrEqual(productNameX, productNameY) ||
				BothAreWhitespaceOrEqual(fileNameX, fileNameY);

			if (nameMatch)
			{
				return true;
			}
		}

		// If one has a MinimumFileVersion and the other a MaximumFileVersion, they are not considered duplicates.
		if ((hasMinX && hasMaxY) || (hasMaxX && hasMinY))
		{
			return false;
		}

		// If none of the rules match, the FileRuleRule objects are not equal.
		return false;
	}


	/// <summary>
	/// Helper method to check if two strings are both whitespace or exactly equal
	/// ✅ " " and " " -> Equal
	/// ✅ "text" and "text" -> Equal
	/// ❌ "text" and " text " -> Not Equal
	/// ❌ null and " " -> Not Equal
	/// ❌ null and null -> Not Equal
	/// </summary>
	/// <param name="a"></param>
	/// <param name="b"></param>
	/// <returns></returns>
	private static bool BothAreWhitespaceOrEqual(string? a, string? b)
	{
		bool isAEmpty = a is not null && string.IsNullOrWhiteSpace(a);
		bool isBEmpty = b is not null && string.IsNullOrWhiteSpace(b);

		if (isAEmpty && isBEmpty)
		{
			return true; // Both are only whitespace, consider equal
		}

		if (a is not null && b is not null && string.Equals(a, b, StringComparison.OrdinalIgnoreCase))
		{
			return true; // Both are exactly equal (ignoring case)
		}

		return false; // Otherwise, they are not equal
	}


	internal const long modulus = 0x7FFFFFFF; // A prime modulus to prevent overflow and ensure a non-negative int.
}
