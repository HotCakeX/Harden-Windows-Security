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
using System.Threading.Tasks;
using System.Xml.Linq;
using AppControlManager.SiPolicyIntel;
using AppControlManager.XMLOps;

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
	/// This is the Main method that is responsible for merging 2 XML files.
	/// The result will be saved in the first XL file and there will be no duplicate data.
	/// The first XML file's data that are non-arrays will be maintained.
	/// Only the data that are arrays will be merged.
	/// No date is lost in the merge process.
	/// </summary>
	/// <param name="mainXmlFilePath"></param>
	/// <param name="otherXmlFilePaths"></param>
	internal static void Merge(string mainXmlFilePath, List<string> otherXmlFilePaths)
	{
		// Create a list of all SiPolicy objects representing the instantiation of otherXmlFilePaths
		List<SiPolicy> allPolicies = [];

		foreach (string item in otherXmlFilePaths)
		{
			allPolicies.Add(Management.Initialize(item, null));
		}

		// Instantiate the main policy
		SiPolicy mainXML = Management.Initialize(mainXmlFilePath, null);

		// Add the main policy to the mix
		allPolicies.Add(mainXML);

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


		// Deserialize, de-duplicate, merge
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
		   ref userModeFileRulesRefs
		   );


		// Generate the policy
		PolicyGenerator(
		   mainXmlFilePath,
		   mainXML,
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
		   mainXML.Settings); // Pass the main policy's Settings for the merge unless there is a need to merge the Settings during a merge operation.
	}


	/// <summary>
	/// Accepts mainXML and allPolicies, and accepts many other collections, fills them with data.
	/// It can be used for a single SiPolicy as well, just supply the same object for both parameters.
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
		ref List<FileRuleRef> userModeFileRulesRefs
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
	}

	/// <summary>
	/// Creates an App Control policy from the deserialized data
	/// </summary>
	/// <param name="mainXmlFilePath">The file path where the generated policy will be saved</param>
	/// <param name="mainXML">The deserialized SiPolicy object of the main policy</param>
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
	internal static void PolicyGenerator(
		string? mainXmlFilePath,
		SiPolicy? mainXML,
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
		List<Setting>? policySettings
		)
	{

		ArgumentNullException.ThrowIfNull(mainXmlFilePath, nameof(mainXmlFilePath));
		ArgumentNullException.ThrowIfNull(mainXML, nameof(mainXML));

		// Get any possible SigningScenario from XML1 (main)
		// Will use some of its rare details when building the new policy
		SigningScenario? mainXMLUserModeSigningScenario = mainXML.SigningScenarios?
		  .FirstOrDefault(s => s.Value == 12);

		SigningScenario? mainXMLKernelModeSigningScenario = mainXML.SigningScenarios?
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
			// Add miscellaneous settings to the User Mode Signing Scenario from the Main XML
			MinimumHashAlgorithm = mainXMLUserModeSigningScenario?.MinimumHashAlgorithm
		};

		if (mainXMLUserModeSigningScenario is { InheritedScenarios: not null })
			UMCISigningScenario.InheritedScenarios = mainXMLUserModeSigningScenario.InheritedScenarios;

		if (mainXMLUserModeSigningScenario is { AppIDTags: not null })
			UMCISigningScenario.AppIDTags = mainXMLUserModeSigningScenario.AppIDTags;

		if (mainXMLUserModeSigningScenario is { TestSigners: not null })
			UMCISigningScenario.TestSigners = mainXMLUserModeSigningScenario.TestSigners;

		if (mainXMLUserModeSigningScenario is { TestSigningSigners: not null })
			UMCISigningScenario.TestSigningSigners = mainXMLUserModeSigningScenario.TestSigningSigners;


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
			// Add miscellaneous settings to the Kernel Mode Signing Scenario from the Main XML
			MinimumHashAlgorithm = mainXMLKernelModeSigningScenario?.MinimumHashAlgorithm
		};

		if (mainXMLKernelModeSigningScenario is { InheritedScenarios: not null })
			KMCISigningScenario.InheritedScenarios = mainXMLKernelModeSigningScenario.InheritedScenarios;

		if (mainXMLKernelModeSigningScenario is { AppIDTags: not null })
			KMCISigningScenario.AppIDTags = mainXMLKernelModeSigningScenario.AppIDTags;

		if (mainXMLKernelModeSigningScenario is { TestSigners: not null })
			KMCISigningScenario.TestSigners = mainXMLKernelModeSigningScenario.TestSigners;

		if (mainXMLKernelModeSigningScenario is { TestSigningSigners: not null })
			KMCISigningScenario.TestSigningSigners = mainXMLKernelModeSigningScenario.TestSigningSigners;


		// Create the final policy data, it will replace the content in the main XML file
		SiPolicy output = new(
			versionEx: mainXML.VersionEx, // Main policy takes priority
			platformID: mainXML.PlatformID, // Main policy takes priority
			policyID: mainXML.PolicyID, // Main policy takes priority
			basePolicyID: mainXML.BasePolicyID, // Main policy takes priority
			rules: mainXML.Rules, // Main policy takes priority
			policyType: mainXML.PolicyType // Main policy takes priority
		)
		{
			PolicyTypeID = mainXML.PolicyTypeID, // Main policy takes priority
			EKUs = ekusToUse, // Aggregated data
			FileRules = fileRulesNode, // Aggregated data
			Signers = signers, // Aggregated data
			SigningScenarios = [UMCISigningScenario, KMCISigningScenario], // Aggregated data
			UpdatePolicySigners = updatePolicySignersCol, // Aggregated data
			CiSigners = [.. ciSigners], // Aggregated data
			HvciOptions = mainXML.HvciOptions, // Main policy takes priority
			Settings = policySettings, // Depends
			Macros = mainXML.Macros, // Main policy takes priority
			SupplementalPolicySigners = supplementalPolicySignersCol, // Aggregated data
			AppSettings = mainXML.AppSettings, // Main policy takes priority
			FriendlyName = mainXML.FriendlyName // Main policy takes priority
		};

		// Save the changes to the main XML File
		Management.SavePolicyToFile(output, mainXmlFilePath);

		// The reason this method is being used to go over the XML one more time and its logic wasn't implemented during policy creation
		// is because this operation needs the complete view of the policy, whereas the policy creation operation micro-manages things
		// And puts each element in their own box, so they don't have access to the complete view of the policy.
		// Another reason is because multiple different elements refer to the same EKU, which again can't be put in those specific element "boxes" since they don't have information about other "boxes".
		EnsureUniqueEKUs(mainXmlFilePath);
	}


	/// <summary>
	/// Helper method to de-duplicate EKUs
	/// </summary>
	/// <param name="xmlFilePath"></param>
	private static void EnsureUniqueEKUs(string xmlFilePath)
	{
		// Load the XML document
		XDocument doc = XDocument.Load(xmlFilePath);
		XNamespace ns = GlobalVars.SiPolicyNamespace;

		// Get all EKU elements
		List<XElement> ekuElements = [.. doc.Descendants(ns + "EKU")];

		// Group EKUs by their Value attribute to identify duplicates
		List<IGrouping<string, XElement>> duplicateGroups = [.. ekuElements
			.GroupBy(e => (string)e.Attribute("Value")!)
			.Where(g => g.Count() > 1)];

		foreach (IGrouping<string, XElement> group in duplicateGroups)
		{
			// Keep the first EKU as the "master" and remove the others
			XElement ekuToKeep = group.First();
			List<XElement> ekusToRemove = [.. group.Skip(1)];

			string ekuToKeepId = (string)ekuToKeep.Attribute("ID")!;

			// Update Signer CertEKU references to point to the retained EKU
			foreach (XElement ekuToRemove in ekusToRemove)
			{
				string ekuToRemoveId = (string)ekuToRemove.Attribute("ID")!;

				IEnumerable<XElement> certEKURefs = doc.Descendants(ns + "CertEKU")
					.Where(e => string.Equals((string)e.Attribute("ID")!, ekuToRemoveId, StringComparison.OrdinalIgnoreCase));

				foreach (XElement certEKURef in certEKURefs)
				{
					certEKURef.SetAttributeValue("ID", ekuToKeepId);
				}

				// Remove the duplicate EKU from the document
				ekuToRemove.Remove();
			}
		}

		// Save the updated XML document
		doc.Save(xmlFilePath);
	}


	/// <summary>
	/// Rule 1: Name, CertRoot.Value, CertPublisher.Value must match
	/// </summary>
	/// <param name="signerX"></param>
	/// <param name="signerY"></param>
	/// <returns></returns>
	internal static bool IsSignerRule1Match(Signer signerX, Signer signerY)
	{
		return !string.IsNullOrWhiteSpace(signerX.Name) &&
			   !string.IsNullOrWhiteSpace(signerY.Name) &&
			   string.Equals(signerX.Name, signerY.Name, StringComparison.OrdinalIgnoreCase) &&
			   signerX.CertRoot is not null && signerY.CertRoot is not null && signerX.CertRoot.Value.Span.SequenceEqual(signerY.CertRoot.Value.Span) &&
			   string.Equals(signerX.CertPublisher?.Value, signerY.CertPublisher?.Value, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Rule 2: Name and CertRoot.Value must match
	/// </summary>
	/// <param name="signerX"></param>
	/// <param name="signerY"></param>
	/// <returns></returns>
	internal static bool IsSignerRule2Match(Signer signerX, Signer signerY)
	{
		return !string.IsNullOrWhiteSpace(signerX.Name) &&
			   !string.IsNullOrWhiteSpace(signerY.Name) &&
			   string.Equals(signerX.Name, signerY.Name, StringComparison.OrdinalIgnoreCase) &&
			   signerX.CertRoot is not null && signerY.CertRoot is not null && signerX.CertRoot.Value.Span.SequenceEqual(signerY.CertRoot.Value.Span);
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
	/// <param name="signingScenarioX"></param>
	/// <param name="signingScenarioY"></param>
	/// <param name="ruleTypeX"></param>
	/// <param name="ruleTypeY"></param>
	/// <param name="packageFamilyNameX"></param>
	/// <param name="packageFamilyNameY"></param>
	/// <param name="hashX"></param>
	/// <param name="hashY"></param>
	/// <param name="filePathX"></param>
	/// <param name="filePathY"></param>
	/// <param name="fileNameX"></param>
	/// <param name="fileNameY"></param>
	/// <param name="minimumFileVersionX"></param>
	/// <param name="minimumFileVersionY"></param>
	/// <param name="maximumFileVersionX"></param>
	/// <param name="maximumFileVersionY"></param>
	/// <param name="internalNameX"></param>
	/// <param name="internalNameY"></param>
	/// <param name="fileDescriptionX"></param>
	/// <param name="fileDescriptionY"></param>
	/// <param name="productNameX"></param>
	/// <param name="productNameY"></param>
	/// <returns>True if the rules are considered equal according to the common logic; otherwise false.</returns>
	internal static bool CompareCommonRuleProperties(
	SSType? signingScenarioX, SSType? signingScenarioY,
	RuleTypeType? ruleTypeX, RuleTypeType? ruleTypeY, // Ony for FileRule type
	string? packageFamilyNameX, string? packageFamilyNameY,
	ReadOnlyMemory<byte>? hashX, ReadOnlyMemory<byte>? hashY,
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

		// Rule 2: If both have non-null Hash values that are byte-for-byte equal, consider them equal.
		if (hashX is not null && hashY is not null && hashX.Value.Span.SequenceEqual(hashY.Value.Span))
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
