using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;
using AppControlManager.Others;
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
/// Each <Allow> node in <FileRules> nodes is associated only with one Signing scenario at a time. Same goes for <Deny> nodes.
///
/// In the <EKUs> node there must be unique EKUs only based on their value. If 2 Signers need to reference the same EKU value, they must use same EKU's ID in their CertEKU section.
///
///
/// </summary>
internal static partial class Merger
{

	/// <summary>
	/// This is the Main method that is responsible for merging 2 XML files.
	/// The result will be saved in the first XL file and there will be no duplicate data.
	/// The first XML file's data that are non-arrays will be maintained.
	/// Only the data that are arrays will be merged.
	/// No date is lost in the merge process.
	/// </summary>
	/// <param name="mainXmlFilePath"></param>
	/// <param name="subXmlFilePath"></param>
	internal static void Merge(string mainXmlFilePath, HashSet<string> otherXmlFilePaths)
	{
		// Close the empty rules in the main policy
		CloseEmptyXmlNodesSemantic.Close(mainXmlFilePath);

		// Create a list of all SiPolicy objects representing the instantiation of otherXmlFilePaths
		List<SiPolicy> allPolicies = [];

		foreach (string item in otherXmlFilePaths)
		{
			CloseEmptyXmlNodesSemantic.Close(item);

			allPolicies.Add(Management.Initialize(item));
		}

		// Instantiate the main policy
		SiPolicy mainXML = Management.Initialize(mainXmlFilePath);

		// Add the main policy to the mix
		allPolicies.Add(mainXML);


		// Data aggregation
		// ID randomization
		// De-duplication
		HashSet<AllowRule> allowRules = Factory.CollectAllowRules(allPolicies);
		HashSet<DenyRule> denyRules = Factory.CollectDenyRules(allPolicies);
		SignerCollection signerCollection = Factory.CollectSignerRules(allPolicies);

		// Get all of the EKUs from rule types that generate it
		IEnumerable<EKU> ekusToUse = signerCollection.WHQLFilePublishers.SelectMany(x => x.Ekus).Concat(signerCollection.WHQLPublishers.SelectMany(x => x.Ekus)).Where(x => x is not null);

		// Get all FileRules that go to <FileRules>
		IEnumerable<object> fileRules = allowRules.Select(x => x.AllowElement).Cast<object>().
			Concat(denyRules.Select(x => x.DenyElement)).
			Concat(signerCollection.FilePublisherSigners.SelectMany(x => x.FileAttribElements)).
			Concat(signerCollection.WHQLFilePublishers.SelectMany(x => x.FileAttribElements)).Where(x => x is not null);

		// Get all FileRuleRefs - User Mode - that go to <FileRulesRef> in ProductSigners
		IEnumerable<FileRuleRef> userModeFileRulesRefs = allowRules.Where(x => x.SigningScenario is SSType.UserMode).Select(x => x.FileRuleRefElement).
			Concat(denyRules.Where(x => x.SigningScenario is SSType.UserMode).Select(x => x.FileRuleRefElement)).Where(x => x is not null);

		// Get all FileRuleRefs - Kernel Mode - that go to <FileRulesRef> in ProductSigners
		IEnumerable<FileRuleRef> kernelModeFileRulesRefs = allowRules.Where(x => x.SigningScenario is SSType.KernelMode).Select(x => x.FileRuleRefElement).
			Concat(denyRules.Where(x => x.SigningScenario is SSType.KernelMode).Select(x => x.FileRuleRefElement)).Where(x => x is not null);

		// Get all Signers
		IEnumerable<Signer> signers = signerCollection.FilePublisherSigners.Select(x => x.SignerElement).
			Concat(signerCollection.WHQLFilePublishers.Select(x => x.SignerElement)).
			Concat(signerCollection.WHQLPublishers.Select(x => x.SignerElement)).
			Concat(signerCollection.SignerRules.Select(x => x.SignerElement)).
			Concat(signerCollection.SupplementalPolicySigners.Select(x => x.SignerElement)).
			Concat(signerCollection.UpdatePolicySigners.Select(x => x.SignerElement)).Where(x => x is not null);

		// Get all CiSigners
		IEnumerable<CiSigner> ciSigners = signerCollection.WHQLPublishers.Where(x => x.SigningScenario is SSType.UserMode).Select(x => x.CiSignerElement).
			Concat(signerCollection.WHQLFilePublishers.Where(x => x.SigningScenario is SSType.UserMode).Select(x => x.CiSignerElement).
			Concat(signerCollection.SignerRules.Where(x => x.SigningScenario is SSType.UserMode).Select(x => x.CiSignerElement))).
			Concat(signerCollection.FilePublisherSigners.Where(x => x.SigningScenario is SSType.UserMode).Select(x => x.CiSignerElement)).Where(x => x is not null)!;


		// Get any possible SigningScenario from XML1 (main)
		// Will use some of its rare details when building the new policy
		SigningScenario? mainXMLUserModeSigningScenario = mainXML.SigningScenarios
		   .FirstOrDefault(s => s.Value == 12);

		SigningScenario? mainXMLKernelModeSigningScenario = mainXML.SigningScenarios
			.FirstOrDefault(s => s.Value == 131);


		// Get all of the AllowedSigners - User Mode
		IEnumerable<AllowedSigner> userModeAllowedSigners = signerCollection.WHQLPublishers.Where(x => x.SigningScenario is SSType.UserMode && x.Auth is Authorization.Allow).Select(x => x.AllowedSignerElement).
			Concat(signerCollection.WHQLFilePublishers.Where(x => x.SigningScenario is SSType.UserMode && x.Auth is Authorization.Allow).Select(x => x.AllowedSignerElement)).
			Concat(signerCollection.SignerRules.Where(x => x.SigningScenario is SSType.UserMode && x.Auth is Authorization.Allow).Select(x => x.AllowedSignerElement)).
			Concat(signerCollection.FilePublisherSigners.Where(x => x.SigningScenario is SSType.UserMode && x.Auth is Authorization.Allow).Select(x => x.AllowedSignerElement)).Where(x => x is not null)!;

		// Get all of the DeniedSigners - User Mode
		IEnumerable<DeniedSigner> userModeDeniedSigners = signerCollection.WHQLPublishers.Where(x => x.SigningScenario is SSType.UserMode && x.Auth is Authorization.Deny).Select(x => x.DeniedSignerElement).
			Concat(signerCollection.WHQLFilePublishers.Where(x => x.SigningScenario is SSType.UserMode && x.Auth is Authorization.Deny).Select(x => x.DeniedSignerElement)).
			Concat(signerCollection.SignerRules.Where(x => x.SigningScenario is SSType.UserMode && x.Auth is Authorization.Deny).Select(x => x.DeniedSignerElement)).
			Concat(signerCollection.FilePublisherSigners.Where(x => x.SigningScenario is SSType.UserMode && x.Auth is Authorization.Deny).Select(x => x.DeniedSignerElement)).Where(x => x is not null)!;

		// Get all of the AllowedSigners - Kernel Mode
		IEnumerable<AllowedSigner> kernelModeAllowedSigners = signerCollection.WHQLPublishers.Where(x => x.SigningScenario is SSType.KernelMode && x.Auth is Authorization.Allow).Select(x => x.AllowedSignerElement).
		  Concat(signerCollection.WHQLFilePublishers.Where(x => x.SigningScenario is SSType.KernelMode && x.Auth is Authorization.Allow).Select(x => x.AllowedSignerElement)).
		  Concat(signerCollection.SignerRules.Where(x => x.SigningScenario is SSType.KernelMode && x.Auth is Authorization.Allow).Select(x => x.AllowedSignerElement)).
		  Concat(signerCollection.FilePublisherSigners.Where(x => x.SigningScenario is SSType.KernelMode && x.Auth is Authorization.Allow).Select(x => x.AllowedSignerElement)).Where(x => x is not null)!;

		// Get all of the DeniedSigners - Kernel Mode
		IEnumerable<DeniedSigner> kernelModeDeniedSigners = signerCollection.WHQLPublishers.Where(x => x.SigningScenario is SSType.KernelMode && x.Auth is Authorization.Deny).Select(x => x.DeniedSignerElement).
			Concat(signerCollection.WHQLFilePublishers.Where(x => x.SigningScenario is SSType.KernelMode && x.Auth is Authorization.Deny).Select(x => x.DeniedSignerElement)).
			Concat(signerCollection.SignerRules.Where(x => x.SigningScenario is SSType.KernelMode && x.Auth is Authorization.Deny).Select(x => x.DeniedSignerElement)).
			Concat(signerCollection.FilePublisherSigners.Where(x => x.SigningScenario is SSType.KernelMode && x.Auth is Authorization.Deny).Select(x => x.DeniedSignerElement)).Where(x => x is not null)!;


		IEnumerable<SupplementalPolicySigner> supplementalPolicySignersCol = signerCollection.SupplementalPolicySigners.Where(x => x is not null).Select(x => x.SupplementalPolicySigner).Where(x => x is not null);

		IEnumerable<UpdatePolicySigner> updatePolicySignersCol = signerCollection.UpdatePolicySigners.Where(x => x is not null).Select(x => x.UpdatePolicySigner).Where(x => x is not null);


		// Construct the User Mode Signing Scenario
		SigningScenario UMCISigningScenario = new()
		{
			Value = 12,
			ID = "ID_SIGNINGSCENARIO_WINDOWS",
			FriendlyName = "User Mode Code Integrity",

			ProductSigners = new ProductSigners
			{
				AllowedSigners = new AllowedSigners
				{
					AllowedSigner = [.. userModeAllowedSigners]
				},
				DeniedSigners = new DeniedSigners
				{
					DeniedSigner = [.. userModeDeniedSigners]
				},
				FileRulesRef = new FileRulesRef
				{
					FileRuleRef = [.. userModeFileRulesRefs]
				}
			}
		};

		// Add miscellaneous settings to the User Mode Signing Scenario from the Main XML
		if (mainXMLUserModeSigningScenario is { MinimumHashAlgorithmSpecified: true })
		{
			UMCISigningScenario.MinimumHashAlgorithmSpecified = true;
			UMCISigningScenario.MinimumHashAlgorithm = mainXMLUserModeSigningScenario.MinimumHashAlgorithm;
		}


		if (mainXMLUserModeSigningScenario is { InheritedScenarios: not null })
			UMCISigningScenario.InheritedScenarios = mainXMLUserModeSigningScenario.InheritedScenarios;

		if (mainXMLUserModeSigningScenario is { AppIDTags: not null })
			UMCISigningScenario.AppIDTags = mainXMLUserModeSigningScenario.AppIDTags;

		if (mainXMLUserModeSigningScenario is { TestSigners: not null })
			UMCISigningScenario.TestSigners = mainXMLUserModeSigningScenario.TestSigners;

		if (mainXMLUserModeSigningScenario is { TestSigningSigners: not null })
			UMCISigningScenario.TestSigningSigners = mainXMLUserModeSigningScenario.TestSigningSigners;


		// Construct the Kernel Mode Signing Scenario
		SigningScenario KMCISigningScenario = new()
		{
			Value = 131,
			ID = "ID_SIGNINGSCENARIO_DRIVERS_1",
			FriendlyName = "Kernel Mode Code Integrity",

			ProductSigners = new ProductSigners
			{
				AllowedSigners = new AllowedSigners
				{
					AllowedSigner = [.. kernelModeAllowedSigners]
				},
				DeniedSigners = new DeniedSigners
				{
					DeniedSigner = [.. kernelModeDeniedSigners]
				},
				FileRulesRef = new FileRulesRef
				{
					FileRuleRef = [.. kernelModeFileRulesRefs]
				}
			}
		};


		// Add miscellaneous settings to the Kernel Mode Signing Scenario from the Main XML
		if (mainXMLKernelModeSigningScenario is { MinimumHashAlgorithmSpecified: true })
		{
			KMCISigningScenario.MinimumHashAlgorithmSpecified = true;
			KMCISigningScenario.MinimumHashAlgorithm = mainXMLKernelModeSigningScenario.MinimumHashAlgorithm;
		}

		if (mainXMLKernelModeSigningScenario is { InheritedScenarios: not null })
			KMCISigningScenario.InheritedScenarios = mainXMLKernelModeSigningScenario.InheritedScenarios;

		if (mainXMLKernelModeSigningScenario is { AppIDTags: not null })
			KMCISigningScenario.AppIDTags = mainXMLKernelModeSigningScenario.AppIDTags;

		if (mainXMLKernelModeSigningScenario is { TestSigners: not null })
			KMCISigningScenario.TestSigners = mainXMLKernelModeSigningScenario.TestSigners;

		if (mainXMLKernelModeSigningScenario is { TestSigningSigners: not null })
			KMCISigningScenario.TestSigningSigners = mainXMLKernelModeSigningScenario.TestSigningSigners;


		// Create the final policy data, it will replace the content in the main XML file
		SiPolicy output = new()
		{
			VersionEx = mainXML.VersionEx, // Main policy takes priority
			PolicyTypeID = mainXML.PolicyTypeID, // Main policy takes priority
			PlatformID = mainXML.PlatformID, // Main policy takes priority
			PolicyID = mainXML.PolicyID, // Main policy takes priority
			BasePolicyID = mainXML.BasePolicyID, // Main policy takes priority
			Rules = mainXML.Rules, // Main policy takes priority
			EKUs = [.. ekusToUse], // Aggregated data
			FileRules = [.. fileRules], // Aggregated data
			Signers = [.. signers], // Aggregated data
			SigningScenarios = [UMCISigningScenario, KMCISigningScenario], // Aggregated data
			UpdatePolicySigners = [.. updatePolicySignersCol], // Aggregated data
			CiSigners = [.. ciSigners], // Aggregated data
			HvciOptions = 2, // Set to the secure state
			HvciOptionsSpecified = true, // Set to the secure state
			Settings = mainXML.Settings, // Main policy takes priority
			Macros = mainXML.Macros, // Main policy takes priority
			SupplementalPolicySigners = [.. supplementalPolicySignersCol], // Aggregated data
			AppSettings = mainXML.AppSettings, // Main policy takes priority
			FriendlyName = mainXML.FriendlyName, // Main policy takes priority
			PolicyType = mainXML.PolicyType, // Main policy takes priority
			PolicyTypeSpecified = mainXML.PolicyTypeSpecified // Main policy takes priority
		};


		// Save the changes to the main XML File
		Management.SavePolicyToFile(output, mainXmlFilePath);

		// Close any empty nodes
		CloseEmptyXmlNodesSemantic.Close(mainXmlFilePath);


		// The reason this method is being used to go over the XML one more time and its logic wasn't implemented during policy creation
		// is because this operation needs the complete view of the policy, whereas the policy creation operation micro-manages things
		// And puts each element in their own box, so they don't have access to the complete view of the policy.
		// Another reason is because multiple different elements refer to the same EKU, which again can't be put in those specific element "boxes" since they don't have information about other "boxes".
		EnsureUniqueEKUs(mainXmlFilePath);


		// Not necessary for the current implementation
		//
		// When 2 FilePublisher or WHQLFilePublisher level signers reference the same FileAttrib
		// And they are in different Signing Scenarios, the FileAttrib must remain.
		// However, if they belong to the same SigningScenario, both signers "can" reference the same FileAttrib.
		// De-duplication is not necessary here but if it is to be done, each signer must have its context.
		// Context: Whether signer is allowing or denying, or if it's kernel-mode or user-mode.
		//
		// AppControlManager.SiPolicyIntel.SiPolicyProcessor.ProcessSiPolicyXml(mainXmlFilePath);
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

			// Update Signer CertEKU references to point to the retained EKU
			foreach (XElement ekuToRemove in ekusToRemove)
			{
				string ekuToRemoveId = (string)ekuToRemove.Attribute("ID")!;
				string ekuToKeepId = (string)ekuToKeep.Attribute("ID")!;

				IEnumerable<XElement> certEKURefs = doc.Descendants(ns + "CertEKU")
					.Where(e => (string)e.Attribute("ID")! == ekuToRemoveId);

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

}
