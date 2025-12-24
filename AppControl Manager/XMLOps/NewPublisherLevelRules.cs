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
using AppControlManager.Others;
using AppControlManager.SiPolicy;

namespace AppControlManager.XMLOps;

internal static class NewPublisherLevelRules
{
	/// <summary>
	/// Creates new Allow Publisher level rules in the SiPolicy object
	/// Each rules includes the Signers, AllowedSigners, and CiSigners(depending on kernel/user mode)
	/// </summary>
	/// <param name="policyObj"></param>
	/// <param name="publisherSigners">The PublisherSigners to be used for creating the rules, they are the output of the BuildSignerAndHashObjects Method</param>
	/// <returns>SiPolicy</returns>
	internal static SiPolicy.SiPolicy CreateAllow(SiPolicy.SiPolicy policyObj, List<PublisherSignerCreator> publisherSigners)
	{
		if (publisherSigners.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoPublisherSignersDetectedAllowMessage"));
			return policyObj;
		}

		Logger.Write(string.Format(GlobalVars.GetStr("PublisherSignersToAddMessage"), publisherSigners.Count, "SiPolicy Object"));

		// Get or Initialize lists
		List<Signer> signers = policyObj.Signers ?? [];
		List<CiSigner> ciSigners = policyObj.CiSigners ?? [];

		// Ensure Scenarios exist
		SigningScenario umciScenario = EnsureScenario(policyObj, 12);
		SigningScenario kmciScenario = EnsureScenario(policyObj, 131);

		// Ensure ProductSigners exist
		umciScenario.ProductSigners ??= new ProductSigners();
		kmciScenario.ProductSigners ??= new ProductSigners();

		// Ensure AllowedSigners exist
		umciScenario.ProductSigners.AllowedSigners ??= new AllowedSigners([]);
		kmciScenario.ProductSigners.AllowedSigners ??= new AllowedSigners([]);

		List<AllowedSigner> umciAllowedSigners = umciScenario.ProductSigners.AllowedSigners.AllowedSigner ?? [];
		List<AllowedSigner> kmciAllowedSigners = kmciScenario.ProductSigners.AllowedSigners.AllowedSigner ?? [];

		foreach (PublisherSignerCreator publisherData in publisherSigners)
		{
			foreach (CertificateDetailsCreator signerData in publisherData.CertificateDetails)
			{
				string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
				string SignerID = $"ID_SIGNER_B_{guid}";

				Signer newSigner = new(
					id: SignerID,
					name: signerData.IntermediateCertName,
					certRoot: new CertRoot
					(
						type: CertEnumType.TBS,
						value: Convert.FromHexString(signerData.IntermediateCertTBS)
					))
				{
					CertPublisher = new CertPublisher(value: signerData.LeafCertName)
				};

				signers.Add(newSigner);

				// For User-Mode files
				if (publisherData.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
				{
					umciAllowedSigners.Add(new AllowedSigner(signerId: SignerID, exceptDenyRule: null));
					ciSigners.Add(new CiSigner(signerID: SignerID));
				}
				// For Kernel-Mode files
				else if (publisherData.SiSigningScenario is SiPolicyIntel.SSType.KernelMode)
				{
					kmciAllowedSigners.Add(new AllowedSigner(signerId: SignerID, exceptDenyRule: null));
				}
			}
		}

		// Update Policy Object
		policyObj.Signers = signers;
		policyObj.CiSigners = ciSigners;

		umciScenario.ProductSigners.AllowedSigners.AllowedSigner = umciAllowedSigners;
		kmciScenario.ProductSigners.AllowedSigners.AllowedSigner = kmciAllowedSigners;

		return policyObj;
	}

	/// <summary>
	/// Creates new Deny Publisher level rules in the SiPolicy object
	/// Each rules includes the Signers, DeniedSigners, and CiSigners(depending on kernel/user mode)
	/// </summary>
	/// <param name="policyObj"></param>
	/// <param name="publisherSigners">The PublisherSigners to be used for creating the rules, they are the output of the BuildSignerAndHashObjects Method</param>
	/// <returns>SiPolicy</returns>
	internal static SiPolicy.SiPolicy CreateDeny(SiPolicy.SiPolicy policyObj, List<PublisherSignerCreator> publisherSigners)
	{
		if (publisherSigners.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoPublisherSignersDetectedDenyMessage"));
			return policyObj;
		}

		Logger.Write(string.Format(GlobalVars.GetStr("PublisherSignersToAddMessage"), publisherSigners.Count, "SiPolicy Object"));

		// Get or Initialize lists
		List<Signer> signers = policyObj.Signers ?? [];
		List<CiSigner> ciSigners = policyObj.CiSigners ?? [];

		// Ensure Scenarios exist
		SigningScenario umciScenario = EnsureScenario(policyObj, 12);
		SigningScenario kmciScenario = EnsureScenario(policyObj, 131);

		// Ensure ProductSigners exist
		umciScenario.ProductSigners ??= new ProductSigners();
		kmciScenario.ProductSigners ??= new ProductSigners();

		// Ensure DeniedSigners exist
		umciScenario.ProductSigners.DeniedSigners ??= new DeniedSigners([]);
		kmciScenario.ProductSigners.DeniedSigners ??= new DeniedSigners([]);

		List<DeniedSigner> umciDeniedSigners = umciScenario.ProductSigners.DeniedSigners.DeniedSigner ?? [];
		List<DeniedSigner> kmciDeniedSigners = kmciScenario.ProductSigners.DeniedSigners.DeniedSigner ?? [];

		foreach (PublisherSignerCreator publisherData in publisherSigners)
		{
			foreach (CertificateDetailsCreator signerData in publisherData.CertificateDetails)
			{
				string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
				string SignerID = $"ID_SIGNER_B_{guid}";

				Signer newSigner = new(
					id: SignerID,
					name: signerData.IntermediateCertName,
					certRoot: new CertRoot
					(
						type: CertEnumType.TBS,
						value: Convert.FromHexString(signerData.IntermediateCertTBS)
					))
				{
					CertPublisher = new CertPublisher(value: signerData.LeafCertName)
				};

				signers.Add(newSigner);

				// For User-Mode files
				if (publisherData.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
				{
					umciDeniedSigners.Add(new DeniedSigner(signerId: SignerID, exceptAllowRule: null));
					ciSigners.Add(new CiSigner(signerID: SignerID));
				}
				// For Kernel-Mode files
				else if (publisherData.SiSigningScenario is SiPolicyIntel.SSType.KernelMode)
				{
					kmciDeniedSigners.Add(new DeniedSigner(signerId: SignerID, exceptAllowRule: null));
				}
			}
		}

		// Update Policy Object
		policyObj.Signers = signers;
		policyObj.CiSigners = ciSigners;

		umciScenario.ProductSigners.DeniedSigners.DeniedSigner = umciDeniedSigners;
		kmciScenario.ProductSigners.DeniedSigners.DeniedSigner = kmciDeniedSigners;

		return policyObj;
	}

	internal static SigningScenario EnsureScenario(SiPolicy.SiPolicy policyObj, byte scenarioValue)
	{
		SigningScenario? scenario = policyObj.SigningScenarios?.FirstOrDefault(s => s.Value == scenarioValue);
		if (scenario is null)
		{
			scenario = new SigningScenario
			(
				value: scenarioValue,
				id: scenarioValue == 12 ? "ID_SIGNINGSCENARIO_UMCI" : "ID_SIGNINGSCENARIO_KMCI",
				productSigners: new ProductSigners()
			)
			{ FriendlyName = scenarioValue == 12 ? "User Mode Signing Scenario" : "Kernel Mode Signing Scenario" };

			List<SigningScenario> scenarios = policyObj.SigningScenarios ?? [];
			scenarios.Add(scenario);
			policyObj.SigningScenarios = scenarios;
		}
		return scenario;
	}

}
