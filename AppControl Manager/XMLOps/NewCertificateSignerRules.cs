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
using AppControlManager.Others;
using AppControlManager.SiPolicy;

namespace AppControlManager.XMLOps;

internal static class NewCertificateSignerRules
{
	/// <summary>
	/// Creates new Signer rules for Certificates in the SiPolicy object
	/// The level is Pca/Root/Leaf certificate, meaning there is no certificate publisher mentioned
	/// Only Certificate TBS and its name is used.
	/// </summary>
	/// <param name="policyObj"></param>
	/// <param name="signerData"></param>
	/// <returns>SiPolicy</returns>
	internal static SiPolicy.SiPolicy CreateAllow(SiPolicy.SiPolicy policyObj, List<CertificateSignerCreator> signerData)
	{
		if (signerData.Count is 0)
		{
			Logger.Write($"no Certificate rules detected to create allow rules for.");
			return policyObj;
		}

		// Get or Initialize lists
		List<Signer> signers = policyObj.Signers ?? [];
		List<CiSigner> ciSigners = policyObj.CiSigners ?? [];

		// Ensure Scenarios exist
		SigningScenario umciScenario = NewPublisherLevelRules.EnsureScenario(policyObj, 12);
		SigningScenario kmciScenario = NewPublisherLevelRules.EnsureScenario(policyObj, 131);

		// Ensure ProductSigners exist
		umciScenario.ProductSigners ??= new ProductSigners();
		kmciScenario.ProductSigners ??= new ProductSigners();

		// Ensure AllowedSigners exist
		umciScenario.ProductSigners.AllowedSigners ??= new AllowedSigners([]);
		kmciScenario.ProductSigners.AllowedSigners ??= new AllowedSigners([]);

		List<AllowedSigner> umciAllowedSigners = umciScenario.ProductSigners.AllowedSigners.AllowedSigner ?? [];
		List<AllowedSigner> kmciAllowedSigners = kmciScenario.ProductSigners.AllowedSigners.AllowedSigner ?? [];

		foreach (CertificateSignerCreator signer in signerData)
		{
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
			string SignerID = $"ID_SIGNER_R_{guid}";

			Signer newSigner = new(
				id: SignerID,
				name: signer.SignerName,
				certRoot: new CertRoot
				(
					type: CertEnumType.TBS,
					value: Convert.FromHexString(signer.TBS)
				));

			signers.Add(newSigner);

			// For User-Mode files
			if (signer.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
			{
				umciAllowedSigners.Add(new AllowedSigner(signerId: SignerID, exceptDenyRule: null));
				ciSigners.Add(new CiSigner(signerID: SignerID));
			}
			// For Kernel-Mode files - they don't need CI Signers
			else if (signer.SiSigningScenario is SiPolicyIntel.SSType.KernelMode)
			{
				kmciAllowedSigners.Add(new AllowedSigner(signerId: SignerID, exceptDenyRule: null));
			}
		}

		// Update Policy Object
		policyObj.Signers = signers;
		policyObj.CiSigners = ciSigners;

		umciScenario.ProductSigners.AllowedSigners.AllowedSigner = umciAllowedSigners;
		kmciScenario.ProductSigners.AllowedSigners.AllowedSigner = kmciAllowedSigners;

		return policyObj;
	}
}
