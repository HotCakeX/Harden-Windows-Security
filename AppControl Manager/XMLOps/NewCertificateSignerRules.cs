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
using System.Xml;
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
		List<Signer> signers = policyObj.Signers?.ToList() ?? [];
		List<CiSigner> ciSigners = policyObj.CiSigners?.ToList() ?? [];

		// Ensure Scenarios exist
		SigningScenario umciScenario = NewPublisherLevelRules.EnsureScenario(policyObj, 12);
		SigningScenario kmciScenario = NewPublisherLevelRules.EnsureScenario(policyObj, 131);

		// Ensure ProductSigners exist
		umciScenario.ProductSigners ??= new ProductSigners();
		kmciScenario.ProductSigners ??= new ProductSigners();

		// Ensure AllowedSigners exist
		umciScenario.ProductSigners.AllowedSigners ??= new AllowedSigners();
		kmciScenario.ProductSigners.AllowedSigners ??= new AllowedSigners();

		List<AllowedSigner> umciAllowedSigners = umciScenario.ProductSigners.AllowedSigners.AllowedSigner?.ToList() ?? [];
		List<AllowedSigner> kmciAllowedSigners = kmciScenario.ProductSigners.AllowedSigners.AllowedSigner?.ToList() ?? [];

		foreach (CertificateSignerCreator signer in signerData)
		{
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
			string SignerID = $"ID_SIGNER_R_{guid}";

			Signer newSigner = new()
			{
				ID = SignerID,
				Name = signer.SignerName,
				CertRoot = new CertRoot
				{
					Type = CertEnumType.TBS,
					Value = Convert.FromHexString(signer.TBS)
				}
			};

			signers.Add(newSigner);

			// For User-Mode files
			if (signer.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
			{
				umciAllowedSigners.Add(new AllowedSigner { SignerId = SignerID });
				ciSigners.Add(new CiSigner { SignerId = SignerID });
			}
			// For Kernel-Mode files - they don't need CI Signers
			else if (signer.SiSigningScenario is SiPolicyIntel.SSType.KernelMode)
			{
				kmciAllowedSigners.Add(new AllowedSigner { SignerId = SignerID });
			}
		}

		// Update Policy Object
		policyObj.Signers = signers.ToArray();
		policyObj.CiSigners = ciSigners.ToArray();

		umciScenario.ProductSigners.AllowedSigners.AllowedSigner = umciAllowedSigners.ToArray();
		kmciScenario.ProductSigners.AllowedSigners.AllowedSigner = kmciAllowedSigners.ToArray();

		return policyObj;
	}
}
