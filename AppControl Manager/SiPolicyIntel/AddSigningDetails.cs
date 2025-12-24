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
using System.Security.Cryptography.X509Certificates;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SiPolicy;

namespace AppControlManager.SiPolicyIntel;

internal static class AddSigningDetails
{
	/// <summary>
	/// Adds the details of a certificate to an App Control policy in order to prepare it for signing.
	/// Regardless of how many chains a certificate contains, only the leaf certificate will be used.
	/// It will also remove the unsigned policy rule option.
	/// </summary>
	/// <param name="xmlPolicyFile"></param>
	/// <param name="certificateFile"></param>
	internal static SiPolicy.SiPolicy Add(string xmlPolicyFile, string certificateFile)
	{
		// Create a certificate object from the .cer file
		X509Certificate2 CertObject = X509CertificateLoader.LoadCertificateFromFile(certificateFile);

		// Get the TBS of the certificate
		string CertTBS = CertificateHelper.GetTBSCertificate(CertObject);

		// Get the Common Name of the certificate
		string CertCommonName = CryptoAPI.GetNameString(CertObject.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false);

		SiPolicy.SiPolicy policyObject = Management.Initialize(xmlPolicyFile, null);

		// Create a Cert root object that will be used by signers
		CertRoot certRoot = new(
			type: CertEnumType.TBS,
			value: Convert.FromHexString(CertTBS)
		);

		Signer supplementalPolicySigner = new(
			id: $"ID_SIGNER_S_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}",
			name: CertCommonName,
			certRoot: certRoot
		);

		Signer updatePolicySigner = new(
			id: $"ID_SIGNER_S_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}",
			name: CertCommonName,
			certRoot: certRoot
		);

		SupplementalPolicySigner supplementalPolicySigner1 = new(signerID: supplementalPolicySigner.ID);

		UpdatePolicySigner updatePolicySigner1 = new(signerID: updatePolicySigner.ID);

		// If the policy has <Signers> node.
		if (policyObject.Signers is not null)
		{
			policyObject.Signers.Add(updatePolicySigner);

			// Only add the SupplementalPolicySigner if the policy is not a SupplementalPolicy
			// Because only Base policies can have that
			if (policyObject.PolicyType is not PolicyType.SupplementalPolicy)
			{
				policyObject.Signers.Add(supplementalPolicySigner);
			}
		}
		// If the policy has no <Signers> node.
		else
		{
			List<Signer> signersList = [];

			signersList.Add(updatePolicySigner);

			if (policyObject.PolicyType is not PolicyType.SupplementalPolicy)
			{
				signersList.Add(supplementalPolicySigner);
			}

			policyObject.Signers = signersList;
		}


		if (policyObject.PolicyType is not PolicyType.SupplementalPolicy)
		{
			if (policyObject.SupplementalPolicySigners is not null)
			{
				policyObject.SupplementalPolicySigners.Add(supplementalPolicySigner1);
			}
			else
			{
				policyObject.SupplementalPolicySigners = [supplementalPolicySigner1];
			}
		}


		if (policyObject.UpdatePolicySigners is not null)
		{
			policyObject.UpdatePolicySigners.Add(updatePolicySigner1);
		}
		else
		{
			policyObject.UpdatePolicySigners = [updatePolicySigner1];
		}

		// Remove the unsigned policy rule option from the policy
		// And save the final result to the file
		CiRuleOptions.Set(filePath: xmlPolicyFile,
			rulesToRemove: [OptionType.EnabledUnsignedSystemIntegrityPolicy],
			DirectPolicyObj: policyObject);

		return policyObject;
	}

}
