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
		CertRoot certRoot = new()
		{
			Type = CertEnumType.TBS,

			// Parses the hexadecimal string (CertTBS) into a byte array by processing 2 characters at a time
			Value = [.. Enumerable.Range(0, CertTBS.Length / 2).Select(x => Convert.ToByte(CertTBS.Substring(x * 2, 2), 16))]
		};

		Signer supplementalPolicySigner = new()
		{
			ID = $"ID_SIGNER_S_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}",
			Name = CertCommonName,
			CertRoot = certRoot
		};

		Signer updatePolicySigner = new()
		{
			ID = $"ID_SIGNER_S_{Guid.CreateVersion7().ToString("N").ToUpperInvariant()}",
			Name = CertCommonName,
			CertRoot = certRoot
		};

		SupplementalPolicySigner supplementalPolicySigner1 = new()
		{
			SignerId = supplementalPolicySigner.ID
		};

		UpdatePolicySigner updatePolicySigner1 = new()
		{
			SignerId = updatePolicySigner.ID
		};


		// If the policy has <Signers> node.
		if (policyObject.Signers is not null)
		{
			// Convert the existing signers array to list for easy manipulation
			List<Signer> currentSignersList = [.. policyObject.Signers];

			currentSignersList.Add(updatePolicySigner);

			// Only add the SupplementalPolicySigner if the policy is not a SupplementalPolicy
			// Because only Base policies can have that
			if (policyObject.PolicyType is not PolicyType.SupplementalPolicy)
			{
				currentSignersList.Add(supplementalPolicySigner);
			}

			policyObject.Signers = currentSignersList.ToArray();
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

			policyObject.Signers = signersList.ToArray();
		}


		if (policyObject.PolicyType is not PolicyType.SupplementalPolicy)
		{
			if (policyObject.SupplementalPolicySigners is not null)
			{
				List<SupplementalPolicySigner> currentSupplementalPolicySignersList = [.. policyObject.SupplementalPolicySigners];
				currentSupplementalPolicySignersList.Add(supplementalPolicySigner1);
				policyObject.SupplementalPolicySigners = [.. currentSupplementalPolicySignersList];
			}
			else
			{
				policyObject.SupplementalPolicySigners = [supplementalPolicySigner1];
			}
		}


		if (policyObject.UpdatePolicySigners is not null)
		{
			List<UpdatePolicySigner> currentUpdatePolicySignersList = [.. policyObject.UpdatePolicySigners];
			currentUpdatePolicySignersList.Add(updatePolicySigner1);
			policyObject.UpdatePolicySigners = [.. currentUpdatePolicySignersList];
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
