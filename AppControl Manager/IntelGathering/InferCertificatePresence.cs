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
using AppControlManager.Others;
using AppControlManager.SiPolicy;

namespace AppControlManager.IntelGathering;

internal static class CertificatePresence
{

	/// <summary>
	/// Takes in a policy object and certificate .cer file path and ensures the certificate's details is added to the policy as UpdatePolicySigner
	/// It also checks to see whether user selected certificate matches the user selected certificate common name.
	/// The reason we don't need to check signature of the deployed signed cip files in the EFI partition is because
	/// The user-selected XML policy's ID is already checked against the deployed signed policies and that provides the necessary signing details in the XML.
	/// </summary>
	/// <param name="policyObject"></param>
	/// <param name="certificatePath"></param>
	/// <param name="certCN"></param>
	/// <returns></returns>
	internal static bool InferCertificatePresence(SiPolicy.SiPolicy policyObject, string certificatePath, string certCN)
	{
		// Create a certificate object from the .cer file
		X509Certificate2 CertObject = X509CertificateLoader.LoadCertificateFromFile(certificatePath);

		// Get the TBS of the certificate
		string CertTBS = CertificateHelper.GetTBSCertificate(CertObject);

		// Get the Common Name of the certificate
		string CertCommonName = CryptoAPI.GetNameString(CertObject.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false);

		// Make sure the certificate that user selected matches the user-selected certificate Common Name
		if (!string.Equals(certCN, CertCommonName, StringComparison.OrdinalIgnoreCase))
		{
			Logger.Write(string.Format(
				GlobalVars.GetStr("SelectedCertCommonNameMismatchMessage"),
				certCN,
				CertCommonName));
			return false;
		}

		// Get the ID of all of the UpdatePolicySigners elements
		IEnumerable<string> updatePolicySignerIDs = policyObject.UpdatePolicySigners.Select(x => x.SignerId);

		// Get all of the <Signer> elements from the policy
		Dictionary<string, Signer> signerDictionary = [];
		foreach (Signer signer in policyObject.Signers)
		{
			_ = signerDictionary.TryAdd(signer.ID, signer);
		}

		// Loop over each updatePolicySignerID in the policy
		foreach (string updatePolicySigner in updatePolicySignerIDs)
		{
			// Try to find a signer that is for UpdatePolicySigners
			if (signerDictionary.TryGetValue(updatePolicySigner, out Signer? signerForUpdateSigner))
			{
				// If signer is TBS Signer
				if (signerForUpdateSigner.CertRoot.Type is CertEnumType.TBS)
				{
					// Get the string value of the CertRoot which is the TBS Hash
					string certRootTBS = Convert.ToHexString(signerForUpdateSigner.CertRoot.Value);

					// Compare the selected certificate's TBS hash with the TBS hash of the signer which is the cert Root value
					// Also compare the Signer's name with the selected certificate's Common Name
					if (string.Equals(CertTBS, certRootTBS, StringComparison.OrdinalIgnoreCase) &&
						string.Equals(CertCommonName, signerForUpdateSigner.Name, StringComparison.OrdinalIgnoreCase))
					{
						return true;
					}
				}
			}
		}

		Logger.Write(GlobalVars.GetStr("NoMatchingUpdatePolicySignerMessage"));
		return false;
	}


	/// <summary>
	/// Gets the path to a .cer certificate file and a certificate common name
	/// Makes sure the common name belongs to the certificate file
	/// </summary>
	/// <param name="certificatePath"></param>
	/// <param name="certCN"></param>
	/// <returns></returns>
	internal static bool VerifyCertAndCNMatch(string certificatePath, string certCN)
	{
		// Create a certificate object from the .cer file
		X509Certificate2 CertObject = X509CertificateLoader.LoadCertificateFromFile(certificatePath);

		// Get the Common Name of the certificate
		string CertCommonName = CryptoAPI.GetNameString(
			CertObject.Handle,
			CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE,
			null,
			false);

		// Make sure the certificate that user selected matches the user-selected certificate Common Name
		if (!string.Equals(certCN, CertCommonName, StringComparison.OrdinalIgnoreCase))
		{
			Logger.Write(string.Format(
				GlobalVars.GetStr("SelectedCertCommonNameMismatchMessage"),
				certCN,
				CertCommonName));
			return false;
		}

		return true;
	}

}

