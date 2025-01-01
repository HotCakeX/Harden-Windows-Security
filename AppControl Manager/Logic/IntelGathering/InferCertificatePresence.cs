using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using AppControlManager.Logging;
using AppControlManager.SiPolicy;

namespace AppControlManager.Logic.IntelGathering;

internal static class CertificatePresence
{

	/// <summary>
	/// Takes in a policy object and certificate .cer file path and ensures the certificate's details is added to the policy as UpdatePolicySigner
	/// It also checks to see whether user selected certificate matches the user selected certificate common name.
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
			Logger.Write($"The selected common name is {certCN} but the common name of the certificate you selected is {CertCommonName} which doesn't match it.");
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
					if (string.Equals(CertTBS, certRootTBS, StringComparison.OrdinalIgnoreCase) && string.Equals(CertCommonName, signerForUpdateSigner.Name, StringComparison.OrdinalIgnoreCase))
					{
						return true;
					}
				}
			}
		}

		Logger.Write("No UpdatePolicySigner found with the same TBS hash and Common Name as the selected certificate in the policy XML file you selected.");

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
		string CertCommonName = CryptoAPI.GetNameString(CertObject.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false);

		// Make sure the certificate that user selected matches the user-selected certificate Common Name
		if (!string.Equals(certCN, CertCommonName, StringComparison.OrdinalIgnoreCase))
		{
			Logger.Write($"The selected common name is {certCN} but the common name of the certificate you selected is {CertCommonName} which doesn't match it.");
			return false;
		}

		return true;
	}

}

