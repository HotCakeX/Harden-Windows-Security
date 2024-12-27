using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
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

		SiPolicy.SiPolicy policyObject = Management.Initialize(xmlPolicyFile);

		// Create a Cert root object that will be used by signers
		CertRoot certRoot = new()
		{
			Type = CertEnumType.TBS,

			// Parses the hexadecimal string (CertTBS) into a byte array by processing 2 characters at a time
			Value = [.. Enumerable.Range(0, CertTBS.Length / 2).Select(x => Convert.ToByte(CertTBS.Substring(x * 2, 2), 16))]
		};

		Signer supplementalPolicySigner = new()
		{
			ID = $"ID_SIGNER_S_{GUIDGenerator.GenerateUniqueGUIDToUpper()}",
			Name = CertCommonName,
			CertRoot = certRoot
		};

		Signer updatePolicySigner = new()
		{
			ID = $"ID_SIGNER_S_{GUIDGenerator.GenerateUniqueGUIDToUpper()}",
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




		// If the policy has <Signers> node
		if (policyObject.Signers is not null)
		{
			// Convert the signers array to list for easy manipulation
			List<Signer> currentSignersList = [.. policyObject.Signers];


			currentSignersList.Add(updatePolicySigner);

			// Only add the SupplementalPolicySigner if the policy is not a SupplementalPolicy
			// Because only Base policies can have that
			if (policyObject.PolicyType is not PolicyType.SupplementalPolicy)
			{
				currentSignersList.Add(supplementalPolicySigner);
			}

			// Converting to IEnumerable is required to assign it properly to the Signers nodes
			IEnumerable<Signer> currentSignersEnumerable = [.. currentSignersList];

			policyObject.Signers = [.. currentSignersEnumerable];
		}
		else
		{
			IEnumerable<Signer> signersList;

			if (policyObject.PolicyType is not PolicyType.SupplementalPolicy)
			{
				signersList = [updatePolicySigner, supplementalPolicySigner];
			}
			else
			{
				signersList = [updatePolicySigner];
			}

			policyObject.Signers = [.. signersList];
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

		Management.SavePolicyToFile(policyObject, xmlPolicyFile);


		return policyObject;
	}

}
