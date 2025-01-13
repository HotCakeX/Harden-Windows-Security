using System;
using System.Collections.Generic;
using System.Xml;
using AppControlManager.Others;

namespace AppControlManager.XMLOps;

internal static class NewPublisherLevelRules
{

	/// <summary>
	/// Creates new Allow Publisher level rules in an XML file
	/// Each rules includes the Signers, AllowedSigners, and CiSigners(depending on kernel/user mode)
	/// </summary>
	/// <param name="xmlFilePath">The path to the XML file to be modified</param>
	/// <param name="publisherSigners">The PublisherSigners to be used for creating the rules, they are the output of the BuildSignerAndHashObjects Method</param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void CreateAllow(string xmlFilePath, List<PublisherSignerCreator> publisherSigners)
	{

		if (publisherSigners is null || publisherSigners.Count == 0)
		{
			Logger.Write($"NewPublisherLevelRules: no Publisher signers detected to create rules for.");
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);



		// This method isn't suitable for strict Kernel-Mode policy
		if (codeIntegrityPolicy.UMCI_ProductSignersNode is null)
		{
			throw new InvalidOperationException("NewPublisherLevelRules.Create method isn't suitable for strict Kernel-Mode policy");
		}



		#region

		// Find AllowedSigners node in each ProductSigners node
		XmlNode? UMCI_ProductSigners_AllowedSigners_Node = codeIntegrityPolicy.UMCI_ProductSignersNode.SelectSingleNode("ns:AllowedSigners", codeIntegrityPolicy.NamespaceManager);
		XmlNode? KMCI_ProductSigners_AllowedSigners_Node = codeIntegrityPolicy.KMCI_ProductSignersNode?.SelectSingleNode("ns:AllowedSigners", codeIntegrityPolicy.NamespaceManager);

		// Check if AllowedSigners node exists, if not, create it
		if (UMCI_ProductSigners_AllowedSigners_Node is null)
		{
			XmlElement UMCI_AllowedSignersNew = codeIntegrityPolicy.XmlDocument.CreateElement("AllowedSigners", codeIntegrityPolicy.NameSpaceURI);
			_ = codeIntegrityPolicy.UMCI_ProductSignersNode.AppendChild(UMCI_AllowedSignersNew);

			UMCI_ProductSigners_AllowedSigners_Node = codeIntegrityPolicy.UMCI_ProductSignersNode.SelectSingleNode("ns:AllowedSigners", codeIntegrityPolicy.NamespaceManager);
		}

		if (UMCI_ProductSigners_AllowedSigners_Node is null)
		{
			throw new InvalidOperationException("UMCI Product Signers AllowedSigners node not found despite creating it");
		}

		// Check if AllowedSigners node exists, if not, create it
		if (KMCI_ProductSigners_AllowedSigners_Node is null)
		{
			XmlElement KMCI_AllowedSignersNew = codeIntegrityPolicy.XmlDocument.CreateElement("AllowedSigners", codeIntegrityPolicy.NameSpaceURI);
			_ = codeIntegrityPolicy.KMCI_ProductSignersNode?.AppendChild(KMCI_AllowedSignersNew);
			KMCI_ProductSigners_AllowedSigners_Node = codeIntegrityPolicy.KMCI_ProductSignersNode?.SelectSingleNode("ns:AllowedSigners", codeIntegrityPolicy.NamespaceManager);
		}

		if (KMCI_ProductSigners_AllowedSigners_Node is null)
		{
			throw new InvalidOperationException("KMCI Product Signers AllowedSigners node not found despite creating it");
		}

		#endregion

		Logger.Write($"NewPublisherLevelRules: There are {publisherSigners.Count} Publisher Signers to be added to the XML file '{xmlFilePath}'");

		foreach (PublisherSignerCreator publisherData in publisherSigners)
		{

			// Create signer for each certificate details in the PublisherSigners
			// Some files are signed by multiple signers
			foreach (CertificateDetailsCreator signerData in publisherData.CertificateDetails)
			{

				string guid = SiPolicyIntel.GUIDGenerator.GenerateUniqueGUIDToUpper();

				string SignerID = $"ID_SIGNER_B_{guid}";

				// Create the new Signer element

				// Create a new Signer node
				XmlElement newSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("Signer", codeIntegrityPolicy.NameSpaceURI);
				// Set the attributes for the new Signer node
				newSignerNode.SetAttribute("ID", SignerID);
				newSignerNode.SetAttribute("Name", signerData.IntermediateCertName);

				// Create the CertRoot element and add it to the Signer element
				XmlElement certRootNode = codeIntegrityPolicy.XmlDocument.CreateElement("CertRoot", codeIntegrityPolicy.NameSpaceURI);
				certRootNode.SetAttribute("Type", "TBS");
				certRootNode.SetAttribute("Value", signerData.IntermediateCertTBS);
				_ = newSignerNode.AppendChild(certRootNode);

				// Create the CertPublisher element and add it to the Signer element
				XmlElement certPublisherNode = codeIntegrityPolicy.XmlDocument.CreateElement("CertPublisher", codeIntegrityPolicy.NameSpaceURI);
				certPublisherNode.SetAttribute("Value", signerData.LeafCertName);
				_ = newSignerNode.AppendChild(certPublisherNode);

				// Add the new Signer element to the Signers node
				_ = codeIntegrityPolicy.SignersNode.AppendChild(newSignerNode);


				// Adding signer to the Signer Scenario and CiSigners

				// For User-Mode files
				if (publisherData.SiSigningScenario == 1)
				{
					// Create AllowedSigner nodes inside the <AllowedSigners> -> <ProductSigners> -> <SigningScenario Value="12">
					XmlElement newUMCIAllowedSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("AllowedSigner", codeIntegrityPolicy.NameSpaceURI);
					newUMCIAllowedSignerNode.SetAttribute("SignerId", SignerID);
					_ = UMCI_ProductSigners_AllowedSigners_Node.AppendChild(newUMCIAllowedSignerNode);


					// Create a CI Signer for the User Mode Signer
					XmlElement newCiSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("CiSigner", codeIntegrityPolicy.NameSpaceURI);
					newCiSignerNode.SetAttribute("SignerId", SignerID);
					_ = codeIntegrityPolicy.CiSignersNode.AppendChild(newCiSignerNode);
				}

				// For Kernel-Mode files
				else if (publisherData.SiSigningScenario == 0)
				{
					// Create AllowedSigner nodes inside the <AllowedSigners> -> <ProductSigners> -> <SigningScenario Value="131">
					XmlElement newKMCIAllowedSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("AllowedSigner", codeIntegrityPolicy.NameSpaceURI);
					newKMCIAllowedSignerNode.SetAttribute("SignerId", SignerID);
					_ = KMCI_ProductSigners_AllowedSigners_Node.AppendChild(newKMCIAllowedSignerNode);


					// Kernel-Mode signers don't need CI Signers
				}
			}
		}

		// Save the XML file
		codeIntegrityPolicy.XmlDocument.Save(xmlFilePath);
	}







	/// <summary>
	/// Creates new Deny Publisher level rules in an XML file
	/// Each rules includes the Signers, DeniedSigners, and CiSigners(depending on kernel/user mode)
	/// </summary>
	/// <param name="xmlFilePath">The path to the XML file to be modified</param>
	/// <param name="publisherSigners">The PublisherSigners to be used for creating the rules, they are the output of the BuildSignerAndHashObjects Method</param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void CreateDeny(string xmlFilePath, List<PublisherSignerCreator> publisherSigners)
	{

		if (publisherSigners is null || publisherSigners.Count == 0)
		{
			Logger.Write($"NewPublisherLevelRules: no Publisher signers detected to create rules for.");
			return;
		}

		// Instantiate the policy
		CodeIntegrityPolicy codeIntegrityPolicy = new(xmlFilePath, null);



		// This method isn't suitable for strict Kernel-Mode policy
		if (codeIntegrityPolicy.UMCI_ProductSignersNode is null)
		{
			throw new InvalidOperationException("NewPublisherLevelRules.Create method isn't suitable for strict Kernel-Mode policy");
		}



		#region

		// Find DeniedSigners node in each ProductSigners node
		XmlNode? UMCI_ProductSigners_DeniedSigners_Node = codeIntegrityPolicy.UMCI_ProductSignersNode.SelectSingleNode("ns:DeniedSigners", codeIntegrityPolicy.NamespaceManager);
		XmlNode? KMCI_ProductSigners_DeniedSigners_Node = codeIntegrityPolicy.KMCI_ProductSignersNode?.SelectSingleNode("ns:DeniedSigners", codeIntegrityPolicy.NamespaceManager);

		// Check if DeniedSigners node exists, if not, create it
		if (UMCI_ProductSigners_DeniedSigners_Node is null)
		{
			XmlElement UMCI_DeniedSignersNew = codeIntegrityPolicy.XmlDocument.CreateElement("DeniedSigners", codeIntegrityPolicy.NameSpaceURI);
			_ = codeIntegrityPolicy.UMCI_ProductSignersNode.AppendChild(UMCI_DeniedSignersNew);

			UMCI_ProductSigners_DeniedSigners_Node = codeIntegrityPolicy.UMCI_ProductSignersNode.SelectSingleNode("ns:DeniedSigners", codeIntegrityPolicy.NamespaceManager);
		}

		if (UMCI_ProductSigners_DeniedSigners_Node is null)
		{
			throw new InvalidOperationException("UMCI Product Signers DeniedSigners node not found despite creating it");
		}

		// Check if DeniedSigners node exists, if not, create it
		if (KMCI_ProductSigners_DeniedSigners_Node is null)
		{
			XmlElement KMCI_DeniedSignersNew = codeIntegrityPolicy.XmlDocument.CreateElement("DeniedSigners", codeIntegrityPolicy.NameSpaceURI);
			_ = codeIntegrityPolicy.KMCI_ProductSignersNode?.AppendChild(KMCI_DeniedSignersNew);
			KMCI_ProductSigners_DeniedSigners_Node = codeIntegrityPolicy.KMCI_ProductSignersNode?.SelectSingleNode("ns:DeniedSigners", codeIntegrityPolicy.NamespaceManager);
		}

		if (KMCI_ProductSigners_DeniedSigners_Node is null)
		{
			throw new InvalidOperationException("KMCI Product Signers DeniedSigners node not found despite creating it");
		}

		#endregion

		Logger.Write($"NewPublisherLevelRules: There are {publisherSigners.Count} Publisher Signers to be added to the XML file '{xmlFilePath}'");

		foreach (PublisherSignerCreator publisherData in publisherSigners)
		{

			// Create signer for each certificate details in the PublisherSigners
			// Some files are signed by multiple signers
			foreach (CertificateDetailsCreator signerData in publisherData.CertificateDetails)
			{

				string guid = SiPolicyIntel.GUIDGenerator.GenerateUniqueGUIDToUpper();

				string SignerID = $"ID_SIGNER_B_{guid}";

				// Create the new Signer element

				// Create a new Signer node
				XmlElement newSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("Signer", codeIntegrityPolicy.NameSpaceURI);
				// Set the attributes for the new Signer node
				newSignerNode.SetAttribute("ID", SignerID);
				newSignerNode.SetAttribute("Name", signerData.IntermediateCertName);

				// Create the CertRoot element and add it to the Signer element
				XmlElement certRootNode = codeIntegrityPolicy.XmlDocument.CreateElement("CertRoot", codeIntegrityPolicy.NameSpaceURI);
				certRootNode.SetAttribute("Type", "TBS");
				certRootNode.SetAttribute("Value", signerData.IntermediateCertTBS);
				_ = newSignerNode.AppendChild(certRootNode);

				// Create the CertPublisher element and add it to the Signer element
				XmlElement certPublisherNode = codeIntegrityPolicy.XmlDocument.CreateElement("CertPublisher", codeIntegrityPolicy.NameSpaceURI);
				certPublisherNode.SetAttribute("Value", signerData.LeafCertName);
				_ = newSignerNode.AppendChild(certPublisherNode);

				// Add the new Signer element to the Signers node
				_ = codeIntegrityPolicy.SignersNode.AppendChild(newSignerNode);


				// Adding signer to the Signer Scenario and CiSigners

				// For User-Mode files
				if (publisherData.SiSigningScenario == 1)
				{
					// Create DeniedSigner nodes inside the <DeniedSigners> -> <ProductSigners> -> <SigningScenario Value="12">
					XmlElement newUMCIDeniedSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("DeniedSigner", codeIntegrityPolicy.NameSpaceURI);
					newUMCIDeniedSignerNode.SetAttribute("SignerId", SignerID);
					_ = UMCI_ProductSigners_DeniedSigners_Node.AppendChild(newUMCIDeniedSignerNode);


					// Create a CI Signer for the User Mode Signer
					XmlElement newCiSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("CiSigner", codeIntegrityPolicy.NameSpaceURI);
					newCiSignerNode.SetAttribute("SignerId", SignerID);
					_ = codeIntegrityPolicy.CiSignersNode.AppendChild(newCiSignerNode);
				}

				// For Kernel-Mode files
				else if (publisherData.SiSigningScenario == 0)
				{
					// Create DeniedSigner nodes inside the <DeniedSigners> -> <ProductSigners> -> <SigningScenario Value="131">
					XmlElement newKMCIDeniedSignerNode = codeIntegrityPolicy.XmlDocument.CreateElement("DeniedSigner", codeIntegrityPolicy.NameSpaceURI);
					newKMCIDeniedSignerNode.SetAttribute("SignerId", SignerID);
					_ = KMCI_ProductSigners_DeniedSigners_Node.AppendChild(newKMCIDeniedSignerNode);


					// Kernel-Mode signers don't need CI Signers
				}
			}
		}

		// Save the XML file
		codeIntegrityPolicy.XmlDocument.Save(xmlFilePath);
	}


}
