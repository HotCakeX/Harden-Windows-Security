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

internal static class NewFilePublisherLevelRules
{

	/// <summary>
	/// Creates new Allow FilePublisher level rules in the SiPolicy object
	/// Each rules includes the FileAttribs, Signers, AllowedSigners, and CiSigners(depending on kernel/user mode)
	/// </summary>
	/// <param name="policyObj"></param>
	/// <param name="filePublisherSigners"> The FilePublisherSigners to be used for creating the rules, they are the output of the BuildSignerAndHashObjects Method </param>
	/// <returns>SiPolicy</returns>
	internal static SiPolicy.SiPolicy CreateAllow(SiPolicy.SiPolicy policyObj, List<FilePublisherSignerCreator> filePublisherSigners)
	{
		if (filePublisherSigners.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoFilePublisherSignersDetectedAllowMessage"));
			return policyObj;
		}

		Logger.Write(string.Format(GlobalVars.GetStr("FilePublisherSignersToAddMessage"), filePublisherSigners.Count));

		// Get or Initialize lists
		List<object> fileRules = policyObj.FileRules ?? [];
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

		foreach (FilePublisherSignerCreator filePublisherData in filePublisherSigners)
		{
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
			string FileAttribID = $"ID_FILEATTRIB_A_{guid}";

			#region Creating File <FileAttrib> node

			FileAttrib newFileAttrib = new(id: FileAttribID)
			{
				FriendlyName = GlobalVars.GetStr("FilePublisherRuleTypeFriendlyName"),
				MinimumFileVersion = filePublisherData.FileVersion!.ToString()
			};

			if (!string.IsNullOrWhiteSpace(filePublisherData.OriginalFileName))
			{
				newFileAttrib.FileName = filePublisherData.OriginalFileName;
			}
			else if (!string.IsNullOrWhiteSpace(filePublisherData.InternalName))
			{
				newFileAttrib.InternalName = filePublisherData.InternalName;
			}
			else if (!string.IsNullOrWhiteSpace(filePublisherData.FileDescription))
			{
				newFileAttrib.FileDescription = filePublisherData.FileDescription;
			}
			else if (!string.IsNullOrWhiteSpace(filePublisherData.ProductName))
			{
				newFileAttrib.ProductName = filePublisherData.ProductName;
			}

			fileRules.Add(newFileAttrib);

			#endregion

			#region Creating Signers

			// Create signer for each certificate details in the FilePublisherSigners
			// Some files are signed by multiple signers

			foreach (CertificateDetailsCreator signerData in filePublisherData.CertificateDetails)
			{
				string guid2 = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
				string signerID = $"ID_SIGNER_A_{guid2}";

				Signer newSigner = new(
					id: signerID,
					name: signerData.IntermediateCertName,
					certRoot: new CertRoot
					(
						type: CertEnumType.TBS,
						value: Convert.FromHexString(signerData.IntermediateCertTBS)
					))
				{
					CertPublisher = new CertPublisher(value: signerData.LeafCertName),
					FileAttribRef = [new FileAttribRef(ruleID: FileAttribID)]
				};

				signers.Add(newSigner);

				// For User-Mode files
				if (filePublisherData.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
				{
					umciAllowedSigners.Add(new AllowedSigner(signerId: signerID, exceptDenyRule: null));
					ciSigners.Add(new CiSigner(signerID: signerID));
				}
				// For Kernel-Mode files
				else if (filePublisherData.SiSigningScenario is SiPolicyIntel.SSType.KernelMode)
				{
					kmciAllowedSigners.Add(new AllowedSigner(signerId: signerID, exceptDenyRule: null));
				}
			}

			#endregion
		}

		// Update Policy Object
		policyObj.FileRules = fileRules;
		policyObj.Signers = signers;
		policyObj.CiSigners = ciSigners;

		umciScenario.ProductSigners.AllowedSigners.AllowedSigner = umciAllowedSigners;
		kmciScenario.ProductSigners.AllowedSigners.AllowedSigner = kmciAllowedSigners;

		return policyObj;
	}


	/// <summary>
	/// Creates new Deny FilePublisher level rules in the SiPolicy object
	/// Each rules includes the FileAttribs, Signers, DeniedSigners, and CiSigners(depending on kernel/user mode)
	/// </summary>
	/// <param name="policyObj"></param>
	/// <param name="filePublisherSigners"> The FilePublisherSigners to be used for creating the rules, they are the output of the BuildSignerAndHashObjects Method </param>
	/// <returns>SiPolicy</returns>
	internal static SiPolicy.SiPolicy CreateDeny(SiPolicy.SiPolicy policyObj, List<FilePublisherSignerCreator> filePublisherSigners)
	{
		if (filePublisherSigners.Count is 0)
		{
			Logger.Write(GlobalVars.GetStr("NoFilePublisherSignersDetectedDenyMessage"));
			return policyObj;
		}

		Logger.Write(string.Format(GlobalVars.GetStr("FilePublisherSignersToAddMessage"), filePublisherSigners.Count));

		// Get or Initialize lists
		List<object> fileRules = policyObj.FileRules ?? [];
		List<Signer> signers = policyObj.Signers ?? [];
		List<CiSigner> ciSigners = policyObj.CiSigners ?? [];

		// Ensure Scenarios exist
		SigningScenario umciScenario = NewPublisherLevelRules.EnsureScenario(policyObj, 12);
		SigningScenario kmciScenario = NewPublisherLevelRules.EnsureScenario(policyObj, 131);

		// Ensure ProductSigners exist
		umciScenario.ProductSigners ??= new ProductSigners();
		kmciScenario.ProductSigners ??= new ProductSigners();

		// Ensure DeniedSigners exist
		umciScenario.ProductSigners.DeniedSigners ??= new DeniedSigners([]);
		kmciScenario.ProductSigners.DeniedSigners ??= new DeniedSigners([]);

		List<DeniedSigner> umciDeniedSigners = umciScenario.ProductSigners.DeniedSigners.DeniedSigner ?? [];
		List<DeniedSigner> kmciDeniedSigners = kmciScenario.ProductSigners.DeniedSigners.DeniedSigner ?? [];

		foreach (FilePublisherSignerCreator filePublisherData in filePublisherSigners)
		{
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
			string FileAttribID = $"ID_FILEATTRIB_A_{guid}";

			#region Creating File <FileAttrib> node

			FileAttrib newFileAttrib = new(id: FileAttribID)
			{
				FriendlyName = GlobalVars.GetStr("FilePublisherRuleTypeFriendlyName"),
				MinimumFileVersion = filePublisherData.FileVersion!.ToString()
			};

			if (!string.IsNullOrWhiteSpace(filePublisherData.OriginalFileName))
			{
				newFileAttrib.FileName = filePublisherData.OriginalFileName;
			}
			else if (!string.IsNullOrWhiteSpace(filePublisherData.InternalName))
			{
				newFileAttrib.InternalName = filePublisherData.InternalName;
			}
			else if (!string.IsNullOrWhiteSpace(filePublisherData.FileDescription))
			{
				newFileAttrib.FileDescription = filePublisherData.FileDescription;
			}
			else if (!string.IsNullOrWhiteSpace(filePublisherData.ProductName))
			{
				newFileAttrib.ProductName = filePublisherData.ProductName;
			}

			fileRules.Add(newFileAttrib);

			#endregion

			#region Creating Signers

			// Create signer for each certificate details in the FilePublisherSigners
			// Some files are signed by multiple signers

			foreach (CertificateDetailsCreator signerData in filePublisherData.CertificateDetails)
			{
				string guid2 = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
				string signerID = $"ID_SIGNER_A_{guid2}";

				Signer newSigner = new(
					id: signerID,
					name: signerData.IntermediateCertName,
					certRoot: new CertRoot
					(
						type: CertEnumType.TBS,
						value: Convert.FromHexString(signerData.IntermediateCertTBS)
					))
				{
					CertPublisher = new CertPublisher(value: signerData.LeafCertName),
					FileAttribRef = [new FileAttribRef(ruleID: FileAttribID)]
				};

				signers.Add(newSigner);

				// For User-Mode files
				if (filePublisherData.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
				{
					umciDeniedSigners.Add(new DeniedSigner(signerId: signerID, exceptAllowRule: null));
					ciSigners.Add(new CiSigner(signerID: signerID));
				}
				// For Kernel-Mode files
				else if (filePublisherData.SiSigningScenario is SiPolicyIntel.SSType.KernelMode)
				{
					kmciDeniedSigners.Add(new DeniedSigner(signerId: signerID, exceptAllowRule: null));
				}
			}

			#endregion
		}

		// Update Policy Object
		policyObj.FileRules = fileRules;
		policyObj.Signers = signers;
		policyObj.CiSigners = ciSigners;

		umciScenario.ProductSigners.DeniedSigners.DeniedSigner = umciDeniedSigners;
		kmciScenario.ProductSigners.DeniedSigners.DeniedSigner = kmciDeniedSigners;

		return policyObj;
	}
}
