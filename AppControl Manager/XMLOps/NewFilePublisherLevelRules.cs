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
using System.Runtime.InteropServices;
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

		// Ensure the lists are Initialized.
		policyObj.FileRules ??= [];
		policyObj.Signers ??= [];
		policyObj.CiSigners ??= [];

		// Ensure Scenarios exist
		SigningScenario umciScenario = NewPublisherLevelRules.EnsureScenario(policyObj, 12);
		SigningScenario kmciScenario = NewPublisherLevelRules.EnsureScenario(policyObj, 131);

		// Ensure AllowedSigners exist
		umciScenario.ProductSigners.AllowedSigners ??= new AllowedSigners([]);
		kmciScenario.ProductSigners.AllowedSigners ??= new AllowedSigners([]);

		foreach (FilePublisherSignerCreator filePublisherData in CollectionsMarshal.AsSpan(filePublisherSigners))
		{
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
			string FileAttribID = $"ID_FILEATTRIB_A_{guid}";

			#region Creating File <FileAttrib> node

			FileAttrib newFileAttrib = new(id: FileAttribID)
			{
				FriendlyName = GlobalVars.GetStr("FilePublisherRuleTypeFriendlyName"),
				MinimumFileVersion = filePublisherData.FileVersion?.ToString()
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

			policyObj.FileRules.Add(newFileAttrib);

			#endregion

			#region Creating Signers

			// Create signer for each certificate details in the FilePublisherSigners
			// Some files are signed by multiple signers

			foreach (CertificateDetailsCreator signerData in CollectionsMarshal.AsSpan(filePublisherData.CertificateDetails))
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

				policyObj.Signers.Add(newSigner);

				// For User-Mode files
				if (filePublisherData.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
				{
					umciScenario.ProductSigners.AllowedSigners.AllowedSigner.Add(new AllowedSigner(signerId: signerID, exceptDenyRule: null));
					policyObj.CiSigners.Add(new CiSigner(signerID: signerID));
				}
				// For Kernel-Mode files
				else if (filePublisherData.SiSigningScenario is SiPolicyIntel.SSType.KernelMode)
				{
					kmciScenario.ProductSigners.AllowedSigners.AllowedSigner.Add(new AllowedSigner(signerId: signerID, exceptDenyRule: null));
				}
			}

			#endregion
		}

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

		// Ensure the lists are Initialized.
		policyObj.FileRules ??= [];
		policyObj.Signers ??= [];
		policyObj.CiSigners ??= [];

		// Ensure Scenarios exist
		SigningScenario umciScenario = NewPublisherLevelRules.EnsureScenario(policyObj, 12);
		SigningScenario kmciScenario = NewPublisherLevelRules.EnsureScenario(policyObj, 131);

		// Ensure DeniedSigners exist
		umciScenario.ProductSigners.DeniedSigners ??= new DeniedSigners([]);
		kmciScenario.ProductSigners.DeniedSigners ??= new DeniedSigners([]);

		foreach (FilePublisherSignerCreator filePublisherData in CollectionsMarshal.AsSpan(filePublisherSigners))
		{
			string guid = Guid.CreateVersion7().ToString("N").ToUpperInvariant();
			string FileAttribID = $"ID_FILEATTRIB_A_{guid}";

			#region Creating File <FileAttrib> node

			FileAttrib newFileAttrib = new(id: FileAttribID)
			{
				FriendlyName = GlobalVars.GetStr("FilePublisherRuleTypeFriendlyName"),
				MinimumFileVersion = filePublisherData.FileVersion?.ToString()
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

			policyObj.FileRules.Add(newFileAttrib);

			#endregion

			#region Creating Signers

			// Create signer for each certificate details in the FilePublisherSigners
			// Some files are signed by multiple signers

			foreach (CertificateDetailsCreator signerData in CollectionsMarshal.AsSpan(filePublisherData.CertificateDetails))
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

				policyObj.Signers.Add(newSigner);

				// For User-Mode files
				if (filePublisherData.SiSigningScenario is SiPolicyIntel.SSType.UserMode)
				{
					umciScenario.ProductSigners.DeniedSigners.DeniedSigner.Add(new DeniedSigner(signerId: signerID, exceptAllowRule: null));
					policyObj.CiSigners.Add(new CiSigner(signerID: signerID));
				}
				// For Kernel-Mode files
				else if (filePublisherData.SiSigningScenario is SiPolicyIntel.SSType.KernelMode)
				{
					kmciScenario.ProductSigners.DeniedSigners.DeniedSigner.Add(new DeniedSigner(signerId: signerID, exceptAllowRule: null));
				}
			}

			#endregion
		}

		return policyObj;
	}
}
