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
using AppControlManager.IntelGathering;
using AppControlManager.Others;

namespace AppControlManager.XMLOps;

internal static class SignerAndHashBuilder
{
	// Get all of the drive letters on the system
	private static readonly List<DriveLetterMapper.DriveMapping> Drives = DriveLetterMapper.GetGlobalRootDrives();
	private static readonly IEnumerable<string?> DriveLetters = Drives.Select(x => x.DriveLetter);


	/// <summary>
	/// Creates Signer and Hash objects from the input data
	///
	/// Types created for Signed Data: FilePublisher, Publisher
	/// Types created for Unsigned Data: Hash
	///
	/// Behavior when the level is set to "Auto" or "FilePublisher":
	/// FilePublisher Signers are created for files that have the necessary details for a FilePublisher rule
	/// Publisher Signers are created for files that don't have the necessary details for a FilePublisher rule
	/// Hashes are created for the unsigned data
	///
	/// Behavior when the level is set to "Publisher":
	/// PublisherSigners are created for all of the Signed files
	/// Hashes are created for all of the unsigned files
	///
	/// Behavior when the level is set to "Hash":
	/// Hashes are created for all of the files, whether they are signed or unsigned
	///
	/// The output is a single object with nested properties for the Signed data and Hashes
	///
	/// Both Publisher and FilePublisher signers first check if the file has both Issuer and Publisher TBS hashes, if they are present then both of them will be used to create the Signer.
	/// If the file is missing the Issuer TBS hash, then the Publisher certificate will be used for both Publisher and Issuer details (TBS and Name)
	/// This will essentially create the Signers based on LeafCertificate Level.
	///
	/// The New-NewFilePublisherLevelRules class and NewPublisherLevelRules class both are able to create rules based on different signer App Control levels.
	///
	/// The other way around, where Publisher TBS hash is missing but Issuer TBS is present, would create a PCACertificate level Signer, but that is not implemented yet.
	/// Its use case is not clear yet and there haven't been any files with that condition yet. <summary>
	/// </summary>
	/// <param name="data">The Data to be processed. These are the logs selected by the user and contain both signed and unsigned data.</param>
	/// <param name="level">Auto, FilePublisher, Publisher, Hash</param>
	/// <param name="publisherToHash">It will pass any publisher rules to the hash array. E.g when sandboxing-like behavior using Macros and AppIDs are used.</param>
	/// <param name="folderPaths"></param>
	/// <param name="customFileRulePatterns"></param>
	/// <param name="packageFamilyNames"></param>
	/// </summary>
	/// <returns></returns>
	internal static FileBasedInfoPackage BuildSignerAndHashObjects(
	List<FileIdentity>? data = null,
	IReadOnlyCollection<string>? folderPaths = null,
	HashSet<string>? customFileRulePatterns = null,
	ScanLevels level = ScanLevels.FilePublisher,
	bool publisherToHash = false,
	List<string>? packageFamilyNames = null
)
	{
		// To store the Signers created with WHQLFilePublisher Level
		List<WHQLFilePublisherSignerCreator> whqlFilePublisherSigners = [];

		// To store the Signers created with FilePublisher Level
		List<FilePublisherSignerCreator> filePublisherSigners = [];

		// To store the Signers created with Publisher Level
		List<PublisherSignerCreator> publisherSigners = [];

		// To store the FileAttributes created using Hash Level
		List<HashCreator> completeHashes = [];

		// To store the file rules created using FilePath Level (including Wildcard Path rules)
		List<FilePathCreator> filePaths = [];

		// To store the PackageFamilyName rules using the PFN Level
		List<PFNRuleCreator> pfnRules = [];

		// Lists to separate data initially
		List<FileIdentity> signedWHQLFilePublisherData = [];
		List<FileIdentity> signedFilePublisherData = [];
		List<FileIdentity> signedPublisherData = [];
		List<FileIdentity> unsignedData = [];
		List<FileIdentity> filePathData = [];
		IReadOnlyCollection<string> wildCardFilePathData = [];
		List<string> PFNs = [];
		HashSet<string> customPatternBasedFileRules = [];

		Logger.Write(GlobalVars.GetStr("BuildSignerDataSeparationStartMessage"));

		// Data separation based on the level
		switch (level)
		{
			// If Hash level is used then add everything to the Unsigned data so Hash rules will be created for them
			case ScanLevels.Hash:
				{

					Logger.Write(GlobalVars.GetStr("BuildSignerHashLevelMessage"));

					if (data is not null)
					{
						// Assign the entire data to the unsigned Data list
						unsignedData = data;
					}

					break;
				}
			// If Publisher level is used then add all Signed data to the SignedPublisherData list and Unsigned data to the Hash list
			case ScanLevels.Publisher:
				{

					if (data is not null)
					{

						Logger.Write(GlobalVars.GetStr("BuildSignerPublisherHashLevelsMessage"));

						foreach (FileIdentity item in data)
						{
							// If the current data is signed and publisherToHash is not used, which would indicate Hash level rules must be created for Publisher level data
							// And make sure the file is not ECC Signed
							if (item.SignatureStatus is SignatureStatus.IsSigned && !publisherToHash && item.IsECCSigned != true)
							{
								signedPublisherData.Add(item);
							}
							else
							{
								// Assign the data to the Hash list
								unsignedData.Add(item);
							}
						}
					}
					break;
				}
			case ScanLevels.FilePublisher:
				{

					if (data is not null)
					{

						// Detect and separate FilePublisher, Publisher and Hash (Unsigned) data if the level is Auto or FilePublisher

						Logger.Write(GlobalVars.GetStr("BuildSignerFilePublisherLevelsMessage"));

						// Loop over each data
						foreach (FileIdentity item in data)
						{
							// If the file's version is empty or it has no file attribute, then add it to the Publishers array
							// because FilePublisher rule cannot be created for it
							if (item.SignatureStatus is SignatureStatus.IsSigned && item.IsECCSigned != true)
							{
								// Get values from the item and check for null, empty or whitespace
								bool hasNoFileAttributes = string.IsNullOrWhiteSpace(item.OriginalFileName) &&
															string.IsNullOrWhiteSpace(item.InternalName) &&
															string.IsNullOrWhiteSpace(item.FileDescription) &&
															string.IsNullOrWhiteSpace(item.ProductName);

								bool hasNoFileVersion = item.FileVersion is null;

								if (hasNoFileAttributes || hasNoFileVersion)
								{
									// if PublisherToHash is not used then add it to the Publisher array normally
									if (!publisherToHash)
									{
										signedPublisherData.Add(item);
									}
									else
									{
										Logger.Write(string.Format(GlobalVars.GetStr("BuildSignerPublisherToHashMessage"), item.FilePath));
										// Add the current signed data to Unsigned data array so that Hash rules will be created for it instead
										unsignedData.Add(item);
									}
								}
								else
								{
									// If the file has the required info for a FilePublisher rule level creation, add the data to the FilePublisher list
									signedFilePublisherData.Add(item);
								}
							}
							else
							{
								// Add the data to the Hash list
								unsignedData.Add(item);
							}
						}
					}
					break;
				}
			case ScanLevels.WHQLFilePublisher:
				{

					if (data is not null)
					{

						// Detect and separate WHQLFilePublisher, FilePublisher, Publisher and Hash (Unsigned) data

						Logger.Write(GlobalVars.GetStr("BuildSignerWHQLFilePublisherLevelsMessage"));

						// Loop over each data
						foreach (FileIdentity item in data)
						{

							// It can be WHQLFilePublisher, FilePublisher, Publisher at this point
							if (item.SignatureStatus is SignatureStatus.IsSigned && item.IsECCSigned != true)
							{
								// Get values from the item and check for null, empty or whitespace
								bool hasNoFileAttributes = string.IsNullOrWhiteSpace(item.OriginalFileName) &&
															string.IsNullOrWhiteSpace(item.InternalName) &&
															string.IsNullOrWhiteSpace(item.FileDescription) &&
															string.IsNullOrWhiteSpace(item.ProductName);

								bool hasNoFileVersion = item.FileVersion is null;

								// If the file's version is empty or it has no file attribute, then add it to the Publishers array
								// because WHQLFilePublisher/FilePublisher rules cannot be created for it
								if (hasNoFileAttributes || hasNoFileVersion)
								{
									// if PublisherToHash is not used then add it to the Publisher array normally
									if (!publisherToHash)
									{
										signedPublisherData.Add(item);
									}
									else
									{
										Logger.Write(string.Format(GlobalVars.GetStr("BuildSignerPublisherToHashMessage"), item.FilePath));
										// Add the current signed data to Unsigned data array so that Hash rules will be created for it instead
										unsignedData.Add(item);
									}
								}
								// If the file has the required info for a WHQL/FilePublisher rule level creation
								else
								{
									// Check for WHQLFilePublisher eligibility
									if (item.HasWHQLSigner == true)
									{
										signedWHQLFilePublisherData.Add(item);
									}
									// FilePublisher level
									else
									{
										signedFilePublisherData.Add(item);
									}
								}
							}
							else
							{
								// Add the data to the Hash list
								unsignedData.Add(item);
							}
						}
					}
					break;
				}
			case ScanLevels.FilePath:
				{
					if (data is not null)
					{
						filePathData = data;
					}
					break;
				}

			case ScanLevels.WildCardFolderPath:
				{
					if (folderPaths is not null)
					{
						wildCardFilePathData = folderPaths;
					}
					break;
				}

			case ScanLevels.CustomFileRulePattern:
				{
					if (customFileRulePatterns is not null)
					{
						customPatternBasedFileRules = customFileRulePatterns;
					}
					break;
				}

			case ScanLevels.PFN:
				{
					if (packageFamilyNames is not null)
					{
						PFNs = packageFamilyNames;
					}
					break;
				}

			default:

				break;
		}

		Logger.Write(string.Format(GlobalVars.GetStr("BuildSignerWHQLFilePublisherRulesCountMessage"), signedWHQLFilePublisherData.Count));
		Logger.Write(string.Format(GlobalVars.GetStr("BuildSignerFilePublisherRulesCountMessage"), signedFilePublisherData.Count));
		Logger.Write(string.Format(GlobalVars.GetStr("BuildSignerPublisherRulesCountMessage"), signedPublisherData.Count));
		Logger.Write(string.Format(GlobalVars.GetStr("BuildSignerHashRulesCountMessage"), unsignedData.Count));
		Logger.Write(string.Format(GlobalVars.GetStr("BuildSignerFilePathRulesCountMessage"), filePathData.Count));
		Logger.Write(string.Format(GlobalVars.GetStr("BuildSignerWildCardFilePathRulesCountMessage"), wildCardFilePathData.Count));
		Logger.Write(string.Format(GlobalVars.GetStr("BuildSignerPFNRulesCountMessage"), PFNs.Count));


		Logger.Write(GlobalVars.GetStr("BuildSignerProcessingWHQLFilePublisherMessage"));

		foreach (FileIdentity signedData in signedWHQLFilePublisherData)
		{
			// Create a new WHQLFilePublisherSignerCreator object
			WHQLFilePublisherSignerCreator currentWHQLFilePublisherSigner = new(
				fileVersion: signedData.FileVersion,
				fileDescription: signedData.FileDescription,
				internalName: signedData.InternalName,
				originalFileName: signedData.OriginalFileName,
				productName: signedData.ProductName,
				fileName: signedData.FilePath,
				authenticodeSHA256: signedData.SHA256Hash,
				authenticodeSHA1: signedData.SHA1Hash,
				siSigningScenario: signedData.SISigningScenario,
				packageFamilyName: signedData.PackageFamilyName,
				certificateDetails: [],
				opus: signedData.Opus
				);

			// Loop through each correlated event and process the certificate details
			foreach (FileSignerInfo corDataValue in signedData.FileSignerInfos)
			{

				// We only need WHQL Signers
				if (corDataValue.IsWHQL != true) continue;

				// If the file doesn't have Issuer TBS hash (aka Intermediate certificate hash), use the leaf cert's TBS hash and CN instead (aka publisher TBS hash)
				// This is according to the ConfigCI's workflow when encountering specific files
				// MDE doesn't generate Issuer TBS hash for some files
				// For those files, the FilePublisher rule will be created with the file's leaf Certificate details only (Publisher certificate)

				string? issuerTBSHash = corDataValue.IssuerTBSHash;
				string? publisherTBSHash = corDataValue.PublisherTBSHash;

				// currentCorData to store the current SignerInfo/Correlated
				CertificateDetailsCreator? currentCorData;

				if (string.IsNullOrWhiteSpace(issuerTBSHash) && !string.IsNullOrWhiteSpace(publisherTBSHash))
				{
					Logger.Write(string.Format(GlobalVars.GetStr("BuildSignerIntermediateCertEmptyMessage"), signedData.FilePath));

					currentCorData = new CertificateDetailsCreator(
						corDataValue.PublisherTBSHash!,
						corDataValue.PublisherName!,
						corDataValue.PublisherTBSHash!,
						corDataValue.PublisherName!
					);

				}
				else
				{
					currentCorData = new CertificateDetailsCreator(
						corDataValue.IssuerTBSHash!,
						corDataValue.IssuerName!,
						corDataValue.PublisherTBSHash!,
						corDataValue.PublisherName!
					);
				}

				// Add the Certificate details to the CurrentFilePublisherSigner's CertificateDetails property
				currentWHQLFilePublisherSigner.CertificateDetails.Add(currentCorData);

			}

			// Add the completed FilePublisherSigner to the list
			whqlFilePublisherSigners.Add(currentWHQLFilePublisherSigner);
		}

		Logger.Write(GlobalVars.GetStr("BuildSignerProcessingFilePublisherMessage"));

		foreach (FileIdentity signedData in signedFilePublisherData)
		{
			// Create a new FilePublisherSignerCreator object
			FilePublisherSignerCreator currentFilePublisherSigner = new(
				fileVersion: signedData.FileVersion,
				fileDescription: signedData.FileDescription,
				internalName: signedData.InternalName,
				originalFileName: signedData.OriginalFileName,
				productName: signedData.ProductName,
				fileName: signedData.FilePath,
				authenticodeSHA256: signedData.SHA256Hash,
				authenticodeSHA1: signedData.SHA1Hash,
				siSigningScenario: signedData.SISigningScenario,
				packageFamilyName: signedData.PackageFamilyName,
				certificateDetails: []
				);

			// Loop through each correlated event and process the certificate details
			foreach (FileSignerInfo corDataValue in signedData.FileSignerInfos)
			{

				// If the file doesn't have Issuer TBS hash (aka Intermediate certificate hash), use the leaf cert's TBS hash and CN instead (aka publisher TBS hash)
				// This is according to the ConfigCI's workflow when encountering specific files
				// MDE doesn't generate Issuer TBS hash for some files
				// For those files, the FilePublisher rule will be created with the file's leaf Certificate details only (Publisher certificate)

				string? issuerTBSHash = corDataValue.IssuerTBSHash;
				string? publisherTBSHash = corDataValue.PublisherTBSHash;

				// currentCorData to store the current SignerInfo/Correlated
				CertificateDetailsCreator? currentCorData;

				if (string.IsNullOrWhiteSpace(issuerTBSHash) && !string.IsNullOrWhiteSpace(publisherTBSHash))
				{
					Logger.Write(string.Format(GlobalVars.GetStr("BuildSignerIntermediateCertEmptyMessage"), signedData.FilePath));

					currentCorData = new CertificateDetailsCreator(
						corDataValue.PublisherTBSHash!,
						corDataValue.PublisherName!,
						corDataValue.PublisherTBSHash!,
						corDataValue.PublisherName!
					);

				}
				else
				{
					currentCorData = new CertificateDetailsCreator(
						corDataValue.IssuerTBSHash!,
						corDataValue.IssuerName!,
						corDataValue.PublisherTBSHash!,
						corDataValue.PublisherName!
					);
				}

				// Add the Certificate details to the CurrentFilePublisherSigner's CertificateDetails property
				currentFilePublisherSigner.CertificateDetails.Add(currentCorData);

			}

			// Add the completed FilePublisherSigner to the list
			filePublisherSigners.Add(currentFilePublisherSigner);
		}


		Logger.Write(GlobalVars.GetStr("BuildSignerProcessingPublisherMessage"));

		foreach (FileIdentity signedData in signedPublisherData)
		{

			// Create a new PublisherSignerCreator object
			PublisherSignerCreator currentPublisherSigner = new(
				fileName: signedData.FilePath,
				authenticodeSHA1: signedData.SHA1Hash,
				authenticodeSHA256: signedData.SHA256Hash,
				siSigningScenario: signedData.SISigningScenario,
				certificateDetails: []
				);

			// Process each correlated event
			foreach (FileSignerInfo corDataValue in signedData.FileSignerInfos)
			{

				string? issuerTBSHash = corDataValue.IssuerTBSHash;
				string? issuerName = corDataValue.IssuerName;
				string? publisherTBSHash = corDataValue.PublisherTBSHash;
				string? publisherName = corDataValue.PublisherName;

				CertificateDetailsCreator? currentCorData;

				if (string.IsNullOrWhiteSpace(issuerTBSHash) && !string.IsNullOrWhiteSpace(publisherTBSHash))
				{
					Logger.Write(string.Format(GlobalVars.GetStr("BuildSignerIntermediateCertEmptyMessage"), signedData.FilePath));

					// Create a new CertificateDetailsCreator object with the retrieved and used values
					currentCorData = new CertificateDetailsCreator(
						publisherTBSHash,
						publisherName!,
						publisherTBSHash,
						publisherName!
					);
				}
				else
				{
					// Create a new CertificateDetailsCreator object with the retrieved and used values
					currentCorData = new CertificateDetailsCreator(
						issuerTBSHash!,
						issuerName!,
						publisherTBSHash!,
						publisherName!
					);
				}

				// Add the Certificate details to the CurrentPublisherSigner's CertificateDetails property
				currentPublisherSigner.CertificateDetails.Add(currentCorData);
			}

			// Add the completed PublisherSigner to the list
			publisherSigners.Add(currentPublisherSigner);
		}


		Logger.Write(GlobalVars.GetStr("BuildSignerProcessingUnsignedHashMessage"));

		foreach (FileIdentity hashData in unsignedData)
		{

			string? sha256 = hashData.SHA256Hash;
			string? sha1 = hashData.SHA1Hash;
			string? filePath = hashData.FilePath;
			SiPolicyIntel.SSType siSigningScenario = hashData.SISigningScenario;

			if (string.IsNullOrWhiteSpace(sha256) || string.IsNullOrWhiteSpace(sha1) || string.IsNullOrWhiteSpace(filePath))
			{
				Logger.Write(GlobalVars.GetStr("BuildSignerNullPropertiesMessage"));
				continue;
			}

			completeHashes.Add(new HashCreator(
				authenticodeSHA256: sha256,
				authenticodeSHA1: sha1,
				filePath: filePath,
				fileName: hashData.FileName,
				siSigningScenario: siSigningScenario
			));
		}

		Logger.Write(GlobalVars.GetStr("BuildSignerProcessingFilePathMessage"));

		foreach (FileIdentity item in filePathData)
		{
			if (!string.IsNullOrWhiteSpace(item.FilePath))
			{
				filePaths.Add(new FilePathCreator(
					item.FilePath,
					"0.0.0.0", // Minimum version of all files allowed by path
					item.SISigningScenario
					));
			}
		}

		Logger.Write(GlobalVars.GetStr("BuildSignerProcessingWildCardFilePathMessage"));

		foreach (string item in wildCardFilePathData)
		{

			// Create wildcard path - If user selected a root of a drive then do not add the extra backslash otherwise we'd create an invalid path such as "D:\\*" in the policy
			string wildcardPath = DriveLetters.Any(x => string.Equals(x, item[..^1], StringComparison.OrdinalIgnoreCase)) ? item + "*" : item + @"\" + "*";

			// FilePath rules can only be used for User-Mode files only
			// Plus we wouldn't know if the folder contains user-mode or kernel-mode files
			filePaths.Add(new FilePathCreator(
				wildcardPath,
				"0.0.0.0", // Minimum version of all files allowed by path
				SiPolicyIntel.SSType.UserMode
				));
		}

		Logger.Write(GlobalVars.GetStr("BuildSignerProcessingCustomPatternMessage"));

		foreach (string item in customPatternBasedFileRules)
		{

			// FilePath rules can only be used for User-Mode files only
			// Using whatever user entered as is.
			filePaths.Add(new FilePathCreator(
				item,
				"0.0.0.0", // Minimum version of all files allowed by path
				SiPolicyIntel.SSType.UserMode
				));
		}

		Logger.Write(GlobalVars.GetStr("BuildSignerProcessingPFNMessage"));

		foreach (string item in PFNs)
		{
			pfnRules.Add(new PFNRuleCreator(
				item,
				"0.0.0.0", // Minimum version of the app allowed by PFN
				SiPolicyIntel.SSType.UserMode
				));
		}

		Logger.Write(GlobalVars.GetStr("BuildSignerCompletedMessage"));

		return new FileBasedInfoPackage(whqlFilePublisherSigners, filePublisherSigners, publisherSigners, completeHashes, filePaths, pfnRules);
	}
}
