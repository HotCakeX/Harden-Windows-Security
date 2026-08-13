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
using System.Runtime.InteropServices;
using AppControlManager.Others;
using CommonCore.IntelGathering;

namespace AppControlManager.XMLOps;

#pragma warning disable IDE0010

internal static class SignerAndHashBuilder
{
	// Get all of the drive letters on the system
	private static readonly HashSet<string?> DriveLetters = DriveLetterMapper.GetGlobalRootDrives().Select(x => x.DriveLetter).ToHashSet(StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// Creates Signer and Hash objects from the input data
	///
	/// FilePublisher rules are created for files that have the necessary details for a FilePublisher rule.
	/// Publisher rules are created for files that don't have the necessary details for a FilePublisher rule.
	/// Hash rules can be created for both unsigned or signed data, depending on what the selected level or fallback level(s) are.
	///
	/// The output is a single object with nested properties for the Signed data and Hashes
	///
	/// Both Publisher and FilePublisher signers first check if the file has both Issuer and Publisher TBS hashes, if they are present then both of them will be used to create the Signer.
	/// If the file is missing the Issuer TBS hash, then the Publisher certificate will be used for both Publisher and Issuer details (TBS and Name)
	/// This will essentially create the Signers based on LeafCertificate Level.
	///
	/// The NewFilePublisherLevelRules class and NewPublisherLevelRules class both are able to create rules based on different signer App Control levels.
	///
	/// The other way around, where Publisher TBS hash is missing but Issuer TBS is present, would create a PCACertificate level Signer, but that is not implemented yet.
	/// Its use case is not clear yet and there haven't been any files with that condition yet.
	/// </summary>
	/// <param name="data">The Data to be processed. These are the logs selected by the user and contain both signed and unsigned data.</param>
	/// <param name="level"><see cref="ScanLevels"/></param>
	/// <param name="publisherToHash">It will pass any publisher rules to the hash array. E.g., when sandboxing-like behavior using Macros and AppIDs are used.</param>
	/// <param name="fallbackLevels">The fallback levels to try, in order, when the primary level cannot be used for a file. Default levels are used when this is null.</param>
	internal static FileBasedInfoPackage BuildSignerAndHashObjects(
	List<FileIdentity>? data = null,
	IReadOnlyCollection<string>? folderPaths = null,
	HashSet<string>? customFileRulePatterns = null,
	ScanLevels level = ScanLevels.WHQLFilePublisher,
	bool publisherToHash = false,
	List<string>? packageFamilyNames = null,
	List<ScanLevels>? fallbackLevels = null)
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

		// To store the FileName rules for the FileName Level
		List<FileNameRuleCreator> fileNameRules = [];

		// Lists to separate data initially
		List<FileIdentity> signedWHQLFilePublisherData = [];
		List<FileIdentity> signedFilePublisherData = [];
		List<FileIdentity> signedPublisherData = [];
		List<FileIdentity> hashRuleData = [];
		List<FileIdentity> filePathData = [];
		IReadOnlyCollection<string> wildCardFilePathData = [];
		List<string> PFNs = [];
		HashSet<string> customPatternBasedFileRules = [];
		List<FileIdentity> fileNameData = [];

		Logger.Write(Atlas.GetStr("BuildSignerDataSeparationStartMessage"));

		// Data separation based on the level
		switch (level)
		{
			// All FileIdentities have Hash so we don't need to consider fallback for this level.
			case ScanLevels.Hash:
				{
					Logger.Write(Atlas.GetStr("BuildSignerHashLevelMessage"));

					if (data is not null)
					{
						// Assign the entire data to the unsigned Data list
						hashRuleData = data;
					}

					break;
				}
			// All FileIdentities have path so we don't need to consider fallback for this level.
			case ScanLevels.FilePath:
				{
					if (data is not null)
					{
						filePathData = data;
					}
					break;
				}
			// Everything passed to this method for WildCardFolderPath level already has the required data so we don't need to consider fallback for this level.
			case ScanLevels.WildCardFolderPath:
				{
					if (folderPaths is not null)
					{
						wildCardFilePathData = folderPaths;
					}
					break;
				}
			// Everything passed to this method for CustomFileRulePattern level already has the required data so we don't need to consider fallback for this level.
			case ScanLevels.CustomFileRulePattern:
				{
					if (customFileRulePatterns is not null)
					{
						customPatternBasedFileRules = customFileRulePatterns;
					}
					break;
				}
			// Everything passed to this method for PFN level already has the required data so we don't need to consider fallback for this level.
			case ScanLevels.PFN:
				{
					if (packageFamilyNames is not null)
					{
						PFNs = packageFamilyNames;
					}
					break;
				}
			// Handle other levels. Fallbacks participate here.
			default:
				{
					if (data is null)
						break;

					// Use the caller-supplied fallback order when present (when calls are from the UI elements such as in ViewModels).
					// Otherwise, preserve the default fallbacks for the selected primary level,
					// Because not all calls to this method come from the UI, some are from internal functions so they need to use the default fallbacks.
					List<ScanLevels> configuredFallbackLevels = fallbackLevels ?? ScanLevelFallbackCatalog.GetDefaultLevels(level);
					List<ScanLevels> levelsToTry = new(1 + configuredFallbackLevels.Count) { level };

					// Do not try the primary level twice or process duplicate fallback levels.
					// We don't use HashSet here because order is important to enforce the fallback levels.
					foreach (ScanLevels fallbackLevel in configuredFallbackLevels)
					{
						if (fallbackLevel != level && !levelsToTry.Contains(fallbackLevel))
							levelsToTry.Add(fallbackLevel);
					}

					// Loop over each data item
					foreach (FileIdentity item in CollectionsMarshal.AsSpan(data))
					{
						// Get values from the item and check for null, empty or whitespace.
						// Makes the current FileIdentity eligible for these levels: FilePublisher, WHQLFilePublisher, FileName
						bool hasNoFileAttributes = string.IsNullOrWhiteSpace(item.OriginalFileName) &&
													string.IsNullOrWhiteSpace(item.InternalName) &&
													string.IsNullOrWhiteSpace(item.FileDescription) &&
													string.IsNullOrWhiteSpace(item.ProductName);

						// Makes the current FileIdentity eligible for these levels: FilePublisher, WHQLFilePublisher, FileName
						bool hasNoFileVersion = item.FileVersion is null;

						// Makes the current FileIdentity eligible for these levels: FilePublisher, WHQLFilePublisher, Publisher
						bool isSigned = item.SignatureStatus is SignatureStatus.IsSigned && item.IsECCSigned != true;

						// Try the primary level followed by each configured fallback level. The first eligible level claims the item.
						foreach (ScanLevels candidateLevel in CollectionsMarshal.AsSpan(levelsToTry))
						{
							bool levelAssigned = false;

							switch (candidateLevel)
							{
								case ScanLevels.WHQLFilePublisher:
									{
										// A WHQLFilePublisher rule requires a signed, non-ECC file with
										// the necessary file attributes, file version and a WHQL signer.
										if (isSigned && !hasNoFileAttributes && !hasNoFileVersion && item.HasWHQLSigner == true)
										{
											signedWHQLFilePublisherData.Add(item);
											levelAssigned = true;
										}
										break;
									}
								case ScanLevels.FilePublisher:
									{
										// A FilePublisher rule requires a signed, non-ECC file with the
										// necessary file attributes and file version.
										if (isSigned && !hasNoFileAttributes && !hasNoFileVersion)
										{
											signedFilePublisherData.Add(item);
											levelAssigned = true;
										}
										break;
									}
								case ScanLevels.Publisher:
									{
										// A Publisher rule required a signed, non-ECC file
										// PublisherToHash prevents Publisher rules so processing can continue
										// to a later configured fallback, normally Hash if defined by user.
										if (isSigned && !publisherToHash)
										{
											signedPublisherData.Add(item);
											levelAssigned = true;
										}
										break;
									}
								case ScanLevels.Hash:
									{
										// Hash rules can be created for both signed and unsigned files, so no additional checks are needed.
										hashRuleData.Add(item);
										levelAssigned = true;

										break;
									}
								case ScanLevels.FileName:
									{
										// A FileName rule requires at least one file attribute and a file version.
										if (!hasNoFileAttributes && !hasNoFileVersion)
										{
											fileNameData.Add(item);
											levelAssigned = true;
										}
										break;
									}
								case ScanLevels.FilePath:
									{
										// FilePath fallback rules can be created for all files.
										filePathData.Add(item);
										levelAssigned = true;
										break;
									}
							}

							if (levelAssigned)
								break;
						}
					}
					break;
				}
		}

		if (signedWHQLFilePublisherData.Count > 0)
			Logger.Write(string.Format(Atlas.GetStr("BuildSignerWHQLFilePublisherRulesCountMessage"), signedWHQLFilePublisherData.Count));

		if (signedFilePublisherData.Count > 0)
			Logger.Write(string.Format(Atlas.GetStr("BuildSignerFilePublisherRulesCountMessage"), signedFilePublisherData.Count));

		if (signedPublisherData.Count > 0)
			Logger.Write(string.Format(Atlas.GetStr("BuildSignerPublisherRulesCountMessage"), signedPublisherData.Count));

		if (hashRuleData.Count > 0)
			Logger.Write(string.Format(Atlas.GetStr("BuildSignerHashRulesCountMessage"), hashRuleData.Count));

		if (filePathData.Count > 0)
			Logger.Write(string.Format(Atlas.GetStr("BuildSignerFilePathRulesCountMessage"), filePathData.Count));

		if (wildCardFilePathData.Count > 0)
			Logger.Write(string.Format(Atlas.GetStr("BuildSignerWildCardFilePathRulesCountMessage"), wildCardFilePathData.Count));

		if (PFNs.Count > 0)
			Logger.Write(string.Format(Atlas.GetStr("BuildSignerPFNRulesCountMessage"), PFNs.Count));

		if (fileNameData.Count > 0)
			Logger.Write(string.Format(Atlas.GetStr("BuildSignerFileNameRulesCountMessage"), fileNameData.Count));


		Logger.Write(Atlas.GetStr("BuildSignerProcessingWHQLFilePublisherMessage"));

		foreach (FileIdentity signedData in CollectionsMarshal.AsSpan(signedWHQLFilePublisherData))
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
				certificateDetails: []
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

				// currentCorData to store the current SignerInfo/Correlated
				WHQLCertificateDetailsCreator currentCorData;

				if (string.IsNullOrWhiteSpace(corDataValue.OPUSInfo))
					throw new InvalidOperationException("Cannot create WHQL signer with empty CertOEMID!");

				if (string.IsNullOrWhiteSpace(corDataValue.IssuerTBSHash) && !string.IsNullOrWhiteSpace(corDataValue.PublisherTBSHash))
				{
					Logger.Write(string.Format(Atlas.GetStr("BuildSignerIntermediateCertEmptyMessage"), signedData.FilePath));

					currentCorData = new WHQLCertificateDetailsCreator(
						corDataValue.PublisherTBSHash,
						corDataValue.PublisherName!,
						corDataValue.PublisherTBSHash,
						corDataValue.PublisherName!,
						opus: corDataValue.OPUSInfo
					);
				}
				else
				{
					currentCorData = new WHQLCertificateDetailsCreator(
						corDataValue.IssuerTBSHash!,
						corDataValue.IssuerName!,
						corDataValue.PublisherTBSHash!,
						corDataValue.PublisherName!,
						opus: corDataValue.OPUSInfo
					);
				}

				// Add the Certificate details to the CurrentFilePublisherSigner's CertificateDetails property
				currentWHQLFilePublisherSigner.CertificateDetails.Add(currentCorData);
			}

			// Add the completed FilePublisherSigner to the list
			whqlFilePublisherSigners.Add(currentWHQLFilePublisherSigner);
		}

		Logger.Write(Atlas.GetStr("BuildSignerProcessingFilePublisherMessage"));

		foreach (FileIdentity signedData in CollectionsMarshal.AsSpan(signedFilePublisherData))
		{
			// Create a new FilePublisherSignerCreator object
			FilePublisherSignerCreator currentFilePublisherSigner = new(
				fileVersion: signedData.FileVersion,
				fileDescription: signedData.FileDescription,
				internalName: signedData.InternalName,
				originalFileName: signedData.OriginalFileName,
				productName: signedData.ProductName,
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

				// currentCorData to store the current SignerInfo/Correlated
				CertificateDetailsCreator currentCorData;

				if (string.IsNullOrWhiteSpace(corDataValue.IssuerTBSHash) && !string.IsNullOrWhiteSpace(corDataValue.PublisherTBSHash))
				{
					Logger.Write(string.Format(Atlas.GetStr("BuildSignerIntermediateCertEmptyMessage"), signedData.FilePath));

					currentCorData = new CertificateDetailsCreator(
						corDataValue.PublisherTBSHash,
						corDataValue.PublisherName!,
						corDataValue.PublisherTBSHash,
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


		Logger.Write(Atlas.GetStr("BuildSignerProcessingPublisherMessage"));

		foreach (FileIdentity signedData in CollectionsMarshal.AsSpan(signedPublisherData))
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

				CertificateDetailsCreator currentCorData;

				if (string.IsNullOrWhiteSpace(issuerTBSHash) && !string.IsNullOrWhiteSpace(publisherTBSHash))
				{
					Logger.Write(string.Format(Atlas.GetStr("BuildSignerIntermediateCertEmptyMessage"), signedData.FilePath));

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


		Logger.Write(Atlas.GetStr("BuildSignerProcessingUnsignedHashMessage"));

		foreach (FileIdentity hashData in CollectionsMarshal.AsSpan(hashRuleData))
		{
			if (string.IsNullOrWhiteSpace(hashData.SHA256Hash) || string.IsNullOrWhiteSpace(hashData.SHA1Hash) || string.IsNullOrWhiteSpace(hashData.FilePath))
			{
				Logger.Write(Atlas.GetStr("BuildSignerNullPropertiesMessage"));
				continue;
			}

			completeHashes.Add(new HashCreator(
				authenticodeSHA256: hashData.SHA256Hash,
				authenticodeSHA1: hashData.SHA1Hash,
				filePath: hashData.FilePath,
				fileName: hashData.FileName,
				siSigningScenario: hashData.SISigningScenario
			));
		}

		Logger.Write(Atlas.GetStr("BuildSignerProcessingFilePathMessage"));

		foreach (FileIdentity item in CollectionsMarshal.AsSpan(filePathData))
		{
			if (!string.IsNullOrWhiteSpace(item.FilePath))
			{
				filePaths.Add(new FilePathCreator(
					item.FilePath,
					"0.0.0.0", // Minimum version of all files allowed by path
					SSType.UserMode
					));
			}
		}

		Logger.Write(Atlas.GetStr("BuildSignerProcessingWildCardFilePathMessage"));

		foreach (string item in wildCardFilePathData)
		{
			// Create wildcard path - If user selected a root of a drive then do not add the extra backslash otherwise we'd create an invalid path such as "D:\\*" in the policy
			string wildcardPath = DriveLetters.Contains(item[..^1]) ? item + "*" : item + @"\" + "*";

			// FilePath rules can only be used for User-Mode files only
			// Plus we wouldn't know if the folder contains user-mode or kernel-mode files
			filePaths.Add(new FilePathCreator(
				wildcardPath,
				"0.0.0.0", // Minimum version of all files allowed by path
				SSType.UserMode
				));
		}

		Logger.Write(Atlas.GetStr("BuildSignerProcessingCustomPatternMessage"));

		foreach (string item in customPatternBasedFileRules)
		{
			// FilePath rules can only be used for User-Mode files only
			// Using whatever the user entered as is.
			filePaths.Add(new FilePathCreator(
				item,
				"0.0.0.0", // Minimum version of all files allowed by path
				SSType.UserMode
				));
		}

		Logger.Write(Atlas.GetStr("BuildSignerProcessingPFNMessage"));

		foreach (string item in CollectionsMarshal.AsSpan(PFNs))
		{
			pfnRules.Add(new PFNRuleCreator(
				item,
				"0.0.0.0", // Minimum version of the app allowed by PFN
				SSType.UserMode
				));
		}

		Logger.Write(Atlas.GetStr("BuildSignerProcessingFileNameMessage"));

		foreach (FileIdentity item in CollectionsMarshal.AsSpan(fileNameData))
		{
			fileNameRules.Add(new FileNameRuleCreator(
				fileVersion: item.FileVersion,
				fileDescription: item.FileDescription,
				internalName: item.InternalName,
				originalFileName: item.OriginalFileName,
				productName: item.ProductName,
				siSigningScenario: item.SISigningScenario
				));
		}

		Logger.Write(Atlas.GetStr("BuildSignerCompletedMessage"));

		return new FileBasedInfoPackage(whqlFilePublisherSigners, filePublisherSigners, publisherSigners, completeHashes, filePaths, pfnRules, fileNameRules);
	}
}
