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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AppControlManager.IntelGathering;
using AppControlManager.Others;

namespace AppControlManager.SimulationMethods;

internal static class Arbitrator
{

	// An array of SpecificFileNames
	private static readonly string[] specificFileNames = ["OriginalFileName", "InternalName", "ProductName", "Version", "FileDescription"];

	/// <summary>
	/// The method that compares the signer information from the App Control policy XML file with the certificate details of the signed file
	/// </summary>
	/// <param name="simulationInput">The SimulationInput object that contains the necessary information for the simulation</param>
	/// <returns></returns>
	internal static SimulationOutput Compare(SimulationInput simulationInput)
	{
		// Get the extended file attributes
		ExFileInfo ExtendedFileInfo = GetExtendedFileAttrib.Get(simulationInput.FilePath.FullName);

		// Create a dictionary out of the ExtendedFileInfo so we can perform high performance lookups later on in the loops without resorting to reflection
		Dictionary<string, string> ExtendedFileInfoDict = [];

		// Add all properties to the dictionary
		if (ExtendedFileInfo.OriginalFileName is not null) ExtendedFileInfoDict["OriginalFileName"] = ExtendedFileInfo.OriginalFileName;
		if (ExtendedFileInfo.InternalName is not null) ExtendedFileInfoDict["InternalName"] = ExtendedFileInfo.InternalName;
		if (ExtendedFileInfo.ProductName is not null) ExtendedFileInfoDict["ProductName"] = ExtendedFileInfo.ProductName;
		if (ExtendedFileInfo.FileDescription is not null) ExtendedFileInfoDict["FileDescription"] = ExtendedFileInfo.FileDescription;
		if (ExtendedFileInfo.Version is not null) ExtendedFileInfoDict["Version"] = ExtendedFileInfo.Version.ToString();


		// Loop through each signer in the signer information array, these are the signers in the XML policy file
		foreach (SignerX signer in simulationInput.SignerInfo)
		{

			// Make sure it's an allowed signer and not a denier
			if (signer.IsAllowed is not true)
			{
				continue;
			}

			// Logger.Write($"Checking the signer: {signer.Name}");

			// If the signer has any EKUs, try to match it with the file's EKU OIDs
			if (signer.HasEKU)
			{
				Logger.Write(string.Format(GlobalVars.GetStr("CurrentFileHasNEKUs"), simulationInput.FilePath.FullName, simulationInput.EKUOIDs?.Count));

				// Check if any of the Signer's OIDs match any of the file's certificates' OIDs (which are basically Leaf certificates' EKU OIDs)
				// This is used for all levels, not just WHQL levels
				bool EKUsMatch = false;

				foreach (string EKU in signer.CertEKU!)
				{
					if (simulationInput.EKUOIDs is not null && simulationInput.EKUOIDs.Contains(EKU))
					{
						EKUsMatch = true;
						break;
					}
				}

				// If both the file and signer had EKUs and they match
				if (EKUsMatch)
				{

					Logger.Write(string.Format(GlobalVars.GetStr("SignerEKUsMatchedFileEKUs"), signer.Name));

					// If the signer and file have matching EKUs and the signer is WHQL then start checking for OemID
					if (signer.IsWHQL)
					{

						Logger.Write(string.Format(GlobalVars.GetStr("SignerIsWHQL"), signer.Name));

						// At this point the file is definitely WHQL-Signed

						// Get the WHQL chain packages by checking for any chain whose leaf certificate contains the WHQL EKU OID
						List<ChainPackage> WHQLChainPackagesCandidates = [.. simulationInput.AllFileSigners
						  .Where(sig => sig.LeafCertificate is not null &&
						  sig.LeafCertificate.Certificate.Extensions
						  .OfType<X509EnhancedKeyUsageExtension>()
						  .Any(eku => eku.EnhancedKeyUsages.Cast<Oid>()
						  .Any(oid => oid.Value is not null && oid.Value.Contains(LocalFilesScan.WHQLOid, StringComparison.OrdinalIgnoreCase))))];


						// HashSet to store all of the Opus data from the WHQL chain packages candidates
						HashSet<string> Current_Chain_Opus = [];

						// List of OpusSigner objects which are pairs of each Intermediate Certificate TBSHash and its corresponding SubjectCN
						List<OpusSigner> OpusSigners = [];

						// Loop through each candidate WHQL chain package
						foreach (ChainPackage chainPackage in WHQLChainPackagesCandidates)
						{
							List<string> CurrentOpusData = [];

							try
							{
								// Try to get the Opus data of the current chain (essentially the current chain's leaf certificate)
								CurrentOpusData = [.. Opus.GetOpusData(chainPackage.SignedCms).Select(p => p.CertOemID)];
							}
							catch
							{
								Logger.Write(GlobalVars.GetStr("FailedToGetOpusDataCurrentChain"));
							}

							// If there was Opus data
							if (CurrentOpusData.Count > 0)
							{
								foreach (string item in CurrentOpusData)
								{
									// Add the Opus data to the HashSet
									_ = Current_Chain_Opus.Add(item);
								}
							}

							// Capture the details of the WHQL signers, aka Intermediate certificate(s) of the signer package that had WHQL EKU
							// In case there are more than 1 intermediate certificates in the chain, add all of them to the HashSets
							// regardless of whether they have Opus data or not because we'll use these data for the WHQL level too and that level doesn't require Opus data match

							if (chainPackage.IntermediateCertificates is not null)
							{
								foreach (ChainElement IntermediateCert in chainPackage.IntermediateCertificates)
								{
									OpusSigner OS = new(
										IntermediateCert.TBSValue,
											IntermediateCert.SubjectCN
										);

									// Add the current TBSHash and SubjectCN pair of the intermediate certificate to the list
									OpusSigners.Add(OS);
								}
							}
						}

						// Flag indicating if the Opus data of the current signer matched with one of the file's leaf certificates Opus data
						// Making it eligible for WHQLFilePublisher and WHQLPublisher levels
						// if true, CertOemID of the signer matches the EKU Opus data of the file (This should belong to the leaf certificate of the file as it's the one with EKUs)
						bool OpusMatch = signer.CertOemID is not null && Current_Chain_Opus.Contains(signer.CertOemID);

						// Loop through each OpusSigner
						// This is to ensure when a file is signed by more than 1 WHQL signer then it will be properly validated as these are pairs of TBSHash and SubjectCN of each WHQL signer's details
						foreach (OpusSigner opusSigner in OpusSigners)
						{

							// Check if the selected file's signer chain's intermediate certificates match the current signer's details
							if (string.Equals(signer.CertRoot, opusSigner.TBSHash, StringComparison.OrdinalIgnoreCase) &&
								string.Equals(signer.Name, opusSigner.SubjectCN, StringComparison.OrdinalIgnoreCase))
							{
								// At this point the file meets the criteria for one of the WHQL levels

								// Indicating it's WHQLFilePublisher signer
								if (OpusMatch && signer.FileAttrib.Count > 0)
								{

									List<Dictionary<string, string>> CandidateFileAttrib = [];

									foreach (KeyValuePair<string, Dictionary<string, string>> Attrib in signer.FileAttrib)
									{

										if (!Attrib.Value.TryGetValue("MinimumFileVersion", out string? MinimumFileVersion))
										{
											Logger.Write(GlobalVars.GetStr("MinimumFileVersionNullSkipping"));
											continue;
										}

										Version tempVer = new(MinimumFileVersion);

										if (ExtendedFileInfo.Version >= tempVer)
										{
											CandidateFileAttrib.Add(Attrib.Value);
										}
									}

									// Loop over all of the candidate file attributes (if they exists) to find a match with the file's extended info
									if (CandidateFileAttrib.Count > 0)
									{
										foreach (Dictionary<string, string> FileAttrib in CandidateFileAttrib)
										{
											// Loop over each SpecificFileName
											for (int i = 0; i < specificFileNames.Length; i++)
											{
												string keyItem = specificFileNames[i];

												if (ExtendedFileInfoDict.TryGetValue(keyItem, out string? FileInfoProperty) &&
												 FileAttrib.TryGetValue(keyItem, out string? FileAttribProperty) &&
												 string.Equals(FileInfoProperty, FileAttribProperty, StringComparison.OrdinalIgnoreCase))
												{
													// Excessive logging
													// Logger.Write(string.Format(GlobalVars.GetStr("SpecificFileNameLevelIs"), keyItem));

													/*
														If there was a match then assign the keyItem, which is the name of the SpecificFileNameLevel option, to the SpecificFileNameLevelMatchCriteria of the SimulationOutput

														ELIGIBILITY CHECK FOR LEVELS: WHQLFilePublisher

														CRITERIA:
														1) The signer's CertRoot (referring to the TBS value in the xml file which belongs to the intermediate cert of the file signed by Microsoft) Matches the TBSValue of the file's certificate that belongs to Microsoft WHQL program
														2) The signer's name (Referring to the one in the XML file) matches the same Intermediate certificate's SubjectCN, the certificate that belongs to Microsoft WHQL program
														3) The signer's CertEKU points to the WHQL EKU OID and one of the file's leaf certificates contains this EKU OID
														4) The signer's CertOemID matches one of the Opus data of the file's certificates (Leaf certificates as they are the ones with EKUs)
														5) The signer's FileAttribRef(s) point to the same file that is currently being investigated
														*/

													return new SimulationOutput(
														Path.GetFileName(simulationInput.FilePath.ToString()),
														SimulationOutputSource.Signer,
														true,
														signer.ID,
														signer.Name,
														signer.CertRoot,
														signer.CertPublisher,
														signer.SignerScope,
														signer.FileAttribRef,
														"WHQLFilePublisher",
														keyItem,
														opusSigner.SubjectCN,
														null,
														null,
														opusSigner.TBSHash,
														simulationInput.FilePath.ToString()
														);
												}
											}
										}
									}
								}

								/*
									ELIGIBILITY CHECK FOR LEVELS: WHQLPublisher

									CRITERIA:
									1) The signer's CertRoot (referring to the TBS value in the xml file which belongs to the intermediate cert of the file signed by Microsoft) Matches the TBSValue of the file's certificate that belongs to Microsoft WHQL program
									2) The signer's name (Referring to the one in the XML file) matches the same Intermediate certificate's SubjectCN, the certificate that belongs to Microsoft WHQL program
									3) The signer's CertEKU points to the WHQL EKU OID and one of the file's leaf certificates contains this EKU OID
									4) The signer's CertOemID matches one of the Opus data of the file's certificates (Leaf certificates as they are the ones with EKUs)
									*/

								// If the signer has FileAttributes meaning it's either WHQLFilePublisher, FilePublisher or SignedVersion then do not use it for other levels
								else if (OpusMatch && signer.FileAttribRef is null)
								{
									return new SimulationOutput(
										Path.GetFileName(simulationInput.FilePath.ToString()),
										SimulationOutputSource.Signer,
										true,
										signer.ID,
										signer.Name,
										signer.CertRoot,
										signer.CertPublisher,
										signer.SignerScope,
										signer.FileAttribRef,
										"WHQLPublisher",
										null,
										opusSigner.SubjectCN,
										null,
										null,
										opusSigner.TBSHash,
										simulationInput.FilePath.ToString()
										);
								}

								/*
									ELIGIBILITY CHECK FOR LEVELS: WHQL

									CRITERIA:
									1) The signer's CertRoot (referring to the TBS value in the xml file which belongs to the intermediate cert of the file signed by Microsoft) Matches the TBSValue of the file's certificate that belongs to Microsoft WHQL program
									2) The signer's name (Referring to the one in the XML file) matches the same Intermediate certificate's SubjectCN, the certificate that belongs to Microsoft WHQL program
									3) The signer's CertEKU points to the WHQL EKU OID and one of the file's leaf certificates contains this EKU OID
									*/

								else
								{
									// If the signer has FileAttributes meaning it's either WHQLFilePublisher, FilePublisher or SignedVersion then do not use it for other levels
									if (signer.FileAttrib.Count > 0)
									{
										continue;
									}

									return new SimulationOutput(
										Path.GetFileName(simulationInput.FilePath.ToString()),
										SimulationOutputSource.Signer,
										true,
										signer.ID,
										signer.Name,
										signer.CertRoot,
										signer.CertPublisher,
										signer.SignerScope,
										signer.FileAttribRef,
										"WHQL",
										null,
										opusSigner.SubjectCN,
										null,
										null,
										opusSigner.TBSHash,
										simulationInput.FilePath.ToString()
										);


								}
							}
						}

						if (EKUsMatch)
						{
							// If the Signer has EKU, it was WHQL EKU (determined early on) but there was no WHQL level match made with the file's properties then skip the current signer
							// as the rest of the levels are not applicable for a WHQL type of signer
							continue;
						}
					}
					//else {
					// If the signer isn't WHQL, just a regular signer with EKU and they matched with the file's EKUs
					// Then do nothing and let the normal rules below handle them
					//  }

				}
				else
				{
					Logger.Write(GlobalVars.GetStr("SignerHadEKUsButNoMatch"));
					// If the signer has EKU but it didn't match with the file's EKU then skip the current signer
					// as it shouldn't be used for any other levels
					continue;
				}
			}

			// Loop through each certificate chain
			foreach (ChainPackage chain in simulationInput.AllFileSigners)
			{

				// If the file has any intermediate certificates
				if (chain.IntermediateCertificates is not null)
				{

					// Loop over each intermediate certificate in the chain
					foreach (ChainElement IntermediateCert in chain.IntermediateCertificates)
					{

						/*
							ELIGIBILITY CHECK FOR LEVELS: FilePublisher, Publisher, SignedVersion

							CRITERIA:
							1) The signer's CertRoot (referring to the TBS value in the xml file which belongs to an intermediate cert of the file) Matches the TBSValue of one of the file's intermediate certificates
							2) The signer's name (Referring to the one in the XML file) matches the same Intermediate certificate's SubjectCN
							3) The signer's CertPublisher (aka Leaf Certificate's CN used in the xml policy) matches the current chain's leaf certificate's SubjectCN
							*/

						if (string.Equals(signer.CertRoot, IntermediateCert.TBSValue, StringComparison.OrdinalIgnoreCase) &&
							string.Equals(signer.Name, IntermediateCert.SubjectCN, StringComparison.OrdinalIgnoreCase) &&
							string.Equals(signer.CertPublisher, chain.LeafCertificate?.SubjectCN, StringComparison.OrdinalIgnoreCase))
						{

							// Check if the matched signer has FileAttrib indicating that it was generated either with FilePublisher or SignedVersion level
							if (signer.FileAttrib.Count > 0)
							{

								// Loop over each <FileAttrib> in the <FileRules> nodes, only those that belong to the Signer
								// Which we retrieved based on the <FileAttribRef> elements under the Signer
								// And only keep those <FileAttrib> where the current file being examined has an equal or higher version than the version in those <FileAttrib> elements

								List<Dictionary<string, string>> CandidateFileAttrib = [];

								foreach (KeyValuePair<string, Dictionary<string, string>> Attrib in signer.FileAttrib)
								{

									_ = Attrib.Value.TryGetValue("MinimumFileVersion", out string? MinimumFileVersion);

									if (MinimumFileVersion is null)
									{
										Logger.Write(GlobalVars.GetStr("MinimumFileVersionNullSkipping"));
										continue;
									}

									Version tempVer = new(MinimumFileVersion);

									if (ExtendedFileInfo.Version >= tempVer)
									{
										CandidateFileAttrib.Add(Attrib.Value);
									}
								}

								// If the signer has a file attribute with a wildcard file name, then it's a SignedVersion level signer
								// These signers have only 1 FileAttribRef and only point to a single FileAttrib
								// Note: If a SignedVersion signer applies to multiple files, the version number of the FileAttrib is set to the minimum version of the files

								if (CandidateFileAttrib.Count > 0)
								{
									// This loop is potentially unnecessary because of the comments above but keeping it for now
									foreach (Dictionary<string, string> dict in CandidateFileAttrib)
									{
										if (dict.TryGetValue("OriginalFileName", out string? originalFileName) && string.Equals(originalFileName, "*", StringComparison.OrdinalIgnoreCase))
										{
											return new SimulationOutput(
											Path.GetFileName(simulationInput.FilePath.ToString()),
											SimulationOutputSource.Signer,
											true,
											signer.ID,
											signer.Name,
											signer.CertRoot,
											signer.CertPublisher,
											signer.SignerScope,
											signer.FileAttribRef,
											"SignedVersion",
											"Version",
											IntermediateCert.SubjectCN,
											IntermediateCert.IssuerCN,
											IntermediateCert.NotAfter.ToString(CultureInfo.InvariantCulture),
											IntermediateCert.TBSValue,
											simulationInput.FilePath.ToString()
											);
										}
									}
								}

								// Loop over all of the candidate file attributes (if they exists) to find a match with the file's extended info
								if (CandidateFileAttrib.Count > 0)
								{

									foreach (Dictionary<string, string> FileAttrib in CandidateFileAttrib)
									{
										// Loop over each SpecificFileName
										for (int i = 0; i < specificFileNames.Length; i++)
										{
											string keyItem = specificFileNames[i];

											if (ExtendedFileInfoDict.TryGetValue(keyItem, out string? FileInfoProperty) &&
											 FileAttrib.TryGetValue(keyItem, out string? FileAttribProperty) &&
											 string.Equals(FileInfoProperty, FileAttribProperty, StringComparison.OrdinalIgnoreCase))
											{
												// Excessive logging
												// Logger.Write(string.Format(GlobalVars.GetStr("SpecificFileNameLevelIs"), keyItem));


												// If there was a match then assign the $KeyItem which is the name of the SpecificFileNameLevel option to the $CurrentFileInfo.SpecificFileNameLevelMatchCriteria
												// And break out of the loop by validating the signer as suitable for FilePublisher level
												return new SimulationOutput(
												Path.GetFileName(simulationInput.FilePath.ToString()),
												SimulationOutputSource.Signer,
												true,
												signer.ID,
												signer.Name,
												signer.CertRoot,
												signer.CertPublisher,
												signer.SignerScope,
												signer.FileAttribRef,
												"FilePublisher",
												keyItem,
												IntermediateCert.SubjectCN,
												IntermediateCert.IssuerCN,
												IntermediateCert.NotAfter.ToString(CultureInfo.InvariantCulture),
												IntermediateCert.TBSValue,
												simulationInput.FilePath.ToString()
												);
											}
										}
									}
								}
							}

							// If the Signer matched and it doesn't have a FileAttrib, then it's a Publisher level signer
							else
							{

								// If the signer has FileAttributes meaning it's either WHQLFilePublisher, FilePublisher or SignedVersion then do not use it for other levels
								if (signer.FileAttribRef.Count > 0)
								{
									continue;
								}

								return new SimulationOutput(
									 Path.GetFileName(simulationInput.FilePath.ToString()),
									 SimulationOutputSource.Signer,
									 true,
									 signer.ID,
									 signer.Name,
									 signer.CertRoot,
									 signer.CertPublisher,
									 signer.SignerScope,
									 signer.FileAttribRef,
									 "Publisher",
									 null,
									 IntermediateCert.SubjectCN,
									 IntermediateCert.IssuerCN,
									 IntermediateCert.NotAfter.ToString(CultureInfo.InvariantCulture),
									 IntermediateCert.TBSValue,
									 simulationInput.FilePath.ToString()
									 );
							}
						}

						/*
							ELIGIBILITY CHECK FOR LEVELS: PcaCertificate, RootCertificate

							CRITERIA:
							1) The signer's CertRoot (referring to the TBS value in the xml file which belongs to an intermediate cert of the file) Matches the TBSValue of one of the file's intermediate certificates
							2) The signer's name (Referring to the one in the XML file) matches the same Intermediate certificate's SubjectCN
							*/

						else if (string.Equals(signer.CertRoot, IntermediateCert.TBSValue, StringComparison.OrdinalIgnoreCase) &&
							string.Equals(signer.Name, IntermediateCert.SubjectCN, StringComparison.OrdinalIgnoreCase))
						{

							// If the signer has FileAttributes meaning it's either WHQLFilePublisher, FilePublisher or SignedVersion then do not use it for other levels
							if (signer.FileAttribRef.Count > 0)
							{
								continue;
							}

							return new SimulationOutput(
									Path.GetFileName(simulationInput.FilePath.ToString()),
									SimulationOutputSource.Signer,
									true,
									signer.ID,
									signer.Name,
									signer.CertRoot,
									signer.CertPublisher,
									signer.SignerScope,
									signer.FileAttribRef,
									"PcaCertificate/RootCertificate",
									null,
									IntermediateCert.SubjectCN,
									IntermediateCert.IssuerCN,
									IntermediateCert.NotAfter.ToString(CultureInfo.InvariantCulture),
									IntermediateCert.TBSValue,
									simulationInput.FilePath.ToString()
									);
						}
					}

				}

				/*
					ELIGIBILITY CHECK FOR LEVELS: LeafCertificate

					CRITERIA:
					1) The Signer's CertRoot (referring to the TBS value in the xml file, which belongs to the leaf certificate of the file when LeafCertificate level is used) matches the TBSValue of the file's Leaf certificate certificates
					2) The signer's name (Referring to the one in the XML file) matches the Leaf certificate's SubjectCN
					*/

				if (string.Equals(signer.CertRoot, chain.LeafCertificate?.TBSValue, StringComparison.OrdinalIgnoreCase) &&
					string.Equals(signer.Name, chain.LeafCertificate?.SubjectCN, StringComparison.OrdinalIgnoreCase))
				{

					// If the signer has FileAttributes meaning it's either WHQLFilePublisher, FilePublisher or SignedVersion then do not use it for other levels
					if (signer.FileAttribRef.Count > 0)
					{
						continue;
					}

					return new SimulationOutput(
							Path.GetFileName(simulationInput.FilePath.ToString()),
							SimulationOutputSource.Signer,
							true,
							signer.ID,
							signer.Name,
							signer.CertRoot,
							signer.CertPublisher,
							signer.SignerScope,
							signer.FileAttribRef,
							"LeafCertificate",
							null,
							chain.LeafCertificate?.SubjectCN,
							chain.LeafCertificate?.IssuerCN,
							chain.LeafCertificate?.NotAfter.ToString(CultureInfo.InvariantCulture),
							chain.LeafCertificate?.TBSValue,
							simulationInput.FilePath.ToString()
							);
				}


				/*
					Region ROOT CERTIFICATE ELIGIBILITY CHECK

					This is regardless of how many certificates exist in the current chain

					ELIGIBILITY CHECK FOR LEVELS: FilePublisher, Publisher, SignedVersion

					CRITERIA:
					1) The signer's CertRoot (referring to the TBS value in the xml file which belongs to the Root Certificate of the file when there is only 1 Element in the chain) Matches the TBSValue of the file's root certificate
					2) The signer's name (Referring to the one in the XML file) matches the same Root certificate's SubjectCN
					3) The signer's CertPublisher matches the Root certificate's SubjectCN
					*/

				if (string.Equals(signer.CertRoot, chain.RootCertificate.TBSValue, StringComparison.OrdinalIgnoreCase) &&
				   string.Equals(signer.Name, chain.RootCertificate.SubjectCN, StringComparison.OrdinalIgnoreCase) &&
				   string.Equals(signer.CertPublisher, chain.RootCertificate.SubjectCN, StringComparison.OrdinalIgnoreCase))
				{

					// If the signer has FileAttributes meaning it's either WHQLFilePublisher, FilePublisher or SignedVersion then do not use it for other levels
					if (signer.FileAttrib.Count > 0)
					{

						List<Dictionary<string, string>> CandidateFileAttrib = [];

						// Get all of the File Attributes associated with the signer and check if the file's version is greater than or equal to the minimum version in them
						foreach (KeyValuePair<string, Dictionary<string, string>> Attrib in signer.FileAttrib)
						{

							_ = Attrib.Value.TryGetValue("MinimumFileVersion", out string? MinimumFileVersion);

							if (MinimumFileVersion is null)
							{
								Logger.Write(GlobalVars.GetStr("MinimumFileVersionNullSkipping"));
								continue;
							}

							Version tempVer = new(MinimumFileVersion);

							if (ExtendedFileInfo.Version >= tempVer)
							{
								CandidateFileAttrib.Add(Attrib.Value);
							}
						}

						// If the signer has a file attribute with a wildcard file name, then it's a SignedVersion level signer
						// These signers have only 1 FileAttribRef and only point to a single FileAttrib
						// If a SignedVersion signer applies to multiple files, the version number of the FileAttrib is set to the minimum version of the files

						if (CandidateFileAttrib.Count == 1)
						{
							// This loop is potentially unnecessary because of the comments above but keeping it for now
							foreach (Dictionary<string, string> dict in CandidateFileAttrib)
							{
								if (dict.TryGetValue("OriginalFileName", out string? originalFileName) && string.Equals(originalFileName, "*", StringComparison.OrdinalIgnoreCase))
								{

									return new SimulationOutput(
									   Path.GetFileName(simulationInput.FilePath.ToString()),
									   SimulationOutputSource.Signer,
									   true,
									   signer.ID,
									   signer.Name,
									   signer.CertRoot,
									   signer.CertPublisher,
									   signer.SignerScope,
									   signer.FileAttribRef,
									   "SignedVersion",
									   "Version",
									   chain.RootCertificate.SubjectCN,
									   chain.RootCertificate.IssuerCN,
									   chain.RootCertificate.NotAfter.ToString(CultureInfo.InvariantCulture),
									   chain.RootCertificate.TBSValue,
									   simulationInput.FilePath.ToString()
									   );
								}
							}
						}

						// Loop over all of the candidate file attributes (if they exists) to find a match with the file's extended info
						if (CandidateFileAttrib.Count > 0)
						{

							foreach (Dictionary<string, string> FileAttrib in CandidateFileAttrib)
							{
								// Loop over each SpecificFileName
								for (int i = 0; i < specificFileNames.Length; i++)
								{
									string keyItem = specificFileNames[i];

									if (ExtendedFileInfoDict.TryGetValue(keyItem, out string? FileInfoProperty) &&
									 FileAttrib.TryGetValue(keyItem, out string? FileAttribProperty) &&
									 string.Equals(FileInfoProperty, FileAttribProperty, StringComparison.OrdinalIgnoreCase))
									{
										// Excessive logging
										// Logger.Write(string.Format(GlobalVars.GetStr("SpecificFileNameLevelIs"), keyItem));

										// If there was a match then assign the $KeyItem which is the name of the SpecificFileNameLevel option to the $CurrentFileInfo.SpecificFileNameLevelMatchCriteria
										// And break out of the loop by validating the signer as suitable for FilePublisher level

										return new SimulationOutput(
											Path.GetFileName(simulationInput.FilePath.ToString()),
											SimulationOutputSource.Signer,
											true,
											signer.ID,
											signer.Name,
											signer.CertRoot,
											signer.CertPublisher,
											signer.SignerScope,
											signer.FileAttribRef,
											"FilePublisher",
											keyItem,
											chain.RootCertificate.SubjectCN,
											chain.RootCertificate.IssuerCN,
											chain.RootCertificate.NotAfter.ToString(CultureInfo.InvariantCulture),
											chain.RootCertificate.TBSValue,
											simulationInput.FilePath.ToString()
										);
									}
								}
							}
						}
					}

					// If the Signer matched and it doesn't have a FileAttrib, then it's a Publisher level signer
					else
					{
						// If the signer has FileAttributes meaning it's either WHQLFilePublisher, FilePublisher or SignedVersion then do not use it for other levels
						if (signer.FileAttribRef.Count > 0)
						{
							continue;
						}

						return new SimulationOutput(
									 Path.GetFileName(simulationInput.FilePath.ToString()),
									 SimulationOutputSource.Signer,
									 true,
									 signer.ID,
									 signer.Name,
									 signer.CertRoot,
									 signer.CertPublisher,
									 signer.SignerScope,
									 signer.FileAttribRef,
									 "Publisher",
									 null,
									 chain.RootCertificate.SubjectCN,
									 chain.RootCertificate.IssuerCN,
									 chain.RootCertificate.NotAfter.ToString(CultureInfo.InvariantCulture),
									 chain.RootCertificate.TBSValue,
									 simulationInput.FilePath.ToString()
									 );
					}
				}

				/*
					ELIGIBILITY CHECK FOR LEVELS: PcaCertificate, RootCertificate (LeafCertificate will also generate the same type of signer)

					CRITERIA:
					1) The signer's CertRoot (referring to the TBS value in the xml file which belongs to the Root Certificate of the file when there is only 1 Element in the chain) Matches the TBSValue of the file's root certificate
					2) The signer's name (Referring to the one in the XML file) matches the same Root certificate's SubjectCN
					*/

				else if (string.Equals(signer.CertRoot, chain.RootCertificate.TBSValue, StringComparison.OrdinalIgnoreCase) &&
					string.Equals(signer.Name, chain.RootCertificate.SubjectCN, StringComparison.OrdinalIgnoreCase))
				{

					// If the signer has FileAttributes meaning it's either WHQLFilePublisher, FilePublisher or SignedVersion then do not use it for other levels
					if (signer.FileAttribRef.Count > 0)
					{
						continue;
					}

					return new SimulationOutput(
							 Path.GetFileName(simulationInput.FilePath.ToString()),
							 SimulationOutputSource.Signer,
							 true,
							 signer.ID,
							 signer.Name,
							 signer.CertRoot,
							 signer.CertPublisher,
							 signer.SignerScope,
							 signer.FileAttribRef,
							 "PcaCertificate/RootCertificate",
							 null,
							 chain.RootCertificate.SubjectCN,
							 chain.RootCertificate.IssuerCN,
							 chain.RootCertificate.NotAfter.ToString(CultureInfo.InvariantCulture),
							 chain.RootCertificate.TBSValue,
							 simulationInput.FilePath.ToString()
							 );
				}
				// Endregion ROOT CERTIFICATE ELIGIBILITY CHECK
			}
		}

		// The file is signed but the signer wasn't found in the policy file that allows it
		return new SimulationOutput(
			Path.GetFileName(simulationInput.FilePath.ToString()),
			SimulationOutputSource.Signer,
			false,
			null,
			null,
			null,
			null,
			null,
			null,
			"Not Allowed",
			null,
			null,
			null,
			null,
			null,
			simulationInput.FilePath.ToString()
			);
	}
}
