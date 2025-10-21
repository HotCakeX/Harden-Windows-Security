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

using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SimulationMethods;

namespace AppControlManager.IntelGathering;

internal static class LocalFilesScan
{

	internal const string WHQLOid = "1.3.6.1.4.1.311.10.3.5";
	private const string ECCOID = "1.2.840.10045.2.1";

	/// <summary>
	/// Scans the local files and returns the scan results
	/// </summary>
	/// <param name="files">File paths to scan</param>
	/// <param name="scalability">How many parallel tasks to use during the scan</param>
	/// <param name="progressReporter">A callback method that will run to display the scan progress in real time and updates the value of its associated ProgressRing UI element.</param>
	/// <returns></returns>
	internal static IEnumerable<FileIdentity> Scan(
		(IEnumerable<string>, int) files,
		ushort scalability,
		IProgress<double> progressReporter,
		CancellationToken? cToken = null)
	{

		// Make sure scalability is always at least 2
		if (scalability < 2)
		{
			scalability = 2;
		}

		try
		{
			Taskbar.Badge.SetBadgeAsActive();

			// Get the security catalog data to include in the scan
			ConcurrentDictionary<string, string> AllSecurityCatalogHashes = CatRootScanner.Scan(null, scalability);

			// Store the output of all of the parallel tasks
			// Uses our custom comparer to ensure unique FileIdentities
			ConcurrentDictionary<FileIdentity, bool> MainOutput = new(scalability, files.Item2, new FileIdentityComparer());

			// The counter variable to track processed files
			int processedFilesCount = 0;

			// The count of all of the files that are going to be processed
			double AllFilesCount = files.Item2;

			// Create a timer to update the progress ring every 2 seconds.
			using Timer progressTimer = new(state =>
			{
				// Read the current value in a thread-safe manner.
				int current = Volatile.Read(ref processedFilesCount);

				// Calculate the percentage complete
				int currentPercentage = (int)(current / AllFilesCount * 100);

				// Cap the percentage at 100
				int percentageToUse = Math.Min(currentPercentage, 100);

				progressReporter.Report(percentageToUse);

				// Update the taskbar progress
				Taskbar.TaskBarProgress.UpdateTaskbarProgress(GlobalVars.hWnd, (ulong)percentageToUse, 100);

			}, null, 0, 2000);

			// split the file paths by the value of Scalability variable
			IEnumerable<string[]> SplitArrays = Enumerable.Chunk(files.Item1, (int)Math.Ceiling(AllFilesCount / scalability));

			// List of tasks to run in parallel
			List<Task> tasks = new(scalability);

			// Loop over each chunk of data
			foreach (string[] chunk in SplitArrays)
			{
				// Run each chunk of data in a different thread
				tasks.Add(Task.Run(() =>
				{
					foreach (string file in chunk)
					{

						cToken?.ThrowIfCancellationRequested();

						// Increment the processed file count safely
						_ = Interlocked.Increment(ref processedFilesCount);

						// To track whether ECC Signed signature has been detected or not
						// Once it's been set to true, it won't be changed to false anymore for the current file
						bool IsECCSigned = false;

						try
						{

							#region Gather File information

							// Get the Code integrity hashes of the file
							CodeIntegrityHashes fileHashes = CiFileHash.GetCiFileHashes(file);

							// Get the extended file attributes
							ExFileInfo ExtendedFileInfo = GetExtendedFileAttrib.Get(file);


							// To store all certificates of the file
							List<AllFileSigners> FileSignatureResults = [];
							try
							{
								// Get the certificate details of the file
								FileSignatureResults = AllCertificatesGrabber.GetAllFileSigners(file);
							}
							// If the file has HashMismatch, Hash rule will be created for it since the FileSignatureResults will be empty and file will be detected as unsigned
							catch (HashMismatchInCertificateException)
							{
								Logger.Write(string.Format(
									GlobalVars.GetStr("FileHashMismatchRuleCreationMessage"),
									file));
							}

							bool fileIsSigned = false;

							if (FileSignatureResults.Count > 0)
							{
								fileIsSigned = true;
							}

							// If the file doesn't have certificates in itself, check for catalog signers
							else if (AllSecurityCatalogHashes.TryGetValue(fileHashes.SHA1Authenticode!, out string? CurrentFilePathHashSHA1CatResult))
							{
								try
								{
									FileSignatureResults = AllCertificatesGrabber.GetAllFileSigners(CurrentFilePathHashSHA1CatResult);
								}
								catch (HashMismatchInCertificateException)
								{
									Logger.Write(string.Format(
										GlobalVars.GetStr("FileHashMismatchRuleCreationMessage"),
										file));
								}
							}
							else if (AllSecurityCatalogHashes.TryGetValue(fileHashes.SHA256Authenticode!, out string? CurrentFilePathHashSHA256CatResult))
							{
								try
								{
									FileSignatureResults = AllCertificatesGrabber.GetAllFileSigners(CurrentFilePathHashSHA256CatResult);
								}
								catch (HashMismatchInCertificateException)
								{
									Logger.Write(string.Format(
										GlobalVars.GetStr("FileHashMismatchRuleCreationMessage"),
										file));
								}
							}

							// Check the signatures again
							if (FileSignatureResults.Count > 0)
							{
								fileIsSigned = true;
							}

							#endregion

							FileIdentity currentFileIdentity = new()
							{
								Origin = FileIdentityOrigin.DirectFileScan,
								SignatureStatus = fileIsSigned ? SignatureStatus.IsSigned : SignatureStatus.IsUnsigned,
								FilePath = file,
								FileName = Path.GetFileName(file),
								SHA1Hash = fileHashes.SHA1Authenticode,
								SHA256Hash = fileHashes.SHA256Authenticode,
								SHA1PageHash = fileHashes.SHA1Page,
								SHA256PageHash = fileHashes.SHA256Page,
								SISigningScenario = KernelModeDrivers.CheckKernelUserModeStatus(file).Verdict,
								OriginalFileName = ExtendedFileInfo.OriginalFileName,
								InternalName = ExtendedFileInfo.InternalName,
								FileDescription = ExtendedFileInfo.FileDescription,
								ProductName = ExtendedFileInfo.ProductName,
								FileVersion = ExtendedFileInfo.Version
							};

							if (fileIsSigned)
							{
								// Get all of the file's OIDs
								List<string> ekuOIDs = GetOIDs(FileSignatureResults);

								// Check if the file has WHQL signer
								bool HasWHQLSigner = ekuOIDs.Contains(WHQLOid);

								// Assign the FileIdentity's property.
								// Indicating the current FileIdentity contains an item in FileSignerInfos property that is a WHQL signer.
								currentFileIdentity.HasWHQLSigner = HasWHQLSigner;

								// Get all of the certificates of the file
								List<ChainPackage> FileSignerInfo = GetCertificateDetails.Get(FileSignatureResults);

								// Iterate through the certificates of the file
								foreach (ChainPackage package in FileSignerInfo)
								{

									string? CurrentOpusData = null;

									try
									{
										// Try to get the Opus data of the current chain (essentially the current chain's leaf certificate)
										CurrentOpusData = Opus.GetOpusData(package.SignedCms).Select(p => p.CertOemID).FirstOrDefault();

										// Some files will still have empty Opus data despite reaching this point in the code
										if (string.IsNullOrWhiteSpace(CurrentOpusData))
										{
											CurrentOpusData = null;
										}
									}
									catch
									{
										Logger.Write(GlobalVars.GetStr("FailedToGetOpusDataMessage"));
									}

									// If the Leaf Certificate exists in the current package
									// Indicating that the current signer of the file is a normal certificate with Leaf/Intermediate(s)/Root
									if (package.LeafCertificate is not null)
									{

										// See if the leaf certificate in the current signer has WHQL OID for its EKU
										bool WHQLConfirmed = DetermineWHQL(package.LeafCertificate.Certificate!.Extensions);

										// Get the TBSHash of the Issuer certificate of the Leaf Certificate of the current file's signer
										string IssuerTBSHash = CertificateHelper.GetTBSCertificate(package.LeafCertificate.Issuer);

										FileSignerInfo signerInfo = new(
											totalSignatureCount: FileSignerInfo.Count,
											notValidAfter: package.LeafCertificate?.NotAfter,
											notValidBefore: package.LeafCertificate?.NotBefore,
											publisherName: package.LeafCertificate?.SubjectCN,
											issuerName: package.LeafCertificate?.IssuerCN,
											publisherTBSHash: package.LeafCertificate?.TBSValue,
											issuerTBSHash: IssuerTBSHash,
											oPUSInfo: CurrentOpusData,
											isWHQL: WHQLConfirmed,
											eKUs: WHQLConfirmed ? WHQLOid : ekuOIDs.FirstOrDefault() // If the Leaf certificate has WHQL EKU then assign that EKU's OID here, otherwise assign the first OID of the leaf certificate of the file.
										);

										// Add the CN of the file's leaf certificate to the FilePublishers HashSet of the current FileIdentity
										if (package.LeafCertificate?.SubjectCN is not null)
										{
											_ = currentFileIdentity.FilePublishers.Add(package.LeafCertificate.SubjectCN);

											// Check to see if it hasn't already been determined that the file is ECC signed
											// We don't want to find an ECC signed certificate and then overwrite the property's value and set it to false by the next non-ECC signed certificate
											if (!IsECCSigned)
											{
												// Check see if the file is ECC-Signed
												currentFileIdentity.IsECCSigned = string.Equals(package.LeafCertificate.Certificate?.PublicKey?.EncodedKeyValue.Oid?.Value, ECCOID, StringComparison.OrdinalIgnoreCase);

												if (currentFileIdentity.IsECCSigned == true)
												{
													// Set it to true so we don't search for ECC Signed certificates in other signers of the file
													IsECCSigned = true;

													Logger.Write(string.Format(
														GlobalVars.GetStr("EccSignedFileDetectedMessage"),
														currentFileIdentity.FilePath));
												}
											}
										}

										_ = currentFileIdentity.FileSignerInfos.Add(signerInfo);
									}
									// If Leaf certificate is null, according to the GetCertificateDetails class's logic,
									// use Root certificate. That means the current signer of the file is a root certificate.
									else if (package.RootCertificate is not null)
									{
										// See if the root certificate in the current signer has WHQL OID for its EKU
										bool WHQLConfirmed = DetermineWHQL(package.RootCertificate.Certificate!.Extensions);

										FileSignerInfo signerInfo = new(
											totalSignatureCount: FileSignerInfo.Count,
											notValidAfter: package.RootCertificate.NotAfter,
											notValidBefore: package.RootCertificate.NotBefore,
											publisherName: package.RootCertificate.SubjectCN,
											issuerName: package.RootCertificate.IssuerCN,
											publisherTBSHash: package.RootCertificate.TBSValue,
											issuerTBSHash: package.RootCertificate.TBSValue,
											oPUSInfo: CurrentOpusData,
											isWHQL: WHQLConfirmed,
											eKUs: WHQLConfirmed ? WHQLOid : ekuOIDs.FirstOrDefault() // If the root certificate has WHQL EKU then assign that EKU's OID here, otherwise assign the first OID of the root certificate of the file.
										);

										// Add the CN of the file's root certificate to the FilePublishers HashSet of the current FileIdentity
										if (package.RootCertificate.SubjectCN is not null)
										{
											_ = currentFileIdentity.FilePublishers.Add(package.RootCertificate.SubjectCN);

											// Check to see if it hasn't already been determined that the file is ECC signed
											// We don't want to find an ECC signed certificate and then overwrite the property's value and set it to false by the next non-ECC signed certificate
											if (!IsECCSigned)
											{
												// Check see if the file is ECC-Signed
												currentFileIdentity.IsECCSigned = string.Equals(package.RootCertificate.Certificate?.PublicKey?.EncodedKeyValue.Oid?.Value, ECCOID, StringComparison.OrdinalIgnoreCase);

												if (currentFileIdentity.IsECCSigned == true)
												{
													// Set it to true so we don't search for ECC Signed certificates in other signers of the file
													IsECCSigned = true;

													Logger.Write(string.Format(
														GlobalVars.GetStr("EccSignedFileDetectedMessage"),
														currentFileIdentity.FilePath));
												}
											}
										}

										_ = currentFileIdentity.FileSignerInfos.Add(signerInfo);
									}
								}
							}

							// Disposing all AllFileSigners instances now that we have extracted
							// every piece of information. This prevents X509Chain native resource accumulation.
							// As of this moment, .NET doesn't warn us about doing this even with all analyzers enabled.
							foreach (AllFileSigners signer in FileSignatureResults)
							{
								signer.Dispose();
							}

							// Add the current file's identity to the output ConcurrentDictionary with a dummy bool for value
							_ = MainOutput.TryAdd(currentFileIdentity, true);
						}
						catch (IOException ex) when (ex.HResult == unchecked((int)0x80070020)) // File in use by another process
						{
							Logger.Write(string.Format(
								GlobalVars.GetStr("SkippingFileInUseMessage"),
								file));
						}
						catch (IOException ex) when (ex.HResult == unchecked((int)0x80070780)) // File cannot be accessed by the system
						{
							Logger.Write(string.Format(
								GlobalVars.GetStr("SkippingFileCannotBeAccessedMessage"),
								file));
						}
						// Custom "Could not hash file via SHA1" error
						// Either thrown from CiFileHash.GetCiFileHashes or CiFileHash.GetAuthenticodeHash
						catch (Exception ex) when (ex.HResult == -2146233079)
						{
							Logger.Write(string.Format(
								GlobalVars.GetStr("SkippingFileHashingFailedMessage"),
								file));
						}
						catch (IOException ex) when (ex.HResult == -2147024894) // FileNotFoundException (0x80070002)
						{
							Logger.Write(string.Format(
								GlobalVars.GetStr("SkippingFileNotFoundMessage"),
								file));
						}
						// Defender files in Program Data directory can throw this
						catch (UnauthorizedAccessException)
						{
							Logger.Write(string.Format(
								GlobalVars.GetStr("SkippingFileAccessDeniedMessage"),
								file));
						}

					}
				}));
			}

			// Wait for all tasks to complete without making the method async
			// The method is already being called in an async/await fashion
			Task.WaitAll(tasks.ToArray());

			// update the progress ring to 100%
			progressReporter.Report(100);

			return MainOutput.Keys;

		}
		finally
		{
			// Clear the taskbar progress
			Taskbar.TaskBarProgress.UpdateTaskbarProgress(GlobalVars.hWnd, 0, 0);
			Taskbar.Badge.ClearBadge();
		}
	}


	/// <summary>
	/// Gets the EKU OIDs of the leaf certificates of all of the signers of a signed file, the ones that App Control policy uses for EKU-based authorization.
	/// Only the leaf certificates have EKUs, others such as root or intermediate have KUs only.
	/// </summary>
	/// <param name="fileSigners"></param>
	/// <returns></returns>
	internal static List<string> GetOIDs(List<AllFileSigners> fileSigners)
	{
		List<string> output = [];

		foreach (AllFileSigners fileSignature in fileSigners)
		{
			// Only process entries where Signer and its SignerInfos exist.
			if (fileSignature.Signer?.SignerInfos is not null)
			{
				foreach (SignerInfo signerInfo in fileSignature.Signer.SignerInfos)
				{
					// Only process if a certificate is present.
					if (signerInfo.Certificate is not null)
					{
						// Iterate over the certificate extensions and select those of type X509EnhancedKeyUsageExtension.
						foreach (X509EnhancedKeyUsageExtension extension in signerInfo.Certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>())
						{
							// Iterate over each Oid in the EnhancedKeyUsages.
							foreach (Oid oid in extension.EnhancedKeyUsages)
							{
								if (oid.Value is not null)
								{
									output.Add(oid.Value);
								}
							}
						}
					}
				}
			}
		}
		return output;
	}


	/// <summary>
	/// Determines whether a file has WHQL signer among all of its signers
	/// </summary>
	/// <param name="Collection"></param>
	/// <returns></returns>
	private static bool DetermineWHQL(X509ExtensionCollection Collection)
	{
		foreach (var ext in Collection)
		{
			if (ext is X509EnhancedKeyUsageExtension eku)
			{
				foreach (Oid oid in eku.EnhancedKeyUsages)
				{
					if (string.Equals(oid.Value, WHQLOid, StringComparison.OrdinalIgnoreCase))
					{
						return true;
					}
				}
			}
		}
		return false;
	}
}
