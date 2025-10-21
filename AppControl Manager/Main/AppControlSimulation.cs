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
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using AppControlManager.IntelGathering;
using AppControlManager.Others;
using AppControlManager.SimulationMethods;
using AppControlManager.XMLOps;

namespace AppControlManager.Main;

internal static class AppControlSimulation
{

	// Extensions that are not supported by Authenticode. So if these files are not allowed by hash, they are not allowed at all
	private static readonly FrozenSet<string> unsignedExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
	{
		".ocx", ".bat", ".bin"
	}.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// An Aux method that calls the main method then checks the result to make sure all files are allowed, if they are then returns true, otherwise returns false
	/// </summary>
	/// <param name="filePaths"></param>
	/// <param name="xmlFilePath"></param>
	/// <param name="noCatalogScanning"></param>
	/// <returns></returns>
	internal static bool Invoke(List<string>? filePaths, string xmlFilePath, bool noCatalogScanning)
	{
		// Call the main method to get the verdicts
		ConcurrentDictionary<string, SimulationOutput> Results = Invoke(filePaths, null, xmlFilePath, noCatalogScanning, null, 2);

		// See if there are any unauthorized files
		IEnumerable<SimulationOutput> ResultsAfterFilter = Results.Values.Where(R => !R.IsAuthorized);

		// If there are no results where the IsAuthorized is false then return true, else return false
		return !ResultsAfterFilter.Any();
	}


	/// <summary>
	/// The main method that performs the App Control Simulation.
	/// </summary>
	/// <param name="filePaths"></param>
	/// <param name="folderPaths"></param>
	/// <param name="xmlFilePath"></param>
	/// <param name="scanSecurityCatalogs"></param>
	/// <param name="catRootPath"></param>
	/// <param name="threadsCount"> The number of concurrent threads used to run the simulation </param>
	/// <param name="progressReporter"></param>
	/// <returns></returns>
	/// <exception cref="ArgumentNullException"></exception>
	/// <exception cref="FileNotFoundException"></exception>
	/// <exception cref="InvalidOperationException"></exception>
	internal static ConcurrentDictionary<string, SimulationOutput> Invoke(
		IReadOnlyCollection<string>? filePaths,
		IReadOnlyCollection<string>? folderPaths,
		string xmlFilePath,
		bool scanSecurityCatalogs,
		List<string>? catRootPath,
		ushort threadsCount = 2,
		IProgress<double>? progressReporter = null)
	{

		// Ensure threadsCount is at least 1
		threadsCount = Math.Max((ushort)1, threadsCount);

		Logger.Write(string.Format(
			GlobalVars.GetStr("RunningAppControlSimulationMessage"),
			threadsCount));

		// Read the content of the XML file into a string
		string xmlContent = File.ReadAllText(xmlFilePath);

		// Convert the string to XML Document
		XmlDocument XMLData = new();
		XMLData.LoadXml(xmlContent);


		// Get the signer information from the XML
		List<SignerX> SignerInfo = GetSignerInfo.Get(XMLData);

		#region Region FilePath Rule Checking
		Logger.Write(GlobalVars.GetStr("CheckingFilePathRulesMessage"));

		HashSet<string> FilePathRules = XmlFilePathExtractor.GetFilePaths(xmlFilePath);

		bool HasFilePathRules = FilePathRules.Count > 0;
		#endregion

		// A dictionary where each key is a hash and value is the .Cat file path where the hash was found in
		ConcurrentDictionary<string, string> AllSecurityCatalogHashes = [];

		if (scanSecurityCatalogs)
		{
			// Get the security catalog data to include in the scan
			AllSecurityCatalogHashes = CatRootScanner.Scan(catRootPath, threadsCount);
		}
		else
		{
			Logger.Write(GlobalVars.GetStr("SkippingSecurityCatalogsMessage"));
		}

		Logger.Write(GlobalVars.GetStr("GettingHashValuesOfFileRulesMessage"));

		// All Hash values of all the file rules based on hash in the supplied xml policy file
		HashSet<string> AllHashTypesFromXML = GetFileHashes.Get(XMLData);

		Logger.Write(GlobalVars.GetStr("GettingSupportedFilePathsMessage"));

		(IEnumerable<string>, int) CollectedFiles = FileUtility.GetFilesFast(
			folderPaths,
			filePaths,
			null);

		// Make sure the selected directories and files contain files with the supported extensions
		if (CollectedFiles.Item2 == 0)
		{
			throw new NoValidFilesSelectedException(
				GlobalVars.GetStr("NoValidFilesSelectedMessage"));
		}

		Logger.Write(GlobalVars.GetStr("LoopingThroughSupportedFilesMessage"));

		// The counter variable to track processed files
		int processedFilesCount = 0;

		// The count of all of the files that are going to be processed
		double AllFilesCount = CollectedFiles.Item2;

		// The Concurrent Dictionary contains any and all of the Simulation results
		// Keys of it are the file paths which aren't important, values are the important items needed at the end of the simulation
		ConcurrentDictionary<string, SimulationOutput> FinalSimulationResults = new(threadsCount, CollectedFiles.Item2);


		#region Region Making Sure No AllowAll Rule Exists

		if (CheckForAllowAll.Check(xmlFilePath))
		{
			Logger.Write(string.Format(
			  GlobalVars.GetStr("XmlFileAllowsAllFilesMessage"),
			  xmlFilePath));

			_ = FinalSimulationResults.TryAdd(xmlFilePath, new SimulationOutput(
				null,
				SimulationOutputSource.AllowAllRule,
				true,
				null,
				null,
				null,
				null,
				null,
				null,
				"Has AllowAll rule",
				null,
				null,
				null,
				null,
				null,
				null));

			// Return the result and do not proceed further
			return FinalSimulationResults;
		}
		#endregion


		try
		{
			// Create a timer to update the progress ring every 2 seconds.
			using Timer? progressTimer = progressReporter is not null ? new Timer(state =>
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

				}, null, 0, 2000) : null;

			Taskbar.Badge.SetBadgeAsActive();

			// split the file paths by ThreadsCount which by default is 2 and minimum 1
			IEnumerable<string[]> SplitArrays = CollectedFiles.Item1.Chunk((int)Math.Ceiling(AllFilesCount / threadsCount));

			// List of tasks to run in parallel
			List<Task> tasks = [];

			// Loop over each chunk of data
			foreach (string[] chunk in SplitArrays)
			{
				// Run each chunk of data in a different thread
				tasks.Add(Task.Run(() =>
				{
					// Loop over the current chunk of data
					foreach (string CurrentFilePath in chunk)
					{
						// Increment the processed file count safely
						_ = Interlocked.Increment(ref processedFilesCount);

						// Check see if the file's hash exists in the XML file regardless of whether it's signed or not
						// This is because App Control policies sometimes have hash rules for signed files too
						// So here we prioritize being authorized by file hash over being authorized by Signature

						FileInfo CurrentFilePathObj = new(CurrentFilePath);

						if (HasFilePathRules && FilePathRules.Contains(CurrentFilePathObj.FullName))
						{
							_ = FinalSimulationResults.TryAdd(CurrentFilePathObj.FullName,
								new SimulationOutput(
									CurrentFilePathObj.Name,
									SimulationOutputSource.FilePath,
									true,
									null,
									null,
									null,
									null,
									null,
									null,
									"Allowed By File Path",
									null,
									null,
									null,
									null,
									null,
									CurrentFilePathObj.FullName
								));

							// Move to the next file
							continue;
						}

						string CurrentFilePathHashSHA256;
						string CurrentFilePathHashSHA1;

						try
						{
							CodeIntegrityHashes CurrentFileHashResult = CiFileHash.GetCiFileHashes(CurrentFilePathObj.FullName);

							CurrentFilePathHashSHA256 = CurrentFileHashResult.SHA256Authenticode!;
							CurrentFilePathHashSHA1 = CurrentFileHashResult.SHA1Authenticode!;
						}
						catch
						{
							_ = FinalSimulationResults.TryAdd(CurrentFilePathObj.FullName,
								new SimulationOutput(
									CurrentFilePathObj.Name,
									SimulationOutputSource.Signer,
									false,
									null,
									null,
									null,
									null,
									null,
									null,
									"Not processed, Inaccessible file",
									null,
									null,
									null,
									null,
									null,
									CurrentFilePathObj.FullName
								));

							// Move to the next file
							continue;
						}

						// if the file's hash exists in the XML file then add the file's path to the allowed files and do not check anymore that whether the file is signed or not
						if (AllHashTypesFromXML.Contains(CurrentFilePathHashSHA256) || AllHashTypesFromXML.Contains(CurrentFilePathHashSHA1))
						{
							_ = FinalSimulationResults.TryAdd(CurrentFilePathObj.FullName,
								new SimulationOutput(
									CurrentFilePathObj.Name,
									SimulationOutputSource.Hash,
									true,
									null,
									null,
									null,
									null,
									null,
									null,
									"Hash Level",
									null,
									null,
									null,
									null,
									null,
									CurrentFilePathObj.FullName
								));

							// Move to the next file
							continue;
						}

						// If the file's extension is not supported by Authenticode and it wasn't allowed by file hash then it's not allowed and no reason to check its signature
						else if (unsignedExtensions.Contains(CurrentFilePathObj.Extension))
						{
							_ = FinalSimulationResults.TryAdd(CurrentFilePathObj.FullName,
								new SimulationOutput(
									CurrentFilePathObj.Name,
									SimulationOutputSource.Unsigned,
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
									CurrentFilePathObj.FullName
								));

							// Move to the next file
							continue;
						}

						// If the file's hash does not exist in the supplied XML file, then check its signature
						else
						{
							List<AllFileSigners> FileSignatureResults = [];
							try
							{
								FileSignatureResults = AllCertificatesGrabber.GetAllFileSigners(CurrentFilePathObj.FullName);

								// If there is no result then check if the file is allowed by a security catalog
								if (FileSignatureResults.Count == 0)
								{
									string? MatchedHashResult = null;

									if (scanSecurityCatalogs)
									{
										_ = AllSecurityCatalogHashes.TryGetValue(CurrentFilePathHashSHA1, out string? CurrentFilePathHashSHA1CatResult);
										_ = AllSecurityCatalogHashes.TryGetValue(CurrentFilePathHashSHA256, out string? CurrentFilePathHashSHA256CatResult);

										MatchedHashResult = CurrentFilePathHashSHA1CatResult ?? CurrentFilePathHashSHA256CatResult;
									}

									if (scanSecurityCatalogs && MatchedHashResult is not null)
									{
										AllFileSigners CatalogSignerDits = AllCertificatesGrabber.GetAllFileSigners(MatchedHashResult).First();

										nint handle = CatalogSignerDits.Chain.ChainElements[0].Certificate.Handle;

										// The file is authorized by a security catalog on the system
										_ = FinalSimulationResults.TryAdd(CurrentFilePathObj.FullName,
											new SimulationOutput(
												CurrentFilePathObj.Name,
												SimulationOutputSource.CatalogSigned,
												true,
												null,
												null,
												null,
												null,
												null,
												null,
												"Catalog Hash",
												MatchedHashResult,
												CryptoAPI.GetNameString(handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false),
												CryptoAPI.GetNameString(handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, true),
												CatalogSignerDits.Chain.ChainElements[0].Certificate.NotAfter.ToString(CultureInfo.InvariantCulture),
												CertificateHelper.GetTBSCertificate(CatalogSignerDits.Chain.ChainElements[0].Certificate),
												CurrentFilePathObj.FullName
											));

										// Disposing catalog signer after extracting all needed info to free native chain resources.
										CatalogSignerDits.Dispose();

										// Move to the next file
										continue;
									}
									else
									{
										// The file is not signed and is not allowed by hash using Security Catalog
										_ = FinalSimulationResults.TryAdd(CurrentFilePathObj.FullName,
											new SimulationOutput(
												CurrentFilePathObj.Name,
												SimulationOutputSource.Unsigned,
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
												CurrentFilePathObj.FullName
											));

										// Move to the next file
										continue;
									}
								}
								else
								{
									// Use the Compare method to process it

									// The EKU OIDs of the primary signer of the file, just like the output of the Get-AuthenticodeSignature cmdlet, the ones that App Control policy uses for EKU-based authorization
									List<string> ekuOIDs = LocalFilesScan.GetOIDs(FileSignatureResults);

									SimulationInput inPutSim = new(
										CurrentFilePathObj, // Path of the signed file
										GetCertificateDetails.Get(FileSignatureResults), //  Get all of the details of all certificates of the signed file
										SignerInfo, // The entire Signer Info of the App Control Policy file
										ekuOIDs);

									SimulationOutput ComparisonResult = Arbitrator.Compare(inPutSim);

									_ = FinalSimulationResults.TryAdd(CurrentFilePathObj.FullName, ComparisonResult);
								}
							}
							catch (HashMismatchInCertificateException)
							{
								_ = FinalSimulationResults.TryAdd(CurrentFilePathObj.FullName,
									new SimulationOutput(
										CurrentFilePathObj.Name,
										SimulationOutputSource.Signer,
										false,
										null,
										null,
										null,
										null,
										null,
										null,
										"Hash Mismatch",
										null,
										null,
										null,
										null,
										null,
										CurrentFilePathObj.FullName
									));

								// Move to the next file
								continue;
							}

							// Handle any other error by storing the file path and the reason for the error to display to the user
							catch (Exception ex)
							{
								// If the file is signed but has unknown signature status
								_ = FinalSimulationResults.TryAdd(CurrentFilePathObj.FullName,
									new SimulationOutput(
										CurrentFilePathObj.Name,
										SimulationOutputSource.Signer,
										false,
										null,
										null,
										null,
										null,
										null,
										null,
										$"UnknownError: {ex.Message}",
										null,
										null,
										null,
										null,
										null,
										CurrentFilePathObj.FullName
									));

								// Move to the next file
								continue;
							}
							finally
							{
								// Disposing all AllFileSigners instances to free X509Chain native resources.
								foreach (AllFileSigners signer in FileSignatureResults)
								{
									signer.Dispose();
								}
							}
						}
					}
				}));
			}

			// Wait for all tasks to complete without making the method async
			// The method is already being called in an async/await fashion
			Task.WaitAll([.. tasks]);

			// update the progress ring to 100%
			progressReporter?.Report(100);

		}
		finally
		{
			// Clear the taskbar progress
			Taskbar.TaskBarProgress.UpdateTaskbarProgress(GlobalVars.hWnd, 0, 0);
			Taskbar.Badge.ClearBadge();
		}

		return FinalSimulationResults;

	}
}
