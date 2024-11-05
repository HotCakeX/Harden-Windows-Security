using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    public static class InvokeWDACSimulation
    {

        /// <summary>
        /// An Aux method that calls the main method then checks the result to make sure all files are allowed, if they are then returns true, otherwise returns false
        /// </summary>
        /// <param name="filePaths"></param>
        /// <param name="xmlFilePath"></param>
        /// <param name="noCatalogScanning"></param>
        /// <returns></returns>
        public static bool Invoke(List<string>? filePaths, string xmlFilePath, bool noCatalogScanning)
        {
            // Call the main method to get the verdicts
            ConcurrentDictionary<string, SimulationOutput> Results = (Invoke(filePaths, null, xmlFilePath, noCatalogScanning, false, null, 2));

            // See if there are any unauthorized files
            IEnumerable<SimulationOutput> ResultsAfterFilter = Results.Values.Where(R => !R.IsAuthorized);

            // If there are no results where the IsAuthorized is false then return true, else return false
            return !ResultsAfterFilter.Any();
        }


        // Using reflection which isn't what we want

        /*
        public static void ExportToCsv(ConcurrentDictionary<string, SimulationOutput> finalResults, string filePath)
        {
            // Get the properties of SimulationOutput class
            var properties = typeof(SimulationOutput).GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .OrderBy(prop => prop.MetadataToken) // Ensures the order matches the class definition
                .ToArray();

            // Create a list for CSV lines
            List<string> csvLines = [];

            // Create header
            var header = string.Join(",", properties.Select(p => $"\"{p.Name}\""));
            csvLines.Add(header);

            // Iterate through the SimulationOutput instances and format each line
            foreach (var output in finalResults.Values)
            {
                var values = properties.Select(p =>
                {
                    var value = p.GetValue(output);
                    if (value is string[] stringArray)
                    {
                        return $"\"{string.Join(",", stringArray)}\""; // Join array elements with commas
                    }
                    return $"\"{value}\""; // Wrap single values in double quotes
                });
                csvLines.Add(string.Join(",", values));
            }

            // Write to file
            File.WriteAllLines(filePath, csvLines);
        }
        */

        public static void ExportToCsv(ConcurrentDictionary<string, SimulationOutput> finalResults, string filePath)
        {
            // Create a list for CSV lines
            List<string> csvLines = [];

            // Create header instead of using reflection to get the properties' names of the SimulationOutput class
            string header = "\"Path\",\"Source\",\"IsAuthorized\",\"SignerID\",\"SignerName\",\"SignerCertRoot\",\"SignerCertPublisher\",\"SignerScope\",\"SignerFileAttributeIDs\",\"MatchCriteria\",\"SpecificFileNameLevelMatchCriteria\",\"CertSubjectCN\",\"CertIssuerCN\",\"CertNotAfter\",\"CertTBSValue\",\"FilePath\"";
            csvLines.Add(header);

            // Iterate through the SimulationOutput instances and format each line
            foreach (SimulationOutput output in finalResults.Values)
            {
                List<string> values =
                [
                    $"\"{output.Path}\"",
                    $"\"{output.Source}\"",
                    $"\"{output.IsAuthorized}\"",
                    $"\"{output.SignerID}\"",
                    $"\"{output.SignerName}\"",
                    $"\"{output.SignerCertRoot}\"",
                    $"\"{output.SignerCertPublisher}\"",
                    $"\"{output.SignerScope}\"",
                    output.SignerFileAttributeIDs is not null ? $"\"{string.Join(",", output.SignerFileAttributeIDs)}\"" : "\"\"",
                    $"\"{output.MatchCriteria}\"",
                    $"\"{output.SpecificFileNameLevelMatchCriteria}\"",
                    $"\"{output.CertSubjectCN}\"",
                    $"\"{output.CertIssuerCN}\"",
                    $"\"{output.CertNotAfter}\"",
                    $"\"{output.CertTBSValue}\"",
                    $"\"{output.FilePath}\""
                ];

                csvLines.Add(string.Join(",", values));
            }

            // Write to file
            File.WriteAllLines(filePath, csvLines);
        }


        /// <summary>
        /// The main method that performs the App Control Simulation.
        /// </summary>
        /// <param name="filePaths"></param>
        /// <param name="folderPaths"></param>
        /// <param name="xmlFilePath"></param>
        /// <param name="noCatalogScanning"></param>
        /// <param name="csvOutput"></param>
        /// <param name="catRootPath"></param>
        /// <param name="threadsCount"> The number of concurrent threads used to run the simulation </param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="FileNotFoundException"></exception>
        /// <exception cref="InvalidOperationException"></exception>
        public static ConcurrentDictionary<string, SimulationOutput> Invoke(
            List<string>? filePaths,
            List<string>? folderPaths,
            string? xmlFilePath,
            bool noCatalogScanning,
            bool csvOutput,
            List<string>? catRootPath,
            ushort threadsCount = 2,
            ProgressBar? UIProgressBar = null)
        {

            if (xmlFilePath is null)
            {
                throw new ArgumentNullException(nameof(xmlFilePath), "The XML file path cannot be null.");
            }

            if (!File.Exists(xmlFilePath))
            {
                throw new FileNotFoundException("The XML file does not exist.", xmlFilePath);
            }

            // Ensure threadsCount is at least 1
            threadsCount = Math.Max((ushort)1, threadsCount);

            Logger.Write($"Running App Control Simulation with {threadsCount} threads count");

            // The Concurrent Dictionary contains any and all of the Simulation results
            // Keys of it are the fil paths which aren't important, values are the important items needed at the end of the simulation
            ConcurrentDictionary<string, SimulationOutput> FinalSimulationResults = [];

            // Read the content of the XML file into a string
            string xmlContent = File.ReadAllText(xmlFilePath);

            // Convert the string to XML Document
            XmlDocument XMLData = new();
            XMLData.LoadXml(xmlContent);

            #region Region Making Sure No AllowAll Rule Exists

            // Define the regex pattern to match the desired XML element
            string pattern = @"<Allow ID=""ID_ALLOW_.*"" FriendlyName="".*"" FileName=""\*"".*/>";
            Regex allowAllRegex = new(pattern, RegexOptions.Compiled);

            // Check if the pattern matches the XML content
            if (allowAllRegex.IsMatch(xmlContent))
            {
                Logger.Write($"The supplied XML file '{xmlFilePath}' contains a rule that allows all files.");

                _ = FinalSimulationResults.TryAdd(xmlFilePath, new SimulationOutput(
                    null,
                    "AllowAllRule",
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

            // Get the signer information from the XML
            List<Signer> SignerInfo = GetSignerInfo.Get(XMLData);

            // Extensions that are not supported by Authenticode. So if these files are not allowed by hash, they are not allowed at all
            HashSet<string> unsignedExtensions = new(StringComparer.OrdinalIgnoreCase)
            {
                ".ocx", ".bat", ".bin"
            };


            #region Region FilePath Rule Checking
            Logger.Write("Checking see if the XML policy has any FilePath rules");

            HashSet<string> FilePathRules = XmlFilePathExtractor.GetFilePaths(xmlFilePath);

            bool HasFilePathRules = FilePathRules.Count > 0;
            #endregion


            // A dictionary where each key is a hash and value is the .Cat file path where the hash was found in
            Dictionary<string, string> AllSecurityCatalogHashes = [];

            if (!noCatalogScanning)
            {

                // Loop through each .cat security catalog on the system - If user selected custom CatRoot folders then use them instead
                DirectoryInfo[] catRootDirectories = [];

                if (catRootPath is not null && catRootPath.Count > 0)
                {
                    catRootDirectories = catRootPath.Select(dir => new DirectoryInfo(dir)).ToArray();
                }
                else
                {
                    catRootDirectories = [new(@"C:\Windows\System32\CatRoot")];
                }

                // Get the .cat files in the directories
                List<FileInfo> detectedCatFiles = FileUtility.GetFilesFast(catRootDirectories, null, [".cat"]);

                Logger.Write($"Including {detectedCatFiles.Count} Security Catalogs in the Simulation process");

                foreach (FileInfo file in detectedCatFiles)
                {
                    // Get the hashes of the security catalog file
                    HashSet<string> catHashes = MeowParser.GetHashes(file.FullName);

                    // If the security catalog file has hashes, then add them to the dictionary
                    if (catHashes.Count > 0)
                    {
                        foreach (string hash in catHashes)
                        {
                            _ = AllSecurityCatalogHashes.TryAdd(hash, file.FullName);
                        }
                    }
                }
            }
            else
            {
                Logger.Write("Skipping Security Catalogs in the Simulation.");
            }

            // Hash Sha256 values of all the file rules based on hash in the supplied xml policy file
            Logger.Write("Getting the Sha256 Hash values of all the file rules based on hash in the supplied xml policy file");

            HashSet<string> SHA256HashesFromXML = GetFileRuleOutput.Get(XMLData).Select(i => i.HashValue).ToHashSet();

            Logger.Write("Getting all of the file paths of the files that WDAC supports, from the user provided directory");

            List<FileInfo> CollectedFiles = FileUtility.GetFilesFast(
                folderPaths?.Select(dir => new DirectoryInfo(dir)).ToArray(),
                filePaths?.Select(file => new FileInfo(file)).ToArray(),
                null);

            // Make sure the selected directories and files contain files with the supported extensions
            if (CollectedFiles.Count == 0)
            {
                throw new InvalidOperationException("There are no files in the selected directory that are supported by the WDAC engine.");
            }

            Logger.Write("Looping through each supported file");

            // Rhe counter variable to track processed files
            int processedFilesCount = 0;

            // The count of all of the files that are going to be processed
            double AllFilesCount = CollectedFiles.Count;

            // split the file paths by ThreadsCount which by default is 2 and minimum 1
            IEnumerable<FileInfo[]> SplitArrays = Enumerable.Chunk(CollectedFiles, (int)Math.Ceiling(AllFilesCount / threadsCount));

            // List of tasks to run in parallel
            List<Task> tasks = [];

            // Loop over each chunk of data
            foreach (FileInfo[] chunk in SplitArrays)
            {
                // Run each chunk of data in a different thread
                tasks.Add(Task.Run(() =>
                {
                    // Loop over the current chunk of data
                    foreach (FileInfo CurrentFilePath in chunk)
                    {

                        // If using the GUI to perform the simulation
                        if (UIProgressBar is not null)
                        {
                            // Increment the processed file count safely
                            _ = Interlocked.Increment(ref processedFilesCount);

                            // Update progress bar safely on the UI thread
                            _ = UIProgressBar.DispatcherQueue.TryEnqueue(() =>
                            {
                                double progressPercentage = (processedFilesCount / AllFilesCount) * 100;

                                // Assuming SimulationProgress is accessible here
                                UIProgressBar.Value = Math.Min(progressPercentage, 100);
                            });
                        }


                        // Check see if the file's hash exists in the XML file regardless of whether it's signed or not
                        // This is because App Control policies sometimes have hash rules for signed files too
                        // So here we prioritize being authorized by file hash over being authorized by Signature

                        if (HasFilePathRules && FilePathRules.Contains(CurrentFilePath.FullName))
                        {
                            _ = FinalSimulationResults.TryAdd(CurrentFilePath.FullName,
                                new SimulationOutput(
                                    CurrentFilePath.Name,
                                    "FilePath",
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
                                    CurrentFilePath.FullName
                                ));

                            // Move to the next file
                            continue;
                        }

                        String CurrentFilePathHashSHA256;
                        String CurrentFilePathHashSHA1;

                        try
                        {
                            CodeIntegrityHashes CurrentFileHashResult = CiFileHash.GetCiFileHashes(CurrentFilePath.FullName);

                            CurrentFilePathHashSHA256 = CurrentFileHashResult.SHA256Authenticode!;
                            CurrentFilePathHashSHA1 = CurrentFileHashResult.SHa1Authenticode!;
                        }
                        catch
                        {
                            _ = FinalSimulationResults.TryAdd(CurrentFilePath.FullName,
                                new SimulationOutput(
                                    CurrentFilePath.Name,
                                    "Signer",
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
                                    CurrentFilePath.FullName
                                ));

                            // Move to the next file
                            continue;
                        }

                        // if the file's hash exists in the XML file then add the file's path to the allowed files and do not check anymore that whether the file is signed or not
                        if (SHA256HashesFromXML.Contains(CurrentFilePathHashSHA256))
                        {
                            _ = FinalSimulationResults.TryAdd(CurrentFilePath.FullName,
                                new SimulationOutput(
                                    CurrentFilePath.Name,
                                    "Hash",
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
                                    CurrentFilePath.FullName
                                ));

                            // Move to the next file
                            continue;
                        }

                        // If the file's extension is not supported by Authenticode and it wasn't allowed by file hash then it's not allowed and no reason to check its signature
                        else if (unsignedExtensions.Contains(CurrentFilePath.Extension))
                        {
                            _ = FinalSimulationResults.TryAdd(CurrentFilePath.FullName,
                                new SimulationOutput(
                                    CurrentFilePath.Name,
                                    "Unsigned",
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
                                    CurrentFilePath.FullName
                                ));

                            // Move to the next file
                            continue;
                        }

                        // If the file's hash does not exist in the supplied XML file, then check its signature
                        else
                        {
                            try
                            {
                                List<AllFileSigners> FileSignatureResults = AllCertificatesGrabber.GetAllFileSigners(CurrentFilePath.FullName);

                                // If there is no result then check if the file is allowed by a security catalog
                                if (FileSignatureResults.Count == 0)
                                {
                                    string? MatchedHashResult = null;

                                    if (!noCatalogScanning)
                                    {
                                        _ = AllSecurityCatalogHashes.TryGetValue(CurrentFilePathHashSHA1, out string? CurrentFilePathHashSHA1CatResult);
                                        _ = AllSecurityCatalogHashes.TryGetValue(CurrentFilePathHashSHA256, out string? CurrentFilePathHashSHA256CatResult);

                                        MatchedHashResult = CurrentFilePathHashSHA1CatResult ?? CurrentFilePathHashSHA256CatResult;
                                    }

                                    if (!noCatalogScanning && MatchedHashResult is not null)
                                    {
                                        AllFileSigners CatalogSignerDits = AllCertificatesGrabber.GetAllFileSigners(MatchedHashResult).First();

                                        nint handle = CatalogSignerDits.Chain.ChainElements[0].Certificate.Handle;

                                        // The file is authorized by a security catalog on the system
                                        _ = FinalSimulationResults.TryAdd(CurrentFilePath.FullName,
                                            new SimulationOutput(
                                                CurrentFilePath.Name,
                                                "Catalog Signed",
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
                                                CurrentFilePath.FullName
                                            ));

                                        // Move to the next file
                                        continue;
                                    }
                                    else
                                    {
                                        // The file is not signed and is not allowed by hash using Security Catalog
                                        _ = FinalSimulationResults.TryAdd(CurrentFilePath.FullName,
                                            new SimulationOutput(
                                                CurrentFilePath.Name,
                                                "Unsigned",
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
                                                CurrentFilePath.FullName
                                            ));

                                        // Move to the next file
                                        continue;
                                    }
                                }
                                else
                                {
                                    // Use the Compare method to process it

                                    // The EKU OIDs of the primary signer of the file, just like the output of the Get-AuthenticodeSignature cmdlet, the ones that WDAC policy uses for EKU-based authorization
                                    string[] ekuOIDs = FileSignatureResults
                                        .Where(p => p.Signer?.SignerInfos is not null)
                                        .SelectMany(p => p.Signer.SignerInfos.Cast<SignerInfo>())
                                        .Where(info => info.Certificate is not null)
                                        .SelectMany(info => info.Certificate!.Extensions.OfType<X509EnhancedKeyUsageExtension>())
                                        .SelectMany(ext => ext.EnhancedKeyUsages.Cast<Oid>())
                                        .Select(oid => oid.Value)
                                        .ToArray()!;

                                    SimulationInput inPutSim = new(
                                        CurrentFilePath, // Path of the signed file
                                        [.. GetCertificateDetails.Get([.. FileSignatureResults])], //  Get all of the details of all certificates of the signed file
                                        [.. SignerInfo], // The entire Signer Info of the WDAC Policy file
                                        ekuOIDs);

                                    SimulationOutput ComparisonResult = Arbitrator.Compare(inPutSim);

                                    _ = FinalSimulationResults.TryAdd(CurrentFilePath.FullName, ComparisonResult);
                                }
                            }
                            catch (ExceptionHashMismatchInCertificate)
                            {
                                _ = FinalSimulationResults.TryAdd(CurrentFilePath.FullName,
                                    new SimulationOutput(
                                        CurrentFilePath.Name,
                                        "Signer",
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
                                        CurrentFilePath.FullName
                                    ));

                                // Move to the next file
                                continue;
                            }

                            // Handle any other error by storing the file path and the reason for the error to display to the user
                            catch (Exception ex)
                            {
                                // If the file is signed but has unknown signature status
                                _ = FinalSimulationResults.TryAdd(CurrentFilePath.FullName,
                                    new SimulationOutput(
                                        CurrentFilePath.Name,
                                        "Signer",
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
                                        CurrentFilePath.FullName
                                    ));

                                // Move to the next file
                                continue;
                            }
                        }
                    }
                }));
            }

            // Wait for all tasks to complete without making the method async
            // The method is already being called in an async/await fashion
            Task.WaitAll([.. tasks]);

            // If user chose to output the results to CSV file
            if (csvOutput)
            {
                ExportToCsv(FinalSimulationResults, @$"C:\Program Files\WDACConfig\AppControl Simulation output {DateTime.Now:yyyy-MM-dd HH-mm-ss}.csv");
            }

            return FinalSimulationResults;

        }
    }
}
