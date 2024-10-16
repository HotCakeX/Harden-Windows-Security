using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;

#nullable enable

namespace WDACConfig
{
    public static class SignerAndHashBuilder
    {
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
        /// The New-FilePublisherLevelRules and New-PublisherLevelRules functions both are able to create rules based on different signer WDAC levels.
        ///
        /// The other way around, where Publisher TBS hash is missing but Issuer TBS is present, would create a PCACertificate level Signer, but that is not implemented yet.
        /// Its use case is not clear yet and there haven't been any files with that condition yet. <summary>
        /// </summary>
        /// <param name="data">The Data to be processed. These are the logs selected by the user and contain both signed and unsigned data.</param>
        /// <param name="incomingDataType">
        /// The type of data that is being processed. This is used to determine the property names in the input data.
        /// The default value is 'MDEAH' (Microsoft Defender Application Guard Event and Hash) and the other value is 'EVTX' (Event Log evtx files).
        /// </param>
        /// <param name="level">Auto, FilePublisher, Publisher, Hash</param>
        /// <param name="publisherToHash">It will pass any publisher rules to the hash array. E.g when sandboxing-like behavior using Macros and AppIDs are used.</param>
        /// <returns></returns>
        public static FileBasedInfoPackage BuildSignerAndHashObjects(Hashtable[] data, string incomingDataType = "MDEAH", string level = "Auto", bool publisherToHash = false)
        {
            // An array to store the Signers created with FilePublisher Level
            List<FilePublisherSignerCreator> filePublisherSigners = [];

            // An array to store the Signers created with Publisher Level
            List<PublisherSignerCreator> publisherSigners = [];

            // An array to store the FileAttributes created using Hash Level
            List<HashCreator> completeHashes = [];

            // Lists to separate data
            List<Hashtable> signedFilePublisherData = [];
            List<Hashtable> signedPublisherData = [];
            List<Hashtable> unsignedData = [];

            Logger.Write("BuildSignerAndHashObjects: Starting the data separation process.");

            // Data separation based on the level
            switch (level.ToLowerInvariant())
            {
                // If Hash level is used then add everything to the Unsigned data so Hash rules will be created for them
                case "hash":

                    Logger.Write("BuildSignerAndHashObjects: Using only Hash level.");

                    foreach (Hashtable item in data)
                    {
                        if (item is null)
                        {
                            Logger.Write("BuildSignerAndHashObjects: Found a null item in data.");
                        }
                        else
                        {
                            unsignedData.Add(item);
                        }
                    }
                    break;

                //  If Publisher level is used then add all Signed data to the SignedPublisherData list and Unsigned data to the Hash list
                case "publisher":

                    Logger.Write("BuildSignerAndHashObjects: Using Publisher -> Hash levels.");

                    foreach (Hashtable item in data)
                    {
                        if (item is null)
                        {
                            Logger.Write("BuildSignerAndHashObjects: Found a null item in data.");
                        }
                        else if (string.Equals(item["SignatureStatus"]?.ToString(), "Signed", StringComparison.OrdinalIgnoreCase) && !publisherToHash)
                        {
                            signedPublisherData.Add(item);
                        }
                        else
                        {
                            unsignedData.Add(item);
                        }
                    }
                    break;

                // Detect and separate FilePublisher, Publisher and Hash (Unsigned) data if the level is Auto or FilePublisher
                default:

                    Logger.Write("BuildSignerAndHashObjects: Using FilePublisher -> Publisher -> Hash levels.");

                    // Loop over each data
                    foreach (Hashtable item in data)
                    {
                        if (item is null)
                        {
                            Logger.Write("BuildSignerAndHashObjects: Found a null item in data.");
                        }
                        // If the file's version is empty or it has no file attribute, then add it to the Publishers array
                        // because FilePublisher rule cannot be created for it
                        else if (string.Equals(item["SignatureStatus"]?.ToString(), "Signed", StringComparison.OrdinalIgnoreCase))
                        {
                            // Safely get values from the item and check for null or whitespace
                            bool hasNoFileAttributes = string.IsNullOrWhiteSpace(item["OriginalFileName"]?.ToString()) &&
                                                        string.IsNullOrWhiteSpace(item["InternalName"]?.ToString()) &&
                                                        string.IsNullOrWhiteSpace(item["FileDescription"]?.ToString()) &&
                                                        string.IsNullOrWhiteSpace(item["ProductName"]?.ToString());

                            bool hasNoFileVersion = string.IsNullOrWhiteSpace(item["FileVersion"]?.ToString());

                            if (hasNoFileAttributes || hasNoFileVersion)
                            {
                                // if PublisherToHash is not used then add it to the Publisher array normally
                                if (!publisherToHash)
                                {
                                    signedPublisherData.Add(item);
                                }
                                else
                                {
                                    Logger.Write($"BuildSignerAndHashObjects: Passing Publisher rule to the hash array for the file: {(string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? item["FileName"] : item["File Name"])}");
                                    // Add the current signed data to Unsigned data array so that Hash rules will be created for it instead
                                    unsignedData.Add(item);
                                }
                            }
                            else
                            {
                                signedFilePublisherData.Add(item);
                            }
                        }
                        else
                        {
                            unsignedData.Add(item);
                        }
                    }
                    break;
            }

            Logger.Write($"BuildSignerAndHashObjects: {signedFilePublisherData.Count} FilePublisher Rules.");
            Logger.Write($"BuildSignerAndHashObjects: {signedPublisherData.Count} Publisher Rules.");
            Logger.Write($"BuildSignerAndHashObjects: {unsignedData.Count} Hash Rules.");

            Logger.Write("BuildSignerAndHashObjects: Processing FilePublisher data.");

            foreach (Hashtable signedData in signedFilePublisherData)
            {
                // Create a new FilePublisherSignerCreator object
                FilePublisherSignerCreator currentFilePublisherSigner = new();

                // Get the certificate details of the current event data based on the incoming type, they can be stored under different names.
                // Safely casting the objects to a HashTable, returning null if the cast fails instead of throwing an exception.
                ICollection? correlatedEventsDataValues = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase)
                    ? (signedData["CorrelatedEventsData"] as Hashtable)?.Values
                    : (signedData["SignerInfo"] as Hashtable)?.Values;

                if (correlatedEventsDataValues is null)
                {
                    Logger.Write("BuildSignerAndHashObjects: correlatedEventsDataValues is null.");
                }
                else
                {
                    // Loop through each correlated event and process the certificate details
                    foreach (Hashtable corDataValue in correlatedEventsDataValues)
                    {

                        // If the file doesn't have Issuer TBS hash (aka Intermediate certificate hash), use the leaf cert's TBS hash and CN instead (aka publisher TBS hash)
                        // This is according to the ConfigCI's workflow when encountering specific files
                        // MDE doesn't generate Issuer TBS hash for some files
                        // For those files, the FilePublisher rule will be created with the file's leaf Certificate details only (Publisher certificate)

                        // Safely access dictionary values and handle nulls
                        string? issuerTBSHash = corDataValue["IssuerTBSHash"]?.ToString();
                        string? publisherTBSHash = corDataValue["PublisherTBSHash"]?.ToString();

                        // currentCorData to store the current SignerInfo/Correlated
                        CertificateDetailsCreator? currentCorData;
                        // Perform the check with null-safe values
                        if (string.IsNullOrWhiteSpace(issuerTBSHash) && !string.IsNullOrWhiteSpace(publisherTBSHash))
                        {
                            Logger.Write($"BuildSignerAndHashObjects: Intermediate Certificate TBS hash is empty for the file: {(string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? signedData["FileName"] : signedData["File Name"])}, using the leaf certificate TBS hash instead");

                            currentCorData = new CertificateDetailsCreator(
                                corDataValue["PublisherTBSHash"]!.ToString()!,
                                corDataValue["PublisherName"]!.ToString()!,
                                corDataValue["PublisherTBSHash"]!.ToString()!,
                                corDataValue["PublisherName"]!.ToString()!
                            );

                        }
                        else
                        {
                            currentCorData = new CertificateDetailsCreator(
                                corDataValue["IssuerTBSHash"]!.ToString()!,
                                corDataValue["IssuerName"]!.ToString()!,
                                corDataValue["PublisherTBSHash"]!.ToString()!,
                                corDataValue["PublisherName"]!.ToString()!
                            );
                        }

                        // Add the Certificate details to the CurrentFilePublisherSigner's CertificateDetails property
                        currentFilePublisherSigner.CertificateDetails.Add(currentCorData);

                    }
                }

                #region Initialize properties
                string? fileVersionString = signedData["FileVersion"]?.ToString();
                string? fileDescription = signedData["FileDescription"]?.ToString();
                string? internalName = signedData["InternalName"]?.ToString();
                string? originalFileName = signedData["OriginalFileName"]?.ToString();
                string? productName = signedData["ProductName"]?.ToString();
                string? fileName = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase)
                    ? (signedData["FileName"]?.ToString())
                    : (signedData["File Name"]?.ToString());

                string? sha256 = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase)
                    ? (signedData["SHA256"]?.ToString())
                    : (signedData["SHA256 Hash"]?.ToString());

                string? sha1 = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase)
                    ? (signedData["SHA1"]?.ToString())
                    : (signedData["SHA1 Hash"]?.ToString());
                _ = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase)
                    ? (signedData["SiSigningScenario"]?.ToString())
                    : (signedData["SI Signing Scenario"]?.ToString());

                // Assign properties, handle null or missing values
                currentFilePublisherSigner.FileVersion = !string.IsNullOrWhiteSpace(fileVersionString)
                    ? Version.Parse(fileVersionString)
                    : null; // Assign null if fileVersionString is null or empty

                currentFilePublisherSigner.FileDescription = fileDescription;
                currentFilePublisherSigner.InternalName = internalName;
                currentFilePublisherSigner.OriginalFileName = originalFileName;
                currentFilePublisherSigner.ProductName = productName;
                currentFilePublisherSigner.FileName = fileName;
                currentFilePublisherSigner.AuthenticodeSHA256 = sha256;
                currentFilePublisherSigner.AuthenticodeSHA1 = sha1;

                currentFilePublisherSigner.SiSigningScenario = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? int.Parse(signedData["SiSigningScenario"]!.ToString()!, CultureInfo.InvariantCulture) : (string.Equals(signedData["SI Signing Scenario"]!.ToString(), "Kernel-Mode", StringComparison.OrdinalIgnoreCase) ? 0 : 1);
                #endregion

                // Check if necessary details are not empty
                if (string.IsNullOrWhiteSpace(currentFilePublisherSigner.AuthenticodeSHA256))
                {
                    Logger.Write($"SHA256 is empty for the file: {(string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? signedData["FileName"] : signedData["File Name"])}");
                }

                if (string.IsNullOrWhiteSpace(currentFilePublisherSigner.AuthenticodeSHA1))
                {
                    Logger.Write($"SHA1 is empty for the file: {(string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? signedData["FileName"] : signedData["File Name"])}");
                }

                // Add the completed FilePublisherSigner to the list
                filePublisherSigners.Add(currentFilePublisherSigner);
            }

            Logger.Write("BuildSignerAndHashObjects: Processing Publisher data.");

            foreach (Hashtable signedData in signedPublisherData)
            {
                // Create a new PublisherSignerCreator object
                PublisherSignerCreator currentPublisherSigner = new();

                // Get the certificate details of the current event data based on the incoming type, they can be stored under different names
                ICollection? correlatedEventsDataValues = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase)
                    ? (signedData?["CorrelatedEventsData"] as Hashtable)?.Values
                    : (signedData?["SignerInfo"] as Hashtable)?.Values;

                if (correlatedEventsDataValues is null)
                {
                    Logger.Write("BuildSignerAndHashObjects: correlatedEventsDataValues is null.");
                }
                else
                {
                    // Process each correlated event
                    foreach (Hashtable corDataValue in correlatedEventsDataValues)
                    {

                        // Safely access dictionary values and handle nulls
                        string? issuerTBSHash = corDataValue["IssuerTBSHash"]?.ToString();
                        string? issuerName = corDataValue["IssuerName"]?.ToString();
                        string? publisherTBSHash = corDataValue["PublisherTBSHash"]?.ToString();
                        string? publisherName = corDataValue["PublisherName"]?.ToString();

                        CertificateDetailsCreator? currentCorData;
                        // Perform the check with null-safe values
                        if (string.IsNullOrWhiteSpace(issuerTBSHash) && !string.IsNullOrWhiteSpace(publisherTBSHash))
                        {
                            Logger.Write($"BuildSignerAndHashObjects: Intermediate Certificate TBS hash is empty for the file: {(string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? signedData!["FileName"] : signedData!["File Name"])}, using the leaf certificate TBS hash instead");

                            // Create a new CertificateDetailsCreator object with the safely retrieved and used values
                            currentCorData = new CertificateDetailsCreator(
                                publisherTBSHash,
                                publisherName!,
                                publisherTBSHash,
                                publisherName!
                            );
                        }
                        else
                        {
                            // Create a new CertificateDetailsCreator object with the safely retrieved and used values
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
                }

                // Need to spend more time on this part to properly inspect how the methods getting data from the current method handle the nulls in this properties
#nullable disable
                currentPublisherSigner.FileName = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? signedData["FileName"].ToString() : signedData["File Name"].ToString();
                currentPublisherSigner.AuthenticodeSHA256 = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? signedData["SHA256"].ToString() : signedData["SHA256 Hash"].ToString();
                currentPublisherSigner.AuthenticodeSHA1 = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? signedData["SHA1"].ToString() : signedData["SHA1 Hash"].ToString();
                currentPublisherSigner.SiSigningScenario = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? int.Parse(signedData["SiSigningScenario"].ToString(), CultureInfo.InvariantCulture) : (string.Equals(signedData["SI Signing Scenario"].ToString(), "Kernel-Mode", StringComparison.OrdinalIgnoreCase) ? 0 : 1);
#nullable enable

                // Add the completed PublisherSigner to the list
                publisherSigners.Add(currentPublisherSigner);
            }

            Logger.Write("BuildSignerAndHashObjects: Processing Unsigned Hash data.");

            foreach (Hashtable hashData in unsignedData)
            {
                if (hashData is null)
                {
                    Logger.Write("BuildSignerAndHashObjects: Found a null hashData item.");
                    continue;
                }

                string? sha256 = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase)
                    ? (hashData["SHA256"]?.ToString())
                    : (hashData["SHA256 Hash"]?.ToString());

                string? sha1 = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase)
                    ? (hashData["SHA1"]?.ToString())
                    : (hashData["SHA1 Hash"]?.ToString());

                string? fileName = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase)
                    ? (hashData["FileName"]?.ToString())
                    : (hashData["File Name"]?.ToString());

                int siSigningScenario = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase)
                    ? (hashData.ContainsKey("SiSigningScenario") ? int.Parse(hashData["SiSigningScenario"]?.ToString()!, CultureInfo.InvariantCulture) : 1)
                    : (hashData.ContainsKey("SI Signing Scenario") ? (string.Equals(hashData["SI Signing Scenario"]?.ToString(), "Kernel-Mode", StringComparison.OrdinalIgnoreCase) ? 0 : 1) : 1);

                if (string.IsNullOrWhiteSpace(sha256) || string.IsNullOrWhiteSpace(sha1) || string.IsNullOrWhiteSpace(fileName))
                {
                    Logger.Write("BuildSignerAndHashObjects: One or more necessary properties are null or empty in hashData.");
                    continue;
                }

                completeHashes.Add(new HashCreator(
                    sha256,
                    sha1,
                    fileName,
                    siSigningScenario
                ));
            }

            Logger.Write("BuildSignerAndHashObjects: Completed the process.");

            return new FileBasedInfoPackage(filePublisherSigners, publisherSigners, completeHashes);
        }
    }
}
