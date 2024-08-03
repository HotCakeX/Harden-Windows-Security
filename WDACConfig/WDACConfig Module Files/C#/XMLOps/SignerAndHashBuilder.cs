using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Globalization;

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
            List<WDACConfig.FilePublisherSignerCreator> filePublisherSigners = new List<WDACConfig.FilePublisherSignerCreator>();

            // An array to store the Signers created with Publisher Level
            List<WDACConfig.PublisherSignerCreator> publisherSigners = new List<WDACConfig.PublisherSignerCreator>();

            // An array to store the FileAttributes created using Hash Level
            List<WDACConfig.HashCreator> completeHashes = new List<WDACConfig.HashCreator>();

            // Defining the arrays to store the signed and unsigned data
            List<Hashtable> signedFilePublisherData = new List<Hashtable>();
            List<Hashtable> signedPublisherData = new List<Hashtable>();
            List<Hashtable> unsignedData = new List<Hashtable>();

            // Do all of the separations in here
            switch (level.ToLowerInvariant())
            {
                // If Hash level is used then add everything to the Unsigned data so Hash rules will be created for them
                case "hash":
                    foreach (var item in data)
                    {
                        unsignedData.Add(item);
                    }
                    break;

                //  If Publisher level is used then add all Signed data to the SignedPublisherData list and Unsigned data to the Hash list
                case "publisher":
                    foreach (var item in data)
                    {
                        if (string.Equals(item["SignatureStatus"].ToString(), "Signed", StringComparison.OrdinalIgnoreCase) && !publisherToHash)
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
                    // Loop over each data
                    foreach (var item in data)
                    {
                        // If the file's version is empty or it has no file attribute, then add it to the Publishers array
                        // because FilePublisher rule cannot be created for it
                        if (string.Equals(item["SignatureStatus"].ToString(), "Signed", StringComparison.OrdinalIgnoreCase))
                        {
                            bool hasNoFileAttributes = string.IsNullOrWhiteSpace(item["OriginalFileName"].ToString()) &&
                                                       string.IsNullOrWhiteSpace(item["InternalName"].ToString()) &&
                                                       string.IsNullOrWhiteSpace(item["FileDescription"].ToString()) &&
                                                       string.IsNullOrWhiteSpace(item["ProductName"].ToString());

                            bool hasNoFileVersion = string.IsNullOrWhiteSpace(item["FileVersion"].ToString());

                            if (hasNoFileAttributes || hasNoFileVersion)
                            {
                                // if PublisherToHash is not used then add it to the Publisher array normally
                                if (!publisherToHash)
                                {
                                    signedPublisherData.Add(item);
                                }
                                else
                                {
                                    WDACConfig.VerboseLogger.Write($"BuildSignerAndHashObjects: Passing Publisher rule to the hash array for the file: {(string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? item["FileName"] : item["File Name"])}");
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

            // Loop over the FilePublisher data
            foreach (var signedData in signedFilePublisherData)
            {
                // Create a new FilePublisherSignerCreator object
                WDACConfig.FilePublisherSignerCreator currentFilePublisherSigner = new WDACConfig.FilePublisherSignerCreator();

                // Get the certificate details of the current event data based on the incoming type, they can be stored under different names
                ICollection correlatedEventsDataValues = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase)
                    ? ((Hashtable)signedData["CorrelatedEventsData"]).Values
                    : ((Hashtable)signedData["SignerInfo"]).Values;


                // Loop through each correlated event and process the certificate details
                foreach (Hashtable corDataValue in correlatedEventsDataValues)
                {
                    // currentCorData to store the current SignerInfo/Correlated
                    WDACConfig.CertificateDetailsCreator currentCorData;

                    // If the file doesn't have Issuer TBS hash (aka Intermediate certificate hash), use the leaf cert's TBS hash and CN instead (aka publisher TBS hash)
                    // This is according to the ConfigCI's workflow when encountering specific files
                    // MDE doesn't generate Issuer TBS hash for some files
                    // For those files, the FilePublisher rule will be created with the file's leaf Certificate details only (Publisher certificate)
                    if (string.IsNullOrWhiteSpace(corDataValue["IssuerTBSHash"].ToString()) && !string.IsNullOrWhiteSpace(corDataValue["PublisherTBSHash"].ToString()))
                    {
                        WDACConfig.VerboseLogger.Write($"BuildSignerAndHashObjects: Intermediate Certificate TBS hash is empty for the file: {(string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? signedData["FileName"] : signedData["File Name"])}, using the leaf certificate TBS hash instead");

                        currentCorData = new WDACConfig.CertificateDetailsCreator(
                            corDataValue["PublisherTBSHash"].ToString(),
                            corDataValue["PublisherName"].ToString(),
                            corDataValue["PublisherTBSHash"].ToString(),
                            corDataValue["PublisherName"].ToString()
                        );
                    }
                    else
                    {
                        currentCorData = new WDACConfig.CertificateDetailsCreator(
                            corDataValue["IssuerTBSHash"].ToString(),
                            corDataValue["IssuerName"].ToString(),
                            corDataValue["PublisherTBSHash"].ToString(),
                            corDataValue["PublisherName"].ToString()
                        );
                    }

                    // Add the Certificate details to the CurrentFilePublisherSigner's CertificateDetails property
                    currentFilePublisherSigner.CertificateDetails.Add(currentCorData);
                }

                currentFilePublisherSigner.FileVersion = Version.Parse(signedData["FileVersion"].ToString());
                currentFilePublisherSigner.FileDescription = signedData["FileDescription"].ToString();
                currentFilePublisherSigner.InternalName = signedData["InternalName"].ToString();
                currentFilePublisherSigner.OriginalFileName = signedData["OriginalFileName"].ToString();
                currentFilePublisherSigner.ProductName = signedData["ProductName"].ToString();
                currentFilePublisherSigner.FileName = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? signedData["FileName"].ToString() : signedData["File Name"].ToString();
                currentFilePublisherSigner.AuthenticodeSHA256 = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? signedData["SHA256"].ToString() : signedData["SHA256 Hash"].ToString();
                currentFilePublisherSigner.AuthenticodeSHA1 = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? signedData["SHA1"].ToString() : signedData["SHA1 Hash"].ToString();
                currentFilePublisherSigner.SiSigningScenario = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? int.Parse(signedData["SiSigningScenario"].ToString(), CultureInfo.InvariantCulture) : (string.Equals(signedData["SI Signing Scenario"].ToString(), "Kernel-Mode", StringComparison.OrdinalIgnoreCase) ? 0 : 1);

                // Some checks to make sure the necessary details are not empty
                if (string.IsNullOrWhiteSpace(currentFilePublisherSigner.AuthenticodeSHA256))
                {
                    WDACConfig.VerboseLogger.Write($"SHA256 is empty for the file: {(string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? signedData["FileName"] : signedData["File Name"])}");
                }

                if (string.IsNullOrWhiteSpace(currentFilePublisherSigner.AuthenticodeSHA1))
                {
                    WDACConfig.VerboseLogger.Write($"SHA1 is empty for the file: {(string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? signedData["FileName"] : signedData["File Name"])}");
                }

                // Add the new object to the FilePublisherSigners array
                filePublisherSigners.Add(currentFilePublisherSigner);
            }

            // Loop over the Publisher data
            foreach (var signedData in signedPublisherData)
            {
                // Create a new PublisherSignerCreator object
                WDACConfig.PublisherSignerCreator currentPublisherSigner = new WDACConfig.PublisherSignerCreator();

                // Get the certificate details of the current event data based on the incoming type, they can be stored under different names
                ICollection correlatedEventsDataValues = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase)
                    ? ((Hashtable)signedData["CorrelatedEventsData"]).Values
                    : ((Hashtable)signedData["SignerInfo"]).Values;


                // Loop through each correlated event and process the certificate details
                foreach (Hashtable corDataValue in correlatedEventsDataValues)
                {
                    WDACConfig.CertificateDetailsCreator currentCorData;

                    if (string.IsNullOrWhiteSpace(corDataValue["IssuerTBSHash"].ToString()) && !string.IsNullOrWhiteSpace(corDataValue["PublisherTBSHash"].ToString()))
                    {
                        WDACConfig.VerboseLogger.Write($"BuildSignerAndHashObjects: Intermediate Certificate TBS hash is empty for the file: {(string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? signedData["FileName"] : signedData["File Name"])}, using the leaf certificate TBS hash instead");

                        currentCorData = new WDACConfig.CertificateDetailsCreator(
                            corDataValue["PublisherTBSHash"].ToString(),
                            corDataValue["PublisherName"].ToString(),
                            corDataValue["PublisherTBSHash"].ToString(),
                            corDataValue["PublisherName"].ToString()
                        );
                    }
                    else
                    {
                        currentCorData = new WDACConfig.CertificateDetailsCreator(
                            corDataValue["IssuerTBSHash"].ToString(),
                            corDataValue["IssuerName"].ToString(),
                            corDataValue["PublisherTBSHash"].ToString(),
                            corDataValue["PublisherName"].ToString()
                        );
                    }

                    // Add the Certificate details to the CurrentPublisherSigner's CertificateDetails property
                    currentPublisherSigner.CertificateDetails.Add(currentCorData);
                }

                currentPublisherSigner.FileName = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? signedData["FileName"].ToString() : signedData["File Name"].ToString();
                currentPublisherSigner.AuthenticodeSHA256 = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? signedData["SHA256"].ToString() : signedData["SHA256 Hash"].ToString();
                currentPublisherSigner.AuthenticodeSHA1 = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? signedData["SHA1"].ToString() : signedData["SHA1 Hash"].ToString();
                currentPublisherSigner.SiSigningScenario = string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? int.Parse(signedData["SiSigningScenario"].ToString(), CultureInfo.InvariantCulture) : (string.Equals(signedData["SI Signing Scenario"].ToString(), "Kernel-Mode", StringComparison.OrdinalIgnoreCase) ? 0 : 1);

                // Add the completed object to the PublisherSigners array
                publisherSigners.Add(currentPublisherSigner);
            }

            // Loop over the unsigned data
            foreach (var hashData in unsignedData)
            {
                completeHashes.Add(new HashCreator(
                    string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? hashData["SHA256"].ToString() : hashData["SHA256 Hash"].ToString(),
                    string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? hashData["SHA1"].ToString() : hashData["SHA1 Hash"].ToString(),
                    string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? hashData["FileName"].ToString() : hashData["File Name"].ToString(),
                    string.Equals(incomingDataType, "MDEAH", StringComparison.OrdinalIgnoreCase) ? int.Parse(hashData["SiSigningScenario"].ToString(), CultureInfo.InvariantCulture) : (string.Equals(hashData["SI Signing Scenario"].ToString(), "Kernel-Mode", StringComparison.OrdinalIgnoreCase) ? 0 : 1)
                ));
            }

            return new FileBasedInfoPackage(filePublisherSigners, publisherSigners, completeHashes);
        }
    }
}
