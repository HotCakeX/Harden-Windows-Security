using System.Collections.Generic;
using WDACConfig.IntelGathering;

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
        /// The New-NewFilePublisherLevelRules class and NewPublisherLevelRules class both are able to create rules based on different signer WDAC levels.
        ///
        /// The other way around, where Publisher TBS hash is missing but Issuer TBS is present, would create a PCACertificate level Signer, but that is not implemented yet.
        /// Its use case is not clear yet and there haven't been any files with that condition yet. <summary>
        /// </summary>
        /// <param name="data">The Data to be processed. These are the logs selected by the user and contain both signed and unsigned data.</param>
        /// </param>
        /// <param name="level">Auto, FilePublisher, Publisher, Hash</param>
        /// <param name="publisherToHash">It will pass any publisher rules to the hash array. E.g when sandboxing-like behavior using Macros and AppIDs are used.</param>
        /// <returns></returns>
        public static FileBasedInfoPackage BuildSignerAndHashObjects(List<FileIdentity> data, ScanLevels level = ScanLevels.FilePublisher, bool publisherToHash = false)
        {
            // To store the Signers created with FilePublisher Level
            List<FilePublisherSignerCreator> filePublisherSigners = [];

            // To store the Signers created with Publisher Level
            List<PublisherSignerCreator> publisherSigners = [];

            // To store the FileAttributes created using Hash Level
            List<HashCreator> completeHashes = [];

            // Lists to separate data initially
            List<FileIdentity> signedFilePublisherData = [];
            List<FileIdentity> signedPublisherData = [];
            List<FileIdentity> unsignedData = [];

            Logger.Write("BuildSignerAndHashObjects: Starting the data separation process.");

            // Data separation based on the level
            switch (level)
            {
                // If Hash level is used then add everything to the Unsigned data so Hash rules will be created for them
                case ScanLevels.Hash:

                    Logger.Write("BuildSignerAndHashObjects: Using only Hash level.");

                    // Assign the entire data to the unsigned Data list
                    unsignedData = data;

                    break;

                // If Publisher level is used then add all Signed data to the SignedPublisherData list and Unsigned data to the Hash list
                case ScanLevels.Publisher:

                    Logger.Write("BuildSignerAndHashObjects: Using Publisher -> Hash levels.");

                    foreach (FileIdentity item in data)
                    {
                        // If the current data is signed and publisherToHash is not used, which would indicate Hash level rules must be created for Publisher level data
                        // And make sure the file is not ECC Signed
                        if (item.SignatureStatus is SignatureStatus.Signed && !publisherToHash && item.IsECCSigned != true)
                        {
                            signedPublisherData.Add(item);
                        }
                        else
                        {
                            // Assign the data to the Hash list
                            unsignedData.Add(item);
                        }
                    }
                    break;

                case ScanLevels.FilePublisher:

                    // Detect and separate FilePublisher, Publisher and Hash (Unsigned) data if the level is Auto or FilePublisher

                    Logger.Write("BuildSignerAndHashObjects: Using FilePublisher -> Publisher -> Hash levels.");

                    // Loop over each data
                    foreach (FileIdentity item in data)
                    {
                        // If the file's version is empty or it has no file attribute, then add it to the Publishers array
                        // because FilePublisher rule cannot be created for it
                        if (item.SignatureStatus is SignatureStatus.Signed && item.IsECCSigned != true)
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
                                    Logger.Write($"BuildSignerAndHashObjects: Passing Publisher rule to the hash array for the file: {item.FilePath}");
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
                    break;

                default:

                    break;
            }

            Logger.Write($"BuildSignerAndHashObjects: {signedFilePublisherData.Count} FilePublisher Rules.");
            Logger.Write($"BuildSignerAndHashObjects: {signedPublisherData.Count} Publisher Rules.");
            Logger.Write($"BuildSignerAndHashObjects: {unsignedData.Count} Hash Rules.");

            Logger.Write("BuildSignerAndHashObjects: Processing FilePublisher data.");

            foreach (FileIdentity signedData in signedFilePublisherData)
            {
                // Create a new FilePublisherSignerCreator object
                FilePublisherSignerCreator currentFilePublisherSigner = new();


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
                        Logger.Write($"BuildSignerAndHashObjects: Intermediate Certificate TBS hash is empty for the file: {signedData.FilePath}, using the leaf certificate TBS hash instead");

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

                #region Initialize properties

                currentFilePublisherSigner.FileVersion = signedData.FileVersion;
                currentFilePublisherSigner.FileDescription = signedData.FileDescription;
                currentFilePublisherSigner.InternalName = signedData.InternalName;
                currentFilePublisherSigner.OriginalFileName = signedData.OriginalFileName;
                currentFilePublisherSigner.ProductName = signedData.ProductName;
                currentFilePublisherSigner.FileName = signedData.FilePath;
                currentFilePublisherSigner.AuthenticodeSHA256 = signedData.SHA256Hash;
                currentFilePublisherSigner.AuthenticodeSHA1 = signedData.SHA1Hash;

                currentFilePublisherSigner.SiSigningScenario = signedData.SISigningScenario;
                #endregion


                // Add the completed FilePublisherSigner to the list
                filePublisherSigners.Add(currentFilePublisherSigner);
            }


            Logger.Write("BuildSignerAndHashObjects: Processing Publisher data.");

            foreach (FileIdentity signedData in signedPublisherData)
            {
                // Create a new PublisherSignerCreator object
                PublisherSignerCreator currentPublisherSigner = new();

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
                        Logger.Write($"BuildSignerAndHashObjects: Intermediate Certificate TBS hash is empty for the file: {signedData.FilePath}, using the leaf certificate TBS hash instead");

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


                currentPublisherSigner.FileName = signedData.FilePath;
                currentPublisherSigner.AuthenticodeSHA256 = signedData.SHA256Hash;
                currentPublisherSigner.AuthenticodeSHA1 = signedData.SHA1Hash;
                currentPublisherSigner.SiSigningScenario = signedData.SISigningScenario;


                // Add the completed PublisherSigner to the list
                publisherSigners.Add(currentPublisherSigner);
            }


            Logger.Write("BuildSignerAndHashObjects: Processing Unsigned Hash data.");

            foreach (FileIdentity hashData in unsignedData)
            {

                string? sha256 = hashData.SHA256Hash;
                string? sha1 = hashData.SHA1Hash;
                string? fileName = hashData.FilePath;
                int siSigningScenario = hashData.SISigningScenario;

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
