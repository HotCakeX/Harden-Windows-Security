﻿using AppControlManager.Logging;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace AppControlManager.IntelGathering
{
    public static class LocalFilesScan
    {

        private const string WHQLOid = "1.3.6.1.4.1.311.10.3.5";

        private const string ECCOID = "1.2.840.10045.2.1";


        public static HashSet<FileIdentity> Scan(List<FileInfo> files, ushort scalability, ProgressBar? UIProgressBar, ProgressRing? UIProgressRing)
        {

            // Store the output of all of the parallel tasks in this
            ConcurrentDictionary<FileInfo, FileIdentity> temporaryOutput = [];

            // The counter variable to track processed files
            int processedFilesCount = 0;

            // The count of all of the files that are going to be processed
            double AllFilesCount = files.Count;

            // split the file paths by the value of Scalability variable
            IEnumerable<FileInfo[]> SplitArrays = Enumerable.Chunk(files, (int)Math.Ceiling(AllFilesCount / scalability));

            // List of tasks to run in parallel
            List<Task> tasks = [];

            // Loop over each chunk of data
            foreach (FileInfo[] chunk in SplitArrays)
            {
                // Run each chunk of data in a different thread
                tasks.Add(Task.Run(() =>
                {

                    foreach (FileInfo file in chunk)
                    {

                        // Increment the processed file count safely
                        _ = Interlocked.Increment(ref processedFilesCount);

                        if (UIProgressBar is not null)
                        {

                            // Update progress bar safely on the UI thread
                            _ = UIProgressBar.DispatcherQueue.TryEnqueue(() =>
                            {
                                double progressPercentage = (processedFilesCount / AllFilesCount) * 100;

                                UIProgressBar.Value = Math.Min(progressPercentage, 100);
                            });

                        }
                        else if (UIProgressRing is not null)
                        {

                            // Update progress ring safely on the UI thread
                            _ = UIProgressRing.DispatcherQueue.TryEnqueue(() =>
                            {
                                double progressPercentage = (processedFilesCount / AllFilesCount) * 100;

                                UIProgressRing.Value = Math.Min(progressPercentage, 100);
                            });
                        }



                        // To track whether ECC Signed signature has been detected or not
                        // Once it's been set to true, it won't be changed to false anymore for the current file
                        bool IsECCSigned = false;

                        // String path of the current file
                        string fileString = file.ToString();

                        #region Gather File information

                        // Get the Code integrity hashes of the file
                        CodeIntegrityHashes fileHashes = CiFileHash.GetCiFileHashes(fileString);

                        // Get the extended file attributes
                        ExFileInfo ExtendedFileInfo = ExFileInfo.GetExtendedFileInfo(fileString);

                        // Get the certificate details of the file
                        List<AllFileSigners> FileSignatureResults = AllCertificatesGrabber.GetAllFileSigners(fileString);

                        List<string> ekuOIDs = [];

                        bool fileIsSigned = false;

                        if (FileSignatureResults.Count > 0)
                        {
                            fileIsSigned = true;
                        }

                        #endregion

                        FileIdentity currentFileIdentity = new()
                        {
                            Origin = FileIdentityOrigin.DirectFileScan,
                            SignatureStatus = fileIsSigned ? SignatureStatus.IsSigned : SignatureStatus.IsUnsigned,
                            FilePath = fileString,
                            FileName = file.Name,
                            SHA1Hash = fileHashes.SHa1Authenticode,
                            SHA256Hash = fileHashes.SHA256Authenticode,
                            SHA1PageHash = fileHashes.SHA1Page,
                            SHA256PageHash = fileHashes.SHA256Page,
                            SISigningScenario = KernelModeDrivers.CheckKernelUserModeStatus(fileString).Verdict is UserOrKernelMode.UserMode ? 1 : 0,
                            OriginalFileName = ExtendedFileInfo.OriginalFileName,
                            InternalName = ExtendedFileInfo.InternalName,
                            FileDescription = ExtendedFileInfo.FileDescription,
                            ProductName = ExtendedFileInfo.ProductName,
                            FileVersion = ExtendedFileInfo.Version
                        };

                        if (fileIsSigned)
                        {

                            // The EKU OIDs of the primary signer of the file, just like the output of the Get-AuthenticodeSignature cmdlet, the ones that App Control policy uses for EKU-based authorization
                            // Only the leaf certificate of the primary signer has EKUs, others such as root or intermediate have KUs only.
                            ekuOIDs = FileSignatureResults
                               .Where(p => p.Signer?.SignerInfos is not null)
                               .SelectMany(p => p.Signer.SignerInfos.Cast<SignerInfo>())
                               .Where(info => info.Certificate is not null)
                               .SelectMany(info => info.Certificate!.Extensions.OfType<X509EnhancedKeyUsageExtension>())
                               .SelectMany(ext => ext.EnhancedKeyUsages.Cast<Oid>())
                               .Select(oid => oid.Value)
                               .ToList()!;

                            // Check if the file has WHQL signer
                            bool HasWHQLSigner = ekuOIDs.Contains(WHQLOid);

                            // Assign the FileIdentity's property.
                            // Indicating the current FileIdentity contains an item in FileSignerInfos property that is a WHQL signer.
                            currentFileIdentity.HasWHQLSigner = HasWHQLSigner;

                            // Get all of the certificates of the file
                            List<ChainPackage> FileSignerInfo = GetCertificateDetails.Get([.. FileSignatureResults]);


                            // Iterate through the certificates of the file
                            foreach (ChainPackage package in FileSignerInfo)
                            {

                                string? CurrentOpusData = null;

                                try
                                {
                                    // Try to get the Opus data of the current chain (essentially the current chain's leaf certificate)
                                    CurrentOpusData = Opus.GetOpusData(package.SignedCms).Select(p => p.CertOemID).First();
                                }
                                catch
                                {
                                    Logger.Write($"Failed to get the Opus data of the current chain package");
                                }



                                // If the Leaf Certificate exists in the current package
                                // Indicating that the current signer of the file is a normal certificate with Leaf/Intermediate(s)/Root
                                if (package.LeafCertificate is not null)
                                {

                                    // See if the leaf certificate in the current signer has WHQL OID for its EKU
                                    bool WHQLConfirmed = package.LeafCertificate.Certificate!.Extensions.OfType<X509EnhancedKeyUsageExtension>()
                                           .Any(eku => eku.EnhancedKeyUsages.Cast<Oid>()
                                           .Any(oid => oid.Value is not null && oid.Value.Contains(WHQLOid, StringComparison.OrdinalIgnoreCase)));


                                    // Get the TBSHash of the Issuer certificate of the Leaf Certificate of the current file's signer
                                    string IssuerTBSHash = CertificateHelper.GetTBSCertificate(package.LeafCertificate.Issuer);

                                    FileSignerInfo signerInfo = new()
                                    {
                                        TotalSignatureCount = FileSignerInfo.Count,
                                        NotValidAfter = package.LeafCertificate?.NotAfter,
                                        NotValidBefore = package.LeafCertificate?.NotBefore,
                                        PublisherName = package.LeafCertificate?.SubjectCN,
                                        IssuerName = package.LeafCertificate?.IssuerCN,
                                        PublisherTBSHash = package.LeafCertificate?.TBSValue,
                                        IssuerTBSHash = IssuerTBSHash,
                                        OPUSInfo = CurrentOpusData,
                                        IsWHQL = WHQLConfirmed,
                                        EKUs = WHQLConfirmed ? WHQLOid : ekuOIDs.First() // If the Leaf certificate has WHQL EKU then assign that EKU's OID here, otherwise assign the first OID of the leaf certificate of the file.
                                    };


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

                                                Logger.Write($"ECC Signed File Detected: {currentFileIdentity.FilePath}. Will create Hash rules for it.");
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
                                    bool WHQLConfirmed = package.RootCertificate.Certificate!.Extensions.OfType<X509EnhancedKeyUsageExtension>()
                                           .Any(eku => eku.EnhancedKeyUsages.Cast<Oid>()
                                           .Any(oid => oid.Value is not null && oid.Value.Contains(WHQLOid, StringComparison.OrdinalIgnoreCase)));


                                    FileSignerInfo signerInfo = new()
                                    {
                                        TotalSignatureCount = FileSignerInfo.Count,
                                        NotValidAfter = package.RootCertificate.NotAfter,
                                        NotValidBefore = package.RootCertificate.NotBefore,
                                        PublisherName = package.RootCertificate.SubjectCN,
                                        IssuerName = package.RootCertificate.IssuerCN,
                                        PublisherTBSHash = package.RootCertificate.TBSValue,
                                        IssuerTBSHash = package.RootCertificate.TBSValue,
                                        OPUSInfo = CurrentOpusData,
                                        IsWHQL = WHQLConfirmed,
                                        EKUs = WHQLConfirmed ? WHQLOid : ekuOIDs.First() // If the root certificate has WHQL EKU then assign that EKU's OID here, otherwise assign the first OID of the root certificate of the file.
                                    };


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

                                                Logger.Write($"ECC Signed File Detected: {currentFileIdentity.FilePath}. Will create Hash rules for it.");
                                            }
                                        }

                                    }

                                    _ = currentFileIdentity.FileSignerInfos.Add(signerInfo);
                                }
                            }
                        }

                        // Add the current file's identity to the output HashSet
                        _ = temporaryOutput.TryAdd(file, currentFileIdentity);

                    }
                }));
            }


            // Wait for all tasks to complete without making the method async
            // The method is already being called in an async/await fashion
            Task.WaitAll([.. tasks]);

            // HashSet to store the output, ensures the data are unique
            HashSet<FileIdentity> fileIdentities = new(new FileIdentityComparer());

            // Add all the items from the Concurrent Dictionary to the Custom HashSet
            foreach (FileIdentity item in temporaryOutput.Values)
            {
                _ = fileIdentities.Add(item);
            }

            return fileIdentities;
        }
    }
}
