using System.Collections.Generic;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

#nullable enable

namespace WDACConfig
{
    public class GetCertificateDetails
    {
        /// <summary>
        /// A method to detect Root, Intermediate and Leaf certificates
        /// It returns a compound object that contains 2 nested objects for Intermediate and Leaf certificates
        ///
        /// Old method of recognizing the certificate type:
        /// If the file's subject common name is equal to the certificate's subject common name, then it's the leaf certificate - If a certificate's subject common name is equal to its issuer common name, then it's a root certificate - otherwise it's an intermediate certificate
        /// CertType    = ($SubjectCN -eq $IssuerCN) ? 'Root' : (($SubjectCN -eq $FileSubjectCN) ? 'Leaf' : 'Intermediate')
        ///
        /// </summary>
        /// <param name="completeSignatureResult"></param>
        /// <returns></returns>
        public static List<ChainPackage> Get(AllFileSigners[] completeSignatureResult)
        {
            // A list to hold the final result of the method
            List<ChainPackage> finalObject = [];

            // Loop over each signer of the file, in case the file has multiple separate signers
            for (int i = 0; i < completeSignatureResult.Length; i++)
            {
                // Get the current chain and SignedCms of the signer
                X509Chain currentChain = completeSignatureResult[i].Chain;
                SignedCms currentSignedCms = completeSignatureResult[i].Signer;

                uint certificatesInChainCount = (uint)currentChain.ChainElements.Count;

                switch (certificatesInChainCount)
                {
                    // If the chain includes a Root, Leaf and at least one Intermediate certificate
                    case > 2:
                        // The last certificate in the chain is the Root certificate
                        X509Certificate2 currentRootCertificate = currentChain.ChainElements[^1].Certificate;

                        var rootCertificate = new ChainElement(
                            CryptoAPI.GetNameString(currentRootCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false), // SubjectCN
                            CryptoAPI.GetNameString(currentRootCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, true), // IssuerCN
                            currentRootCertificate.NotAfter,
                            CertificateHelper.GetTBSCertificate(currentRootCertificate),
                            currentRootCertificate, // Append the certificate object itself to the output object as well
                            CertificateType.Root
                        );

                        // An array to hold the Intermediate Certificate(s) of the current chain
                        var intermediateCertificates = new List<ChainElement>();

                        // All the certificates in between are Intermediate certificates
                        for (int j = 1; j < certificatesInChainCount - 1; j++)
                        {
                            X509Certificate2 cert = currentChain.ChainElements[j].Certificate;

                            // Create a collection of intermediate certificates
                            intermediateCertificates.Add(new ChainElement(
                                CryptoAPI.GetNameString(cert.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false),
                                CryptoAPI.GetNameString(cert.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, true),
                                cert.NotAfter,
                                CertificateHelper.GetTBSCertificate(cert),
                                cert, // Append the certificate object itself to the output object as well
                                CertificateType.Intermediate
                            ));
                        }

                        // The first certificate in the chain is the Leaf certificate
                        X509Certificate2 currentLeafCertificate = currentChain.ChainElements[0].Certificate;

                        var leafCertificate = new ChainElement(
                            CryptoAPI.GetNameString(currentLeafCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false),
                            CryptoAPI.GetNameString(currentLeafCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, true),
                            currentLeafCertificate.NotAfter,
                            CertificateHelper.GetTBSCertificate(currentLeafCertificate),
                            currentLeafCertificate, // Append the certificate object itself to the output object as well
                            CertificateType.Leaf
                        );

                        finalObject.Add(new ChainPackage(
                            currentChain, // The entire current chain of the certificate
                            currentSignedCms, // The entire current SignedCms object
                            rootCertificate,
                            intermediateCertificates.ToArray(),
                            leafCertificate
                        ));

                        break;

                    // If the chain only includes a Root and Leaf certificate
                    case 2:
                        // The last certificate in the chain is the Root certificate
                        currentRootCertificate = currentChain.ChainElements[^1].Certificate;

                        rootCertificate = new ChainElement(
                            CryptoAPI.GetNameString(currentRootCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false), // SubjectCN
                            CryptoAPI.GetNameString(currentRootCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, true), // IssuerCN
                            currentRootCertificate.NotAfter,
                            CertificateHelper.GetTBSCertificate(currentRootCertificate),
                            currentRootCertificate, // Append the certificate object itself to the output object as well
                            CertificateType.Root
                        );

                        // The first certificate in the chain is the Leaf certificate
                        currentLeafCertificate = currentChain.ChainElements[0].Certificate;

                        leafCertificate = new ChainElement(
                            CryptoAPI.GetNameString(currentLeafCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false),
                            CryptoAPI.GetNameString(currentLeafCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, true),
                            currentLeafCertificate.NotAfter,
                            CertificateHelper.GetTBSCertificate(currentLeafCertificate),
                            currentLeafCertificate, // Append the certificate object itself to the output object as well
                            CertificateType.Leaf
                        );

                        finalObject.Add(new ChainPackage(
                            currentChain, // The entire current chain of the certificate
                            currentSignedCms, // The entire current SignedCms object
                            rootCertificate,
                            null,
                            leafCertificate
                        ));

                        break;

                    // If the chain only includes a Root certificate
                    case 1:
                        // The only certificate in the chain is the Root certificate
                        currentRootCertificate = currentChain.ChainElements[0].Certificate;

                        rootCertificate = new ChainElement(
                            CryptoAPI.GetNameString(currentRootCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false), // SubjectCN
                            CryptoAPI.GetNameString(currentRootCertificate.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, true), // IssuerCN
                            currentRootCertificate.NotAfter,
                            CertificateHelper.GetTBSCertificate(currentRootCertificate),
                            currentRootCertificate, // Append the certificate object itself to the output object as well
                            CertificateType.Root
                        );

                        finalObject.Add(new ChainPackage(
                            currentChain, // The entire current chain of the certificate
                            currentSignedCms, // The entire current SignedCms object
                            rootCertificate,
                            null,
                            null
                        ));

                        break;
                    default:
                        break;
                }
            }

            return finalObject;
        }
    }
}
