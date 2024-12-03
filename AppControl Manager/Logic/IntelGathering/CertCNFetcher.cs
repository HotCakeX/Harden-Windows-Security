using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace WDACConfig
{
    public static class CertCNFetcher
    {
        public static HashSet<string> GetCertCNs()
        {

            HashSet<string> output = [];

            // Open the current user's personal store
            using (X509Store store = new(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);

                // Loop through each certificate in the current user's personal store
                foreach (X509Certificate2 cert in store.Certificates)
                {
                    // Make sure it uses RSA algorithm (Because ECDSA is not supported for signing App Control policies)
                    if (string.Equals(cert.PublicKey.Oid.FriendlyName, "RSA", StringComparison.OrdinalIgnoreCase))
                    {
                        // Get its Subject Common Name (CN) using the GetNameString method from CryptoAPI
                        string cn = CryptoAPI.GetNameString(cert.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false);

                        // Add the CN to the output set and warn if there is already CN with the same name in the HashSet
                        if (!output.Add(cn))
                        {
                            throw new InvalidOperationException($"There are more than 1 certificates with the common name '{cn}' in the Personal certificate store of the Current User. Delete one of them if you want to use it.");
                        }
                    }
                }
            }

            // Explicitly call ToArray() from Enumerable
            return [.. output];
        }
    }
}
