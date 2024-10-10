using System;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

#nullable enable

namespace WDACConfig
{
    // A class to throw a custom exception when the certificate collection cannot be obtained during WDAC Simulation
    public class ExceptionFailedToGetCertificateCollection(string message, string functionName) : Exception($"{functionName}: {message}")
    {
    }

    public class CertificateHelper
    {
        public static string GetTBSCertificate(X509Certificate2 cert)
        // Calculates the TBS value of a certificate
        {
            // Get the raw data of the certificate
            byte[] rawData = cert.RawData;

            // Create an ASN.1 reader to parse the certificate
            AsnReader asnReader = new(rawData, AsnEncodingRules.DER);

            // Read the certificate sequence
            AsnReader certificate = asnReader.ReadSequence();

            // Read the TBS (To be signed) value of the certificate
            ReadOnlyMemory<byte> tbsCertificate = certificate.ReadEncodedValue();

            // Read the signature algorithm sequence
            AsnReader signatureAlgorithm = certificate.ReadSequence();

            // Read the algorithm OID of the signature
            string algorithmOid = signatureAlgorithm.ReadObjectIdentifier();

            // Define a hash function based on the algorithm OID
            HashAlgorithm hashFunction = algorithmOid switch
            {
                "1.2.840.113549.1.1.4" => MD5.Create(),
                "1.2.840.113549.1.1.5" or "1.3.14.3.2.29" => SHA1.Create(), // sha-1WithRSAEncryption
                "1.2.840.113549.1.1.11" => SHA256.Create(),
                "1.2.840.113549.1.1.12" => SHA384.Create(),
                "1.2.840.113549.1.1.13" => SHA512.Create(),
                // These are less likely to be used since Code Integrity doesn't support their OIDs
                "1.2.840.10040.4.3" => SHA1.Create(),
                "2.16.840.1.101.3.4.3.2" => SHA256.Create(),
                "2.16.840.1.101.3.4.3.3" => SHA384.Create(),
                "2.16.840.1.101.3.4.3.4" => SHA512.Create(),
                "1.2.840.10045.4.1" => SHA1.Create(),
                "1.2.840.10045.4.3.2" => SHA256.Create(),
                "1.2.840.10045.4.3.3" => SHA384.Create(),
                "1.2.840.10045.4.3.4" => SHA512.Create(),
                _ => throw new InvalidOperationException($"No handler for algorithm {algorithmOid}"),
            };
            using (hashFunction)
            {
                // Compute the hash of the TBS value using the hash function
                byte[] hash = hashFunction.ComputeHash(tbsCertificate.ToArray());

                // Convert the hash to a hex string
                string hexStringOutput = Convert.ToHexString(hash);

                return hexStringOutput;
            }
        }

        public static string ConvertHexToOID(string hex)
        // Converts a hexadecimal string to an OID
        // Used for converting hexadecimal values found in the EKU sections of the WDAC policies to their respective OIDs.
        {
            if (string.IsNullOrEmpty(hex))
            {
                throw new ArgumentException("Hex string cannot be null or empty", nameof(hex));
            }

            // Convert the hexadecimal string to a byte array by looping through the string in pairs of two characters
            // and converting each pair to a byte using the base 16 (hexadecimal) system
            byte[] numArray = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
            {
                numArray[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            }

            // Change the first byte from 1 to 6 because the hexadecimal string is missing the tag and length bytes
            // that are required for the ASN.1 encoding of an OID
            // The tag byte indicates the type of the data, and for an OID it is 6
            // The length byte indicates the number of bytes that follow the tag byte
            // and for this example it is 10 (0A in hexadecimal)
            numArray[0] = 6;

            // Create an AsnReader object with the default encoding rules
            // This is a class that can read the ASN.1 BER, CER, and DER data formats
            // BER (Basic Encoding Rules) is the most flexible and widely used encoding rule
            // CER (Canonical Encoding Rules) is a subset of BER that ensures a unique encoding
            // DER (Distinguished Encoding Rules) is a subset of CER that ensures a deterministic encoding
            // The AsnReader object takes the byte array as input and the encoding rule as an argument
            AsnReader asnReader = new(numArray, AsnEncodingRules.BER);

            // Read the OID as an ObjectIdentifier
            // This is a method of the AsnReader class that returns the OID as a string
            // The first two numbers are derived from the first byte of the encoded data
            // The rest of the numbers are derived from the subsequent bytes using a base 128 (variable-length) system
            string oid = asnReader.ReadObjectIdentifier();

            // Return the OID value as string
            return oid;
        }
    }
}
