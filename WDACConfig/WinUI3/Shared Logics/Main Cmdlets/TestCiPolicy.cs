using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Schema;

#nullable enable

namespace WDACConfig
{
    public static class CiPolicyTest
    {
        public static object? TestCiPolicy(string? xmlFilePath, string? cipFilePath)
        {
            // Make sure the parameters are mutually exclusive
            if (!string.IsNullOrEmpty(xmlFilePath) && !string.IsNullOrEmpty(cipFilePath))
            {
                throw new ArgumentException("Only one of xmlFilePath or cipFilePath should be provided.");
            }

            // Check if XML file path was provided
            if (!string.IsNullOrEmpty(xmlFilePath))
            {
                // Get the Code Integrity Schema file path
                string schemaPath = WDACConfig.GlobalVars.CISchemaPath;

                // Make sure the schema file exists
                if (!File.Exists(schemaPath))
                {
                    throw new FileNotFoundException($"The Code Integrity Schema file could not be found at: {schemaPath}");
                }

                // Make sure the input XML file exists
                if (!File.Exists(xmlFilePath))
                {
                    throw new FileNotFoundException($"The file {xmlFilePath} does not exist.");
                }

                // Validate XML file against schema
                try
                {
                    // Create the XmlReaderSettings object
                    XmlReaderSettings settings = new();

                    // Add schema to settings
                    _ = settings.Schemas.Add(null, schemaPath);

                    // Set the validation settings
                    settings.ValidationType = ValidationType.Schema;

                    // Set the validation flags to report warnings
                    settings.ValidationFlags |= XmlSchemaValidationFlags.ReportValidationWarnings;

                    // Set the validation event handler
                    settings.ValidationEventHandler += (sender, args) =>
                    {
                        throw new XmlSchemaValidationException($"Validation error in {xmlFilePath}: {args.Message}");
                    };

                    // Create an XmlDocument object
                    XmlDocument xmlDoc = new();
                    // Load the input XML document
                    xmlDoc.Load(xmlFilePath);

                    using XmlReader reader = XmlReader.Create(new StringReader(xmlDoc.OuterXml), settings);
                    // Validate the XML document
                    while (reader.Read()) { }

                    return true;
                }
                catch (XmlSchemaValidationException ex)
                {
                    throw new InvalidOperationException($"Validation error in {xmlFilePath}: {ex.Message}");
                }
            }

            // Check if CIP file path was provided
            else if (!string.IsNullOrEmpty(cipFilePath))
            {
                // Code to read signed CIP file
                try
                {
                    // Create a new SignedCms object to store the signed message
                    SignedCms signedCms = new();

                    // Decode the signed message from the file specified by cipFilePath
                    // The file is read as a byte array because the SignedCms.Decode() method expects a byte array as input
                    // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.signedcms.decode
                    signedCms.Decode(File.ReadAllBytes(cipFilePath));

                    X509Certificate2Collection certificates = signedCms.Certificates;
                    X509Certificate2[] certificateArray = new X509Certificate2[certificates.Count];
                    certificates.CopyTo(certificateArray, 0);

                    // Return an array of X509Certificate2 objects that represent the certificates used to sign the message
                    return certificateArray;
                }
                catch (CryptographicException)
                {
                    // "The file cipFilePath does not contain a valid signature."
                    return null;
                }
            }
            else
            {
                throw new InvalidOperationException("Either xmlFilePath or cipFilePath must be provided.");
            }
        }
    }
}
