using System;
using System.IO;
using System.Management.Automation;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Xml;
using System.Xml.Schema;

namespace WDACConfig
{
    public static class CiPolicyTest
    {
        public static object TestCiPolicy(FileInfo xmlFile, FileInfo cipFile)
        {
            // Make sure the parameters are mutually exclusive
            if (xmlFile != null && cipFile != null)
            {
                throw new ArgumentException("Only one of XmlFile or CipFile should be provided.");
            }

            // Check if XML File was provided
            if (xmlFile != null)
            {
                // Get the Code Integrity Schema file path
                string schemaPath = WDACConfig.GlobalVars.CISchemaPath;

                // Make sure the schema file exists
                if (!File.Exists(schemaPath))
                {
                    throw new FileNotFoundException($"The Code Integrity Schema file could not be found at: {schemaPath}");
                }

                // Make sure the input XML file exists
                if (!xmlFile.Exists)
                {
                    throw new FileNotFoundException($"The file {xmlFile.FullName} does not exist.");
                }

                // Validate XML file against schema
                try
                {
                    // Create the XmlReaderSettings object
                    XmlReaderSettings settings = new XmlReaderSettings();

                    // Add schema to settings
                    settings.Schemas.Add(null, schemaPath);

                    // Set the validation settings
                    settings.ValidationType = ValidationType.Schema;

                    // Set the validation flags to report warnings
                    settings.ValidationFlags |= XmlSchemaValidationFlags.ReportValidationWarnings;

                    // Set the validation event handler
                    settings.ValidationEventHandler += (sender, args) =>
                    {
                        throw new XmlSchemaValidationException($"Validation error in {xmlFile.FullName}: {args.Message}");
                    };

                    // Create an XmlDocument object
                    XmlDocument xmlDoc = new XmlDocument();
                    // Load the input XML document
                    xmlDoc.Load(xmlFile.FullName);

                    using (XmlReader reader = XmlReader.Create(new StringReader(xmlDoc.OuterXml), settings))
                    {
                        // Validate the XML document
                        while (reader.Read()) { }
                    }

                    return true;
                }
                catch (XmlSchemaValidationException ex)
                {
                    throw new InvalidOperationException($"Validation error in {xmlFile.FullName}: {ex.Message}");
                }
            }

            // Check if CIP File was provided
            else if (cipFile != null)
            {
                // Code to read signed CIP file
                try
                {
                    // Create a new SignedCms object to store the signed message
                    SignedCms signedCms = new SignedCms();

                    // Decode the signed message from the file specified by $CipFile
                    // The file is read as a byte array because the SignedCms.Decode() method expects a byte array as input
                    // https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.signedcms.decode
                    signedCms.Decode(File.ReadAllBytes(cipFile.FullName));

                    X509Certificate2Collection certificates = signedCms.Certificates;
                    X509Certificate2[] certificateArray = new X509Certificate2[certificates.Count];
                    certificates.CopyTo(certificateArray, 0);

                    // Return an array of X509Certificate2 objects that represent the certificates used to sign the message
                    return certificateArray;
                }
                catch (CryptographicException)
                {
                    // "The file CipFile does not contain a valid signature."
                    return null;
                }
            }
            else
            {
                throw new ArgumentNullException("Either XmlFile or CipFile must be provided.");
            }
        }
    }
}
