using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    public partial class GetFileRuleOutput
    {
        /// <summary>
        /// A function that accepts an App Control policy XML content and creates an output array that contains the file rules that are based on file hashes.
        /// The function is intentionally not made to handle Allow all rules since checking for their existence happens in the main cmdlet.
        /// </summary>
        /// <param name="xml"></param>
        /// <returns></returns>
        public static HashSet<PolicyHashObj> Get(XmlDocument xml)
        {
            // Create an empty HashSet to store the output
            HashSet<PolicyHashObj> outputHashInfoProcessing = [];

            // Get the namespace manager
            XmlNamespaceManager nsmgr = new(xml.NameTable);
            nsmgr.AddNamespace("si", "urn:schemas-microsoft-com:sipolicy");

            // Loop through each file rule in the XML file
            XmlNodeList? fileRules = xml.SelectNodes("//si:FileRules/si:Allow", nsmgr);
            if (fileRules is not null)
            {
                foreach (XmlNode fileRule in fileRules)
                {
                    if (fileRule.Attributes is not null)
                    {
                        // Extract the hash value from the Hash attribute
                        string? hashValue = fileRule.Attributes["Hash"]?.InnerText;

                        // Extract the hash type and file path from the FriendlyName attribute using regex
                        string? friendlyName = fileRule.Attributes["FriendlyName"]?.InnerText;
                        if (!string.IsNullOrEmpty(friendlyName))
                        {
                            // Extract the hash type from the FriendlyName attribute using regex
                            Match hashTypeMatch = MyRegex().Match(friendlyName);
                            string hashType = hashTypeMatch.Success ? hashTypeMatch.Groups[1].Value : string.Empty;

                            // Extract the file path from the FriendlyName attribute using regex
                            string filePathForHash = MyRegex1().Replace(friendlyName, string.Empty);

                            // Add the extracted values of the current Hash rule to the output HashSet
                            if (!string.IsNullOrEmpty(hashValue) && !string.IsNullOrEmpty(hashType) && !string.IsNullOrEmpty(filePathForHash))
                            {
                                _ = outputHashInfoProcessing.Add(new PolicyHashObj(hashValue, hashType, filePathForHash));
                            }
                        }
                    }
                }
            }

            // Only keep the Authenticode Hash SHA256
            outputHashInfoProcessing = new HashSet<PolicyHashObj>(outputHashInfoProcessing.Where(obj => string.Equals(obj.HashType, "Hash Sha256", StringComparison.OrdinalIgnoreCase)));

            Logger.Write($"Returning {outputHashInfoProcessing.Count} file rules that are based on file hashes");

            // Return the output HashSet
            return outputHashInfoProcessing;
        }

        [GeneratedRegex(@".* (Hash (Sha1|Sha256|Page Sha1|Page Sha256|Authenticode SIP Sha256))$", RegexOptions.Compiled | RegexOptions.IgnoreCase)]
        private static partial Regex MyRegex();

        [GeneratedRegex(@" (Hash (Sha1|Sha256|Page Sha1|Page Sha256|Authenticode SIP Sha256))$", RegexOptions.Compiled | RegexOptions.IgnoreCase)]
        private static partial Regex MyRegex1();

    }
}
