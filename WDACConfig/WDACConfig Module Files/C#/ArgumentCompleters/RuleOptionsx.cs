using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    public interface IValidateSetValuesGenerator
    {
        string[] GetValidValues();
    }

    public class RuleOptionsx : IValidateSetValuesGenerator
    {

        public string[] GetValidValues()
        {
            // Load the CI Schema content
            XmlDocument schemaData = new();
            schemaData.Load(Path.Combine(WDACConfig.GlobalVars.CISchemaPath));

            // Create a namespace manager to handle namespaces
            XmlNamespaceManager nsManager = new(schemaData.NameTable);
            nsManager.AddNamespace("xs", "http://www.w3.org/2001/XMLSchema");

            // Define the XPath query to fetch enumeration values
            string xpathQuery = "//xs:simpleType[@name='OptionType']/xs:restriction/xs:enumeration/@value";

            // Create a new HashSet to store the valid policy rule options
            HashSet<string> validOptions = new(StringComparer.OrdinalIgnoreCase);

            // Fetch enumeration values from the schema
            XmlNodeList? optionNodes = schemaData.SelectNodes(xpathQuery, nsManager) ?? throw new InvalidOperationException("No valid options found in the Code Integrity Schema.");

            foreach (XmlNode node in optionNodes)
            {
                if (node.Value != null)
                {
                    _ = validOptions.Add(node.Value);
                }
            }

            if (WDACConfig.GlobalVars.ModuleRootPath == null)
            {
                throw new InvalidOperationException("ModuleRootPath is null!");
            }

            // Construct the full path to PolicyRuleOptions.Json
            string jsonFilePath = Path.Combine(WDACConfig.GlobalVars.ModuleRootPath, "Resources", "PolicyRuleOptions.Json");

            // Read PolicyRuleOptions.Json
            string jsonContent = File.ReadAllText(jsonFilePath);

            // Deserialize the JSON content
            Dictionary<string, string>? intel = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(jsonContent) ?? throw new InvalidOperationException("The PolicyRuleOptions.Json file did not have valid JSON content to be deserialized.");

            // Perform validation
            foreach (string key in intel.Values)
            {
                if (!validOptions.Contains(key))
                {
                    throw new InvalidOperationException($"Invalid Policy Rule Option detected that is not part of the Code Integrity Schema: {key}");
                }
            }

            foreach (string option in validOptions)
            {
                if (!intel.Values.Contains(option, StringComparer.OrdinalIgnoreCase))
                {
                    // this should be a verbose or warning message
                    // throw new Exception($"Rule option '{option}' exists in the Code Integrity Schema but not being used by the module.");
                }
            }

            return intel.Values.ToArray();
        }
    }
}
