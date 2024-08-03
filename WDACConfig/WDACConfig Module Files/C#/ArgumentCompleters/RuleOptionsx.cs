using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml;

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
            XmlDocument schemaData = new XmlDocument();
            schemaData.Load(Path.Combine(WDACConfig.GlobalVars.CISchemaPath));

            // Create a namespace manager to handle namespaces
            XmlNamespaceManager nsManager = new XmlNamespaceManager(schemaData.NameTable);
            nsManager.AddNamespace("xs", "http://www.w3.org/2001/XMLSchema");

            // Define the XPath query to fetch enumeration values
            string xpathQuery = "//xs:simpleType[@name='OptionType']/xs:restriction/xs:enumeration/@value";

            // Fetch enumeration values from the schema
            HashSet<string> validOptions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            XmlNodeList optionNodes = schemaData.SelectNodes(xpathQuery, nsManager);
            foreach (XmlNode node in optionNodes)
            {
                validOptions.Add(node.Value);
            }

            // Read PolicyRuleOptions.Json
            string jsonFilePath = Path.Combine(WDACConfig.GlobalVars.ModuleRootPath, "Resources", "PolicyRuleOptions.Json");
            string jsonContent = File.ReadAllText(jsonFilePath);
            Dictionary<string, string> intel = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(jsonContent);

            // Perform validation
            foreach (string key in intel.Values)
            {
                if (!validOptions.Contains(key))
                {
                    throw new Exception($"Invalid Policy Rule Option detected that is not part of the Code Integrity Schema: {key}");
                }
            }

            foreach (string option in validOptions)
            {
                if (!intel.Values.Contains(option, StringComparer.OrdinalIgnoreCase))
                {
                    // this should be a verbose or warning message
                    //    throw new Exception($"Rule option '{option}' exists in the Code Integrity Schema but not being used by the module.");
                }
            }

            return intel.Values.ToArray();
        }
    }
}
