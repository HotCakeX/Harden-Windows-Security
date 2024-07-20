using System;
using System.Collections.Generic;
using System.Xml;

namespace HardeningModule
{
    public static class MitigationPolicyProcessor
    {
        // This method processes the exploit mitigation policies of the current system and returns a dictionary of the mitigations applied to each executable
        public static Dictionary<string, HashSet<string>> ProcessMitigationPolicies(string xmlPath)
        {
            // Load the XML document
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load(xmlPath);

            // Initialize the dictionary to store the output of the current system's exploit mitigation policy XML file exported by the Get-ProcessMitigation cmdlet
            Dictionary<string, HashSet<string>> processMitigations = new Dictionary<string, HashSet<string>>();

            // Get all AppConfig elements in the XML document
            XmlNodeList appConfigNodes = xmlDoc.SelectNodes("//MitigationPolicy/AppConfig");

            // Loop through each AppConfig element in the XML document
            foreach (XmlNode appNode in appConfigNodes)
            {
                // Get the executable name of the app
                string executableName = appNode.Attributes["Executable"].Value;

                // Create a hash set to store the mitigations
                HashSet<string> mitigations = new HashSet<string>();

                // Loop through each child element of the app element
                foreach (XmlNode childNode in appNode.ChildNodes)
                {
                    // Get the name of the mitigation
                    string mitigationName = childNode.Name;

                    // Loop through each attribute of the child element
                    foreach (XmlAttribute attribute in childNode.Attributes)
                    {
                        // Get the name and value of the attribute
                        string attributeName = attribute.Name;
                        string attributeValue = attribute.Value;

                        // If the attribute value is true, add it to the hash set
                        // We don't include the mitigations that are disabled/set to false
                        // For example, some poorly designed git apps are incompatible with mandatory ASLR
                        // And they pollute the output of the Get-ProcessMitigation cmdlet with items such as "<ASLR ForceRelocateImages="false" RequireInfo="false" />"
                        if (attributeValue.Equals("true", StringComparison.OrdinalIgnoreCase))
                        {
                            // If the attribute name is Enable, use the mitigation name instead, because we only need the names of the mitigations that are enabled for comparison with the CSV file.
                            // Some attributes such as "<StrictHandle Enable="true" />" don't have a name so we add the mitigation's name to the array instead, which is "StrictHandle" in this case.
                            if (attributeName.Equals("Enable", StringComparison.OrdinalIgnoreCase))
                            {
                                // Add the mitigation name to the hash set
                                mitigations.Add(mitigationName);
                            }
                            else
                            {
                                // Add the attribute name to the hash set
                                mitigations.Add(attributeName);
                            }
                        }
                    }
                }

                // Make sure the array isn't empty which filters out apps with no mitigations or mitigations that are all disabled/set to false
                if (mitigations.Count > 0)
                {
                    // Add the executable and its mitigations to the dictionary
                    processMitigations[executableName] = mitigations;
                }
            }

            // Create a new empty hashtable which replaces "StrictControlFlowGuard" with "StrictCFG" and "ControlFlowGuard" with "CFG"
            // since the shortened name is used in the CSV file and required by the the Set-ProcessMitigation cmdlet
            Dictionary<string, HashSet<string>> revisedProcessMitigations = new Dictionary<string, HashSet<string>>();

            // Loop over the keys and values of the original dictionary
            foreach (var kvp in processMitigations)
            {
                // Get the value set for the current key
                HashSet<string> valueSet = kvp.Value;

                // Replace "StrictControlFlowGuard" with "StrictCFG" in the value set
                // Replace "ControlFlowGuard" with "CFG" in the value set
                HashSet<string> revisedValueSet = new HashSet<string>();
                foreach (var value in valueSet)
                {
                    // Check if the value is "StrictControlFlowGuard" and replace it with "StrictCFG"
                    if (value.Equals("StrictControlFlowGuard", StringComparison.OrdinalIgnoreCase))
                    {
                        // Add "StrictCFG" to the revised value set instead of "StrictControlFlowGuard"
                        revisedValueSet.Add("StrictCFG");
                    }
                    // Check if the value is "ControlFlowGuard" and replace it with "CFG"
                    else if (value.Equals("ControlFlowGuard", StringComparison.OrdinalIgnoreCase))
                    {
                        // Add "CFG" to the revised value set instead of "ControlFlowGuard"
                        revisedValueSet.Add("CFG");
                    }
                    else
                    {
                        // Add the original value to the revised value set if it's not "ControlFlowGuard" or "StrictControlFlowGuard"
                        revisedValueSet.Add(value);
                    }
                }

                // Add the modified key-value pair to the new dictionary
                revisedProcessMitigations[kvp.Key] = revisedValueSet;
            }

            return revisedProcessMitigations;
        }
    }
}
