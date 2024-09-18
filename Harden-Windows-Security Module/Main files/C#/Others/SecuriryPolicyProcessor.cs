using System;
using System.Collections.Generic;
using System.Linq;

#nullable enable

namespace HardenWindowsSecurity
{
    public class SecurityPolicyChecker
    {
        /// <summary>
        /// The method is used to verify the compliance of security group policies on the system against the predefined values in the SecurityPoliciesVerification.csv
        /// </summary>
        /// <param name="category">The category to filter the CSV file content by</param>
        /// <returns></returns>
        public static List<HardenWindowsSecurity.IndividualResult> CheckPolicyCompliance(string category)
        {
            // Create a list of IndividualResult objects
            List<HardenWindowsSecurity.IndividualResult> nestedObjectArray = [];

            // Filter the CSV data to only get the records that match the input category
            var csvRecords = HardenWindowsSecurity.GlobalVars.SecurityPolicyRecords?
                .Where(record => record.Category != null && record.Category.Equals(category, StringComparison.OrdinalIgnoreCase))
                .ToList();

            // Ensure csvRecords is not null before iterating
            if (csvRecords != null)
            {
                // Loop over each filtered CSV data
                foreach (var record in csvRecords)
                {
                    string? section = record.Section;
                    string? path = record.Path;
                    string? expectedValue = record.Value;
                    string? name = record.Name;

                    bool complianceResult = false;

                    string? actualValue = null;

                    // Ensure SystemSecurityPoliciesIniObject is not null and check for section
                    if (HardenWindowsSecurity.GlobalVars.SystemSecurityPoliciesIniObject != null &&
                        section != null && // Check if section is not null
                        HardenWindowsSecurity.GlobalVars.SystemSecurityPoliciesIniObject.TryGetValue(section, out var sectionDict) &&
                        sectionDict != null &&
                        path != null && // Check if path is not null
                        sectionDict.TryGetValue(path, out string? value))
                    {
                        actualValue = value;
                        complianceResult = actualValue == expectedValue;
                    }

                    nestedObjectArray.Add(new HardenWindowsSecurity.IndividualResult
                    {
                        FriendlyName = name,
                        Compliant = complianceResult,
                        Value = actualValue,
                        Name = name,
                        Category = category,
                        Method = "Security Group Policy"
                    });
                }
            }
            else
            {
                throw new InvalidOperationException("CSV Records cannot be null.");
            }

            return nestedObjectArray;
        }
    }
}
