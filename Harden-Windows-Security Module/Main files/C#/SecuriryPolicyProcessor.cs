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
            List<HardenWindowsSecurity.IndividualResult> nestedObjectArray = new List<HardenWindowsSecurity.IndividualResult>();

            // Filter the CSV data to only get the records that match the input category
            var csvRecords = HardenWindowsSecurity.GlobalVars.SecurityPolicyRecords.Where(record => record.Category.Equals(category, StringComparison.OrdinalIgnoreCase)).ToList();

            // Loop over each filtered CSV data
            foreach (var record in csvRecords)
            {
                string section = record.Section;
                string path = record.Path;
                string expectedValue = record.Value;
                string name = record.Name;

                bool complianceResult = false;

                string actualValue = null;

                if (HardenWindowsSecurity.GlobalVars.SystemSecurityPoliciesIniObject.ContainsKey(section) &&
                    HardenWindowsSecurity.GlobalVars.SystemSecurityPoliciesIniObject[section].ContainsKey(path))
                {
                    actualValue = HardenWindowsSecurity.GlobalVars.SystemSecurityPoliciesIniObject[section][path];
                    complianceResult = actualValue == expectedValue;
                }

                nestedObjectArray.Add(new HardenWindowsSecurity.IndividualResult
                {
                    FriendlyName = name,
                    Compliant = complianceResult ? "True" : "False",
                    Value = actualValue,
                    Name = name,
                    Category = category,
                    Method = "Security Group Policy"
                });
            }

            return nestedObjectArray;
        }
    }
}
