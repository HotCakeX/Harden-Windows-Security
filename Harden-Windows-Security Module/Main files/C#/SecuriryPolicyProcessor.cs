using System;
using System.Collections.Generic;
using System.Linq;

namespace HardeningModule
{
    public class SecurityPolicyChecker
    {
        /// <summary>
        /// The method is used to verify the compliance of security group policies on the system against the predefined values in the SecurityPoliciesVerification.csv
        /// </summary>
        /// <param name="category">The category to filter the CSV file content by</param>
        /// <returns></returns>
        public static List<HardeningModule.IndividualResult> CheckPolicyCompliance(string category)
        {
            // Create a list of IndividualResult objects
            List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

            // Filter the CSV data to only get the records that match the input category
            var csvRecords = HardeningModule.GlobalVars.SecurityPolicyRecords.Where(record => record.Category.Equals(category, StringComparison.OrdinalIgnoreCase)).ToList();

            // Loop over each filtered CSV data
            foreach (var record in csvRecords)
            {
                string section = record.Section;
                string path = record.Path;
                string expectedValue = record.Value;
                string name = record.Name;

                bool complianceResult = false;

                string actualValue = null;

                if (HardeningModule.GlobalVars.SystemSecurityPoliciesIniObject.ContainsKey(section) &&
                    HardeningModule.GlobalVars.SystemSecurityPoliciesIniObject[section].ContainsKey(path))
                {
                    actualValue = HardeningModule.GlobalVars.SystemSecurityPoliciesIniObject[section][path];
                    complianceResult = actualValue == expectedValue;
                }

                nestedObjectArray.Add(new HardeningModule.IndividualResult
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
