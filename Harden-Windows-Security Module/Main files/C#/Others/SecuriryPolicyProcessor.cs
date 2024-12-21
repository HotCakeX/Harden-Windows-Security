using System;
using System.Collections.Generic;
using System.Linq;

namespace HardenWindowsSecurity;

    internal static class SecurityPolicyChecker
    {
        /// <summary>
        /// The method is used to verify the compliance of security group policies on the system against the predefined values in the SecurityPoliciesVerification.csv
        /// </summary>
        /// <param name="category">The category to filter the CSV file content by</param>
        /// <returns></returns>
        internal static List<IndividualResult> CheckPolicyCompliance(ComplianceCategories category)
        {
            // Create a list of IndividualResult objects
            List<IndividualResult> nestedObjectArray = [];

            // Filter the CSV data to only get the records that match the input category
            List<SecurityPolicyRecord>? csvRecords = GlobalVars.SecurityPolicyRecords?
                .Where(record => record.Category == category)
                .ToList();

            // Ensure csvRecords is not null before iterating
            if (csvRecords is not null)
            {
                // Loop over each filtered CSV data
                foreach (SecurityPolicyRecord record in csvRecords)
                {
                    string? section = record.Section;
                    string? path = record.Path;
                    string? expectedValue = record.Value;
                    string? name = record.Name;

                    bool complianceResult = false;

                    string? actualValue = null;

                    // Ensure SystemSecurityPoliciesIniObject is not null and check for section
                    if (section is not null && // Check if section is not null
                        GlobalVars.SystemSecurityPoliciesIniObject.TryGetValue(section, out var sectionDict) &&
                        sectionDict is not null &&
                        path is not null && // Check if path is not null
                        sectionDict.TryGetValue(path, out string? value))
                    {
                        actualValue = value;
                        complianceResult = actualValue == expectedValue;
                    }

                    nestedObjectArray.Add(new IndividualResult
                    {
                        FriendlyName = name ?? string.Empty,
                        Compliant = complianceResult,
                        Value = actualValue,
                        Name = name ?? string.Empty,
                        Category = category,
                        Method = ConfirmSystemComplianceMethods.Method.SecurityGroupPolicy
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
