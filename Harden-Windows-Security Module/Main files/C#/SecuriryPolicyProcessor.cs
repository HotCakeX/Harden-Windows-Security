using System;
using System.Collections.Generic;
using System.Linq;

namespace HardeningModule
{
    public class SecurityPolicyChecker
    {
        public static List<HardeningModule.IndividualResult> CheckPolicyCompliance(string category)
        {
            List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();
            var csvRecords = HardeningModule.GlobalVars.SecurityPolicyRecords.Where(record => record.Category.Equals(category, StringComparison.OrdinalIgnoreCase)).ToList();

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
