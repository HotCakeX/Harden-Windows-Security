using System;
using System.Collections.Generic;

#nullable enable

namespace WDACConfig
{
    public class BasePolicyNamez : IValidateSetValuesGenerator
    {
        // Argument tab auto-completion and ValidateSet for Non-System Policy names
        public string[] GetValidValues()
        {
            List<CiPolicyInfo>? BasePolicies = CiToolHelper.GetPolicies(false, true, false);

            if (BasePolicies is not null)
            {
                List<string> BasePolicyNames = [];
                foreach (CiPolicyInfo policy in BasePolicies)
                {
                    if (policy.FriendlyName is not null)
                    {
                        BasePolicyNames.Add(policy.FriendlyName);
                    }
                }
                return BasePolicyNames.ToArray();
            }
            else
            {
                return Array.Empty<string>();
            }
        }
    }
}
