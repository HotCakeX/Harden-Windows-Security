using System;
using System.Linq;
using System.Collections.Generic;

#nullable enable

namespace HardenWindowsSecurity
{
    public class GetMDMResultValue
    {
        /// <summary>
        /// Get the value of a specific MDM result in a resilient way so if the property or value don't exist then return false instead of throwing errors
        /// </summary>
        /// <param name="propertyName">The Name of the MDM object to use the filter the results by</param>
        /// <param name="comparisonValue">This value will be used in comparison with the value property of the MDM object we find after filtering</param>
        /// <returns></returns>
        public static bool Get(string propertyName, string comparisonValue)
        {
            try
            {
                // Ensure the list is not null
                if (GlobalVars.MDMResults == null)
                {
                    return false;
                }

                // Query the list
                var result = GlobalVars.MDMResults
                    .Where(element => element != null && element.Name == propertyName)
                    .Select(element => element.Value as string) // Value is cast to string
                    .FirstOrDefault();

                // Perform the comparison
                if (result != null && result.Equals(comparisonValue, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}
