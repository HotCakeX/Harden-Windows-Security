using System;
using System.Collections.Generic;
using System.Linq;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class PropertyHelper
    {
        /// <summary>
        /// Get the value of a property from a dynamic object
        /// All of the queries made to the dynamic objects GlobalVars.MDAVConfigCurrent or GlobalVars.MDAVPreferencesCurrent
        /// Must go through this method so that their value is acquired properly and in case of nonexistence, null is returned, otherwise direct access to the nonexistent property would lead to error.
        /// If the code that calls this method tries to compare its value using string.Equals, Convert.ToInt or something similar, a default value must be supplied to it via ?? string.Empty or ?? ushort.MaxValue or ?? false/true when this method returns null.
        /// </summary>
        /// <param name="obj"></param>
        /// <param name="propertyName"></param>
        /// <returns></returns>
        public static object? GetPropertyValue(dynamic obj, string propertyName)
        {
            // Convert dynamic object to IDictionary<string, object> to access properties and check for nulls
            if (obj is IDictionary<string, object> dictionary)
            {
                // Find the key in a case-insensitive manner
                var key = dictionary.Keys.FirstOrDefault(k => string.Equals(k, propertyName, StringComparison.OrdinalIgnoreCase));
                if (key is not null)
                {
                    var value = dictionary[key];

                    // Check if the value is null, empty, or whitespace
                    if (value is not null && !(value is string str && string.IsNullOrWhiteSpace(str)))
                    {
                        return value;
                    }
                }
            }

            // Return null if the property does not exist or is null, empty, or whitespace
            return null;
        }
    }
}
