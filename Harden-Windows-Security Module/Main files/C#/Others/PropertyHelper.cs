using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;

#nullable enable

namespace HardenWindowsSecurity
{
    internal static class PropertyHelper
    {
        // Get the value of a property from a dynamic object
        internal static object? GetPropertyValue(dynamic obj, string propertyName)
        {
            // Convert dynamic object to IDictionary<string, object> to access properties
            var dictionary = obj as IDictionary<string, object>;

            // Check if the dictionary is not null
            if (dictionary != null)
            {
                // Find the key in a case-insensitive manner
                var key = dictionary.Keys.FirstOrDefault(k => string.Equals(k, propertyName, StringComparison.OrdinalIgnoreCase));
                if (key != null)
                {
                    var value = dictionary[key];

                    // Check if the value is null, empty, or whitespace
                    if (value != null && !(value is string str && string.IsNullOrWhiteSpace(str)))
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
