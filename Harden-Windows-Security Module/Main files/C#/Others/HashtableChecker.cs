using System;
using System.Collections;
using System.Collections.Generic;

#nullable enable

namespace HardenWindowsSecurity
{
    // Class to hold the result of the hashtable check
    internal class HashtableCheckerResult
    {
        internal bool IsMatch { get; set; } // Indicates if the value matches
        internal string? Value { get; set; } // The value from the hashtable if found
    }

    // Static class containing the method to check values in a hashtable
    internal static class HashtableChecker
    {
        /// <summary>
        /// Method to check if a value in the hashtable matches the supplied value
        /// </summary>
        /// <typeparam name="T">We supply the type to be used during comparison</typeparam>
        /// <param name="hashtable">The hashtable containing the MDM parsed result that we're gonna use to query</param>
        /// <param name="key">The key to be used against the Hashtable in order to get the value</param>
        /// <param name="compareValue">Our desired value which will be compared against the value found in the Hashtable after finding it based on the key we supply</param>
        /// <returns></returns>
        internal static HashtableCheckerResult CheckValue<T>(Hashtable hashtable, string key, T compareValue)
        {
            // Initialize the result object
            var result = new HashtableCheckerResult();

            // Check if the hashtable contains the specified key
            if (hashtable.ContainsKey(key))
            {
                // Retrieve the value associated with the key
                var value = hashtable[key];

                // If the value is not null and is of the expected type
                if (value != null && value is T)
                {
                    bool isMatch = false;

                    // Check if the type is a string
                    if (typeof(T) == typeof(string))
                    {
                        // Perform case-insensitive comparison for strings
                        isMatch = string.Equals(value as string, compareValue as string, StringComparison.OrdinalIgnoreCase);
                    }
                    // Check if the type is a string array
                    else if (typeof(T) == typeof(string[]))
                    {
                        var valueArray = value as string[];
                        var compareArray = compareValue as string[];

                        // Ensure both arrays are not null and have the same length
                        if (valueArray != null && compareArray != null && valueArray.Length == compareArray.Length)
                        {
                            isMatch = true;

                            // Compare each element in the arrays case-insensitively
                            for (int i = 0; i < valueArray.Length; i++)
                            {
                                if (!string.Equals(valueArray[i], compareArray[i], StringComparison.OrdinalIgnoreCase))
                                {
                                    isMatch = false;
                                    break;
                                }
                            }
                        }
                    }
                    // Default comparison for other types
                    else
                    {
                        isMatch = EqualityComparer<T>.Default.Equals((T)value, compareValue);
                    }

                    // If a match is found, set the result properties accordingly
                    if (isMatch)
                    {
                        result.IsMatch = true;
                        result.Value = value.ToString();
                        return result;
                    }
                }
            }

            // If no match is found, set the result properties to indicate no match
            result.IsMatch = false;
            result.Value = string.Empty;
            return result;
        }
    }
}
