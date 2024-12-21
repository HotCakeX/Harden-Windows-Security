using System;
using System.Collections;
using System.Collections.Generic;

namespace HardenWindowsSecurity;

    // Class to hold the result of the HashTable check
    internal sealed class HashTableCheckerResult
    {
        internal bool IsMatch { get; set; } // Indicates if the value matches
        internal string? Value { get; set; } // The value from the HashTable if found
    }

    // Static class containing the method to check values in a HashTable
    internal static class HashTableChecker
    {
        /// <summary>
        /// Method to check if a value in the HashTable matches the supplied value
        /// </summary>
        /// <typeparam name="T">We supply the type to be used during comparison</typeparam>
        /// <param name="hashTable">The HashTable containing the MDM parsed result that we're gonna use to query</param>
        /// <param name="key">The key to be used against the HashTable in order to get the value</param>
        /// <param name="compareValue">Our desired value which will be compared against the value found in the HashTable after finding it based on the key we supply</param>
        /// <returns></returns>
        internal static HashTableCheckerResult CheckValue<T>(Hashtable? hashTable, string key, T compareValue)
        {
            // Initialize the result object
            HashTableCheckerResult result = new();

            // Check if the HashTable contains the specified key
            if (hashTable is not null && hashTable.ContainsKey(key))
            {
                // Retrieve the value associated with the key
                var value = hashTable[key];

                // If the value is not null and is of the expected type
                if (value is not null && value is T t)
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
                        // Ensure both arrays are not null and have the same length
                        if (value is string[] valueArray && compareValue is string[] compareArray && valueArray.Length == compareArray.Length)
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
                        isMatch = EqualityComparer<T>.Default.Equals(t, compareValue);
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
