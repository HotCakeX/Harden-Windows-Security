using System;
using System.Collections.Generic;
using System.Dynamic;

namespace HardeningModule
{
    public static class DynamicPropertyHelper
    {
        /// <summary>
        /// Safely retrieves the value of a specified property from a dynamic object.
        /// </summary>
        /// <param name="dynamicObject">The dynamic object to query.</param>
        /// <param name="propertyName">The name of the property to retrieve.</param>
        /// <returns>The value of the property if found, otherwise null.</returns>
        public static object GetPropertyValue(dynamic dynamicObject, string propertyName)
        {
            // Check if the dynamic object is not null and is of the expected type
            if (dynamicObject is IDictionary<string, object> dictionary)
            {
                // Check if the property exists in the dictionary
                if (dictionary.ContainsKey(propertyName))
                {
                    try
                    {
                        // Return the property value
                        return dictionary[propertyName];
                    }
                    catch (Exception ex)
                    {
                        // Log or handle the exception as needed
                        Console.WriteLine($"Error retrieving property '{propertyName}': {ex.Message}");
                    }
                }
                else
                {
                    Console.WriteLine($"Property '{propertyName}' does not exist.");
                }
            }
            else
            {
                Console.WriteLine("The dynamic object is not of type IDictionary<string, object>.");
            }

            // Return null if property is not found or if any error occurs
            return null;
        }
    }
}
