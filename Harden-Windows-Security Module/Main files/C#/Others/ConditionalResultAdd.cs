using System;
using System.Collections.Generic;
using System.Linq;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class ConditionalResultAdd
    {
        /// <summary>
        /// The method to add a result to the results list based on the Compliant status of the item.
        /// The foreach loops in the ConfirmSystemComplianceMethods.cs file must all be located at the end of each category's method for this mechanism to be accurate and effective.
        /// </summary>
        /// <param name="nestedObjectArray">A reference to the NestedObjectsArray List from the parent method so we can conditionally modify it</param>
        /// <param name="result">The current item that must be conditionally added to the List</param>
        public static void Add(List<IndividualResult> nestedObjectArray, IndividualResult result)
        {
            // Check if there is already an instance with the FriendlyName
            var existingItem = nestedObjectArray.FirstOrDefault(item => string.Equals(item.FriendlyName, result.FriendlyName, StringComparison.OrdinalIgnoreCase));

            if (existingItem is not null)
            {
                // Check the Compliant status of the existing item in the results list
                // If the item already exists and is Non-compliant
                if (!existingItem.Compliant)
                {
                    // Check the Compliant status of the current item being added to the results list
                    if (result.Compliant)
                    {
                        // Remove the existing item with Compliant status "False"
                        _ = nestedObjectArray.Remove(existingItem);
                        // Add the current item with Compliant status "True"
                        nestedObjectArray.Add(result);
                        Logger.LogMessage($"Item with Name '{existingItem.Name}' and FriendlyName '{existingItem.FriendlyName}' replaced with a compliant item.", LogTypeIntel.Information);
                    }
                    else
                    {
                        // Write a descriptive and detailed message to the console
                        Logger.LogMessage($"Item not added: An item with Name '{existingItem.Name}' and FriendlyName '{existingItem.FriendlyName}' already exists with Compliant status '{existingItem.Compliant}' and Value '{existingItem.Value}'.", LogTypeIntel.Information);
                    }
                }
                //    else
                //   {
                // If the item already exists and is compliant then do nothing
                //    }
            }
            else
            {
                nestedObjectArray.Add(result);
            }
        }
    }
}
