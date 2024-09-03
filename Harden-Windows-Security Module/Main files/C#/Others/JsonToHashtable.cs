using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

#nullable enable

namespace HardenWindowsSecurity
{
    internal class JsonToHashtable
    {
        // Using HashTable since they don't throw error for non-existing keys
        // This method acts like ConvertFrom-Json -AsHashtable in PowerShell
        internal static Hashtable ProcessJsonFile(string filePath)
        {
            // Check if the file exists at the specified path
            if (!File.Exists(filePath))
            {
                // Throw an exception if the file does not exist
                throw new FileNotFoundException($"The specified file at '{filePath}' does not exist.");
            }

            // Read the JSON file content as a string
            string jsonContent = File.ReadAllText(filePath);

            // Parse the JSON content into a JsonDocument
            JsonDocument jsonDocument = JsonDocument.Parse(jsonContent);

            // Convert the root element of the JsonDocument to a Hashtable and return it
            return ConvertJsonElementToHashtable(jsonDocument.RootElement);
        }

        // Private method to convert a JsonElement representing a JSON object into a Hashtable
        private static Hashtable ConvertJsonElementToHashtable(JsonElement jsonElement)
        {
            // Create a new Hashtable to store the key-value pairs
            Hashtable hashtable = new Hashtable();

            // Enumerate through all properties of the JSON object
            foreach (JsonProperty property in jsonElement.EnumerateObject())
            {
                // Check the type of the JSON value
                if (property.Value.ValueKind == JsonValueKind.Object)
                {
                    // If the value is a nested object, recursively convert it to a Hashtable
                    hashtable[property.Name] = ConvertJsonElementToHashtable(property.Value);
                }
                else if (property.Value.ValueKind == JsonValueKind.Array)
                {
                    // If the value is an array, convert it to an ArrayList
                    hashtable[property.Name] = ConvertJsonArrayToArrayList(property.Value);
                }
                else
                {
                    // For primitive values, add them directly to the Hashtable
                    hashtable[property.Name] = property.Value.ToString();
                }
            }

            // Return the constructed Hashtable
            return hashtable;
        }

        // Private method to convert a JsonElement representing a JSON array into an ArrayList
        private static ArrayList ConvertJsonArrayToArrayList(JsonElement jsonArray)
        {
            // Create a new ArrayList to store the elements
            ArrayList arrayList = new ArrayList();

            // Enumerate through all elements of the JSON array
            foreach (JsonElement item in jsonArray.EnumerateArray())
            {
                // Check the type of the JSON element
                if (item.ValueKind == JsonValueKind.Object)
                {
                    // If the element is an object, recursively convert it to a Hashtable
                    arrayList.Add(ConvertJsonElementToHashtable(item));
                }
                else if (item.ValueKind == JsonValueKind.Array)
                {
                    // If the element is an array, recursively convert it to an ArrayList
                    arrayList.Add(ConvertJsonArrayToArrayList(item));
                }
                else
                {
                    // For primitive values, add them directly to the ArrayList
                    arrayList.Add(item.ToString());
                }
            }

            // Return the constructed ArrayList
            return arrayList;
        }
    }
}
