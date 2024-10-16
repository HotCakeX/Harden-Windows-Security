using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text.Json;

#nullable enable

namespace HardenWindowsSecurity
{
    public class CiToolRunner
    {
        /// <summary>
        /// Converts a 64-bit unsigned integer into a version type, used for converting the numbers from CiTool.exe output to proper versions.
        /// </summary>
        /// <param name="number">The 64-bit unsigned integer as a string.</param>
        /// <returns>The parsed version</returns>
        private static Version Measure(string number)
        {
            try
            {
                // Validate input, ensuring it's not null or empty
                if (string.IsNullOrEmpty(number))
                {
                    return new Version(0, 0, 0, 0);
                }

                // Convert the input string to a 64-bit unsigned integer
                if (!ulong.TryParse(number, out ulong num))
                {
                    throw new FormatException("Input string is not a valid 64-bit unsigned integer.");
                }

                // Split the 64-bit integer into four 16-bit segments for the version parts
                ushort part1 = (ushort)((num & 0xFFFF000000000000) >> 48); // Highest 16 bits
                ushort part2 = (ushort)((num & 0x0000FFFF00000000) >> 32); // Next 16 bits
                ushort part3 = (ushort)((num & 0x00000000FFFF0000) >> 16); // Third 16 bits
                ushort part4 = (ushort)(num & 0x000000000000FFFF);         // Lowest 16 bits

                // Form the version string and attempt to parse it into a Version object, don't need the bool output of the parse result
                _ = Version.TryParse($"{part1}.{part2}.{part3}.{part4}"!, out Version? VersionOutput);

                // Return the constructed Version object
                return VersionOutput!;
            }
            catch (Exception ex)
            {
                // Handle errors by printing an error message and returning a default version of 0.0.0.0
                Logger.LogMessage($"Error converting number to version: {ex.Message}", LogTypeIntel.Error);
                return new Version(0, 0, 0, 0);
            }
        }

        public static JsonSerializerOptions GetOptions()
        {
            return new JsonSerializerOptions
            {
                // Ignore case when matching JSON property names
                PropertyNameCaseInsensitive = true,
            };
        }


        /// <summary>
        /// Gets a list of AppControl policies on the system with filtering
        /// </summary>
        /// <param name="SystemPolicies">Will include System policies in the output</param>
        /// <param name="BasePolicies">Will include Base policies in the output</param>
        /// <param name="SupplementalPolicies">Will include Supplemental policies in the output</param>
        /// <returns></returns>
        /// <exception cref="Exception"></exception>
        public static List<CiPolicyInfo> RunCiTool(JsonSerializerOptions options, bool SystemPolicies = false, bool BasePolicies = false, bool SupplementalPolicies = false)
        {
            // Create an empty list of Policy objects to return at the end
            var policies = new List<CiPolicyInfo>();

            // Combine the path to CiTool.exe using the system's special folder path
            string ciToolPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "CiTool.exe");

            // Set up the process start info to run CiTool.exe with necessary arguments
            ProcessStartInfo processStartInfo = new()
            {
                FileName = ciToolPath,
                Arguments = "-lp -json",   // Arguments to list policies and output as JSON
                RedirectStandardOutput = true, // Capture the standard output
                UseShellExecute = false,   // Do not use the OS shell to start the process
                CreateNoWindow = true      // Run the process without creating a window
            };


            // Start the process and capture the output
            using Process? process = Process.Start(processStartInfo) ?? throw new InvalidOperationException("There was a problem running the CiTool.exe in the RunCiTool method.");

            // Read all output as a string
            string jsonOutput = process.StandardOutput.ReadToEnd();

            // Wait for the process to complete
            process.WaitForExit();

            if (process.ExitCode != 0)
            {
                // Throw an exception with the error message
                throw new InvalidOperationException($"Command execution failed with error code {process.ExitCode}");
            }

            // Deserialize the JSON into a JsonElement for easy traversal
            var rootElement = JsonSerializer.Deserialize<JsonElement>(jsonOutput, options);

            // If "Policies" property exists and is an array, start processing each policy
            if (rootElement.TryGetProperty("Policies", out JsonElement policiesElement) && policiesElement.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement policyElement in policiesElement.EnumerateArray())
                {
                    // Create a new Policy object and populate its properties from the JSON data
                    CiPolicyInfo? policy = new()
                    {
                        PolicyID = policyElement.GetPropertyOrDefault("PolicyID", string.Empty),
                        BasePolicyID = policyElement.GetPropertyOrDefault("BasePolicyID", string.Empty),
                        FriendlyName = policyElement.GetPropertyOrDefault("FriendlyName", string.Empty),
                        Version = Measure(policyElement.GetProperty("Version").GetUInt64().ToString(CultureInfo.InvariantCulture)),
                        VersionString = policyElement.GetPropertyOrDefault("VersionString", string.Empty),
                        IsSystemPolicy = policyElement.GetPropertyOrDefault("IsSystemPolicy", false),
                        IsSignedPolicy = policyElement.GetPropertyOrDefault("IsSignedPolicy", false),
                        IsOnDisk = policyElement.GetPropertyOrDefault("IsOnDisk", false),
                        IsEnforced = policyElement.GetPropertyOrDefault("IsEnforced", false),
                        IsAuthorized = policyElement.GetPropertyOrDefault("IsAuthorized", false),
                        PolicyOptions = policyElement.GetPolicyOptionsOrDefault()
                    };

                    // Add the policy to the list based on filtering options

                    // If the policy is System and SystemPolicies parameter was used then add it to the list
                    if (SystemPolicies && policy.IsSystemPolicy) { policies.Add(policy); }

                    // If the policy is Not System, and the policy is Base and BasePolicies parameter was used then add it to the list
                    else if (BasePolicies && !policy.IsSystemPolicy && policy.BasePolicyID == policy.PolicyID) { policies.Add(policy); }

                    // If the policy is Not System, and the policy is supplemental and the SupplementalPolicies parameter was used then add it to the list
                    else if (SupplementalPolicies && !policy.IsSystemPolicy && policy.BasePolicyID != policy.PolicyID) { policies.Add(policy); }
                }

                // Return the list of policies
                return policies;
            }

            // Return an empty list if no policies were found
            return policies;
        }


        /// <summary>
        /// Removes a deployed AppControl policy from the system
        /// </summary>
        /// <param name="policyId">the GUID which is the policy ID of the policy to be removed, with the curly brackets {} wrapped with double quotes "" </param>
        /// <exception cref="ArgumentException"></exception>
        public static void RemovePolicy(string policyId)
        {
            if (string.IsNullOrWhiteSpace(policyId))
            {
                throw new ArgumentException("Policy ID cannot be null or empty.", nameof(policyId));
            }

            // Combine the path to CiTool.exe using the system's special folder path
            string ciToolPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "CiTool.exe");

            // Set up the process start info to run CiTool.exe with necessary arguments
            ProcessStartInfo processStartInfo = new()
            {
                FileName = ciToolPath,
                Arguments = $"--remove-policy \"{{{policyId}}}\" -json",   // Arguments to remove a AppControl policy
                RedirectStandardOutput = true, // Capture the standard output
                UseShellExecute = false,   // Do not use the OS shell to start the process
                CreateNoWindow = true      // Run the process without creating a window
            };

            // Start the process and capture the output
            using Process? process = Process.Start(processStartInfo) ?? throw new InvalidOperationException("There was a problem running the CiTool.exe in the RunCiTool method.");

            // Read all output as a string
            string jsonOutput = process.StandardOutput.ReadToEnd();

            // Wait for the process to complete
            process.WaitForExit();

            if (process.ExitCode != 0)
            {
                // Throw an exception with the error message
                throw new InvalidOperationException($"Command execution failed with error code {process.ExitCode}");
            }
        }
    }

    // Extension methods for JsonElement to simplify retrieving properties with default values
    public static class JsonElementExtensions
    {

        /// <summary>
        /// Retrieves the value of a string property from a JSON element. If the property does not exist
        /// or is not a string, the provided default value is returned.
        /// </summary>
        /// <param name="element">The JSON element from which to retrieve the property.</param>
        /// <param name="propertyName">The name of the property to retrieve.</param>
        /// <param name="defaultValue">The default value to return if the property does not exist or is not a string.</param>
        /// <returns>The value of the property as a string if it exists and is of type string; otherwise, returns the default value.</returns>
        public static string? GetPropertyOrDefault(this JsonElement element, string propertyName, string defaultValue)
        {
            // Attempt to retrieve the property with the specified name from the JSON element.
            // Check if the property exists and if its value is of type string.
            return element.TryGetProperty(propertyName, out JsonElement value) && value.ValueKind == JsonValueKind.String
                // If the property exists and is a string, return its value.
                ? value.GetString()
                // Otherwise, return the provided default value.
                : defaultValue;
        }

        /// <summary>
        /// Retrieves the value of a boolean property from a JSON element. If the property does not exist
        /// or is not a boolean, the provided default value is returned.
        /// </summary>
        /// <param name="element">The JSON element from which to retrieve the property.</param>
        /// <param name="propertyName">The name of the property to retrieve.</param>
        /// <param name="defaultValue">The default value to return if the property does not exist or is not a boolean.</param>
        /// <returns>The value of the property as a boolean if it exists and is of type boolean; otherwise, returns the default value.</returns>
        public static bool GetPropertyOrDefault(this JsonElement element, string propertyName, bool defaultValue)
        {
            // Attempt to retrieve the property with the specified name from the JSON element.
            // Check if the property exists and if its value is of type boolean.
            return element.TryGetProperty(propertyName, out JsonElement value) &&
                   (value.ValueKind == JsonValueKind.True || value.ValueKind == JsonValueKind.False)
                // If the property exists and is of type boolean, return true or false based on the property's value.
                ? value.GetBoolean()
                // Otherwise, return the provided default value.
                : defaultValue;
        }

        /// <summary>
        /// Retrieves a list of policy options from a JSON element. If no policy options are found or the
        /// element is not in the expected format, an empty list is returned.
        /// </summary>
        /// <param name="element">The JSON element containing the policy options.</param>
        /// <returns>A list of policy options as strings. Returns an empty list if no options are found
        /// or if the element is not formatted correctly.</returns>
        public static List<string> GetPolicyOptionsOrDefault(this JsonElement element)
        {
            // Attempt to retrieve the "PolicyOptions" property from the JSON element.
            if (element.TryGetProperty("PolicyOptions", out JsonElement value))
            {
                // Check if the retrieved value is an array.
                if (value.ValueKind == JsonValueKind.Array)
                {
                    // Initialize a new list to hold the policy options.
                    var options = new List<string>();

                    // Iterate through each item in the array.
                    foreach (var item in value.EnumerateArray())
                    {
                        // Get the string representation of the item.
                        var str = item.GetString();

                        // Add the string to the options list if it is not null.
                        if (str is not null)
                        {
                            options.Add(str);
                        }
                    }

                    // Return the list of policy options.
                    return options;
                }
                // Check if the retrieved value is a single string.
                else if (value.ValueKind == JsonValueKind.String)
                {
                    // Get the string representation of the single value.
                    var str = value.GetString();

                    // Return a list containing the single string if it is not null.
                    if (str is not null)
                    {
                        return [str];
                    }
                }
            }

            // If the "PolicyOptions" property is not found or is not in the expected format, return an empty list.
            return [];
        }
    }
}
