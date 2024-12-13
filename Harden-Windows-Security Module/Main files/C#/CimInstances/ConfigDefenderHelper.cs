using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Management;

namespace HardenWindowsSecurity
{
    internal static class ConfigDefenderHelper
    {
        // Get the MpComputerStatus from the MSFT_MpComputerStatus WMI class and returns it as a dynamic object
        internal static dynamic GetMpComputerStatus()
        {
            try
            {
                // Define the WMI query to retrieve the MpComputerStatus
                string namespaceName = "ROOT\\Microsoft\\Windows\\Defender";
                string className = "MSFT_MpComputerStatus";
                string queryString = $"SELECT * FROM {className}";

                // Execute the query
                using ManagementObjectSearcher searcher = new(namespaceName, queryString);
                ManagementObjectCollection results = searcher.Get();

                // Make sure the results isn't empty
                if (results.Count > 0)
                {
                    ManagementBaseObject? result = results.Cast<ManagementBaseObject>().FirstOrDefault();

                    if (result is not null)
                    {

                        return ConvertToDynamic(result);
                    }
                    else
                    {
                        throw new InvalidOperationException("Failed to get MpComputerStatus!");
                    }
                }
                else
                {
                    throw new PowerShellExecutionException("WMI query for 'MSFT_MpComputerStatus' failed");
                }
            }
            catch (ManagementException ex)
            {
                string errorMessage = $"WMI query for 'MSFT_MpComputerStatus' failed: {ex.Message}";
                throw new PowerShellExecutionException(errorMessage, ex);
            }
        }

        // Convert the ManagementBaseObject to a dynamic object
        private static dynamic ConvertToDynamic(ManagementBaseObject managementObject)
        {
            // Creating a dynamic object to store the properties of the ManagementBaseObject
            dynamic expandoObject = new ExpandoObject();

            IDictionary<string, object> dictionary = expandoObject;

            foreach (PropertyData property in managementObject.Properties)
            {
                if (property.Type == CimType.DateTime && property.Value is string dmtfTime)
                {
                    dictionary[property.Name] = ConvertDmtfToDateTime(dmtfTime);
                }
                else
                {
                    dictionary[property.Name] = property.Value;
                }
            }

            return expandoObject;
        }

        // Convert DMTF datetime format to DateTime
        private static DateTime ConvertDmtfToDateTime(string dmtfTime)
        {
            // DMTF datetime format: yyyymmddHHMMSS.mmmmmmsUUU
            if (ManagementDateTimeConverter.ToDateTime(dmtfTime) is DateTime dateTime)
            {
                return dateTime;
            }

            throw new FormatException($"Invalid DMTF datetime format: {dmtfTime}");
        }


        /// <summary>
        /// The Set-MpPreference and Add-MpPreference commands but implemented from scratch for the Harden Windows Security application
        /// </summary>
        /// <typeparam name="T">The type of the value to set the Microsoft Defender feature to</typeparam>
        /// <param name="preferenceName">The name of the Microsoft Defender feature to configure</param>
        /// <param name="preferenceValue">The value to set the Microsoft Defender feature to</param>
        /// <param name="Set">Bool. If true, Set will be used, if false, Add will be used.</param>
        internal static void ManageMpPreference<T>(string preferenceName, T preferenceValue, bool Set)
        {

            // The name of the method
            string MethodName = Set ? "Set" : "Add";

            try
            {
                // Connect to the WMI namespace
                ManagementScope scope = new(@"\\.\ROOT\Microsoft\Windows\Defender");
                scope.Connect();

                // Create an instance of the MSFT_MpPreference class
                using ManagementClass mpPreferenceClass = new(scope, new ManagementPath("MSFT_MpPreference"), null);

                // Get the available methods for the class
                ManagementBaseObject methodParams = mpPreferenceClass.GetMethodParameters(MethodName);

                if (preferenceValue is null)
                {
                    throw new ArgumentNullException(nameof(preferenceValue));
                }

                // Set the preference based on the type T
                if (typeof(T) == typeof(string))
                {
                    methodParams[preferenceName] = (string)(object)preferenceValue;
                }
                else if (typeof(T) == typeof(bool))
                {
                    methodParams[preferenceName] = (bool)(object)preferenceValue;
                }
                else if (typeof(T) == typeof(int))
                {
                    methodParams[preferenceName] = (int)(object)preferenceValue;
                }
                else if (typeof(T) == typeof(double))
                {
                    methodParams[preferenceName] = (double)(object)preferenceValue;
                }
                else if (typeof(T) == typeof(float))
                {
                    methodParams[preferenceName] = (float)(object)preferenceValue;
                }
                else if (typeof(T) == typeof(string[]))
                {
                    methodParams[preferenceName] = (string[])(object)preferenceValue;
                }
                else if (typeof(T) == typeof(byte))
                {
                    methodParams[preferenceName] = (byte)(object)preferenceValue;
                }
                else if (typeof(T) == typeof(ushort))
                {
                    methodParams[preferenceName] = (ushort)(object)preferenceValue;
                }
                else
                {
                    throw new ArgumentException($"Unsupported type {typeof(T)} for preference value");
                }

                // Invoke the method to apply the settings
                _ = mpPreferenceClass.InvokeMethod(MethodName, methodParams, null);

                Logger.LogMessage($"{preferenceName} set to {preferenceValue} (Type: {typeof(T).Name}) successfully.", LogTypeIntel.Information);
            }
            catch (Exception ex)
            {
                Logger.LogMessage($"Error setting {preferenceName}: {ex.Message}- You might need to update your OS first.", LogTypeIntel.Warning);
            }
        }
    }
}
