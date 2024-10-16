using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Globalization;
using System.Linq;
using System.Management;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class MpPreferenceHelper
    {
        // Get the MpPreference from the MSFT_MpPreference WMI class and returns it as a dynamic object
        public static dynamic GetMpPreference()
        {
            try
            {
                // Defining the WMI query to retrieve the MpPreference
                string namespaceName = "ROOT\\Microsoft\\Windows\\Defender";
                string className = "MSFT_MpPreference";
                string queryString = $"SELECT * FROM {className}";

                // Execute the query
                using ManagementObjectSearcher searcher = new(namespaceName, queryString);

                ManagementObjectCollection results = searcher.Get();

                // Return the first result if there are any
                if (results.Count > 0)
                {
                    var result = results.Cast<ManagementBaseObject>().FirstOrDefault();

                    if (result is not null)
                    {

                        return ConvertToDynamic(result);
                    }
                    else
                    {
                        throw new InvalidOperationException("Failed to get MpComputerPreference");
                    }
                }
                else
                {
                    throw new InvalidOperationException("Failed to get MpComputerPreference");
                }
            }
            catch (ManagementException ex)
            {
                string errorMessage = $"WMI query for 'MSFT_MpPreference' failed: {ex.Message}";
                throw new HardenWindowsSecurity.PowerShellExecutionException(errorMessage, ex);
            }
        }

        // Convert the ManagementBaseObject to a dynamic object
        private static dynamic ConvertToDynamic(ManagementBaseObject managementObject)
        {
            // Creating a dynamic object to store the properties of the ManagementBaseObject
            dynamic expandoObject = new ExpandoObject();
            var dictionary = (IDictionary<string, object>)expandoObject;

            // Iterating through the properties of the ManagementBaseObject and adding them to the dynamic object
            foreach (var property in managementObject.Properties)
            {
                // Check if the value of the property is in DMTF datetime format
                // Properties such as SignatureScheduleTime use that format
                if (property.Type == CimType.DateTime && property.Value is string dmtfTime)
                {
                    // Convert DMTF datetime format to TimeSpan
                    dictionary[property.Name] = ConvertDmtfToTimeSpan(dmtfTime);
                }
                else
                {
                    // Add the property to the dynamic object as is if it's not DMTF
                    dictionary[property.Name] = property.Value;
                }
            }

            return expandoObject;
        }

        private static TimeSpan ConvertDmtfToTimeSpan(string dmtfTime)
        {
            // DMTF datetime format: yyyymmddHHMMSS.mmmmmmsUUU
            // We only need HHMMSS part for this case
            if (dmtfTime.Length >= 15)
            {
                string hhmmss = dmtfTime.Substring(8, 6);
                if (TimeSpan.TryParseExact(hhmmss, "HHmmss", CultureInfo.InvariantCulture, out TimeSpan timeSpan))
                {
                    return timeSpan;
                }
            }
            return TimeSpan.Zero;
        }
    }
}
