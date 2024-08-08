using System;
using System.Linq;
using System.Management;
using System.Dynamic;
using System.Globalization;
using System.Collections.Generic;
using System.Collections;

namespace HardenWindowsSecurity
{
    public static class MpComputerStatusHelper
    {
        // Get the MpComputerStatus from the MSFT_MpComputerStatus WMI class and returns it as a dynamic object
        public static dynamic GetMpComputerStatus()
        {
            try
            {
                // Define the WMI query to retrieve the MpComputerStatus
                string namespaceName = "ROOT\\Microsoft\\Windows\\Defender";
                string className = "MSFT_MpComputerStatus";
                string queryString = $"SELECT * FROM {className}";

                // Execute the query
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(namespaceName, queryString);
                ManagementObjectCollection results = searcher.Get();

                // Make sure the results isn't empty
                if (results.Count > 0)
                {
                    var result = results.Cast<ManagementBaseObject>().FirstOrDefault();

                    if (result != null)
                    {

                        return ConvertToDynamic(result);
                    }
                    else
                    {
                        throw new Exception("Failed to get MpComputerStatus!");
                    }
                }
                else
                {
                    throw new HardenWindowsSecurity.PowerShellExecutionException("WMI query for 'MSFT_MpComputerStatus' failed");
                }
            }
            catch (ManagementException ex)
            {
                string errorMessage = $"WMI query for 'MSFT_MpComputerStatus' failed: {ex.Message}";
                throw new HardenWindowsSecurity.PowerShellExecutionException(errorMessage, ex);
            }
        }

        // Convert the ManagementBaseObject to a dynamic object
        private static dynamic ConvertToDynamic(ManagementBaseObject managementObject)
        {
            // Creating a dynamic object to store the properties of the ManagementBaseObject
            dynamic expandoObject = new ExpandoObject();
            var dictionary = (IDictionary<string, object>)expandoObject;

            foreach (var property in managementObject.Properties)
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
    }
}
