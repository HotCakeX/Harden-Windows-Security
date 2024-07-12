using System;
using System.Linq;
using System.Management;
using System.Collections.Generic;
using System.Globalization;

namespace HardeningModule
{
    public static class MpComputerStatusHelper
    {
        // Get the MpComputerStatus from the MSFT_MpComputerStatus WMI class and returns it as a dictionary
        public static Dictionary<string, object> GetMpComputerStatus()
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

                // Return the first result if there are any
                if (results.Count > 0)
                {
                    var result = results.Cast<ManagementBaseObject>().FirstOrDefault();
                    return ConvertToDictionary(result);
                }
                else
                {
                    return null;
                }
            }
            catch (ManagementException ex)
            {
                string errorMessage = $"WMI query for 'MSFT_MpComputerStatus' failed: {ex.Message}";
                throw new HardeningModule.PowerShellExecutionException(errorMessage, ex);
            }
        }

        // Convert the ManagementBaseObject to a dictionary
        private static Dictionary<string, object> ConvertToDictionary(ManagementBaseObject managementObject)
        {
            Dictionary<string, object> dictionary = new Dictionary<string, object>();

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

            return dictionary;
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
