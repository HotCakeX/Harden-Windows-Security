using System;
using System.Collections.ObjectModel;
using System.Management.Automation;
using System.Linq;

namespace HardeningModule
{
    public static class MpPreferenceHelper
    {
        public static dynamic GetMpPreference()
        {
            using (PowerShell ps = PowerShell.Create())
            {
                ps.AddCommand("Get-MpPreference");
                var results = ps.Invoke();

                // Check for errors
                if (ps.HadErrors)
                {
                    var errorRecord = ps.Streams.Error.ReadAll().FirstOrDefault();
                    if (errorRecord != null)
                    {
                        string errorMessage = $"PowerShell command 'Get-MpPreference' failed: {errorRecord.Exception.Message}";
                        throw new PowerShellExecutionException(errorMessage, errorRecord.Exception);
                    }
                }

                // Return the result if there are any
                if (results.Count > 0)
                {
                    return results[0];
                }
                else
                {
                    return null;
                }
            }
        }
    }

    // Custom exception class for PowerShell execution errors
    public class PowerShellExecutionException : Exception
    {
        public PowerShellExecutionException(string message) : base(message)
        {
        }

        public PowerShellExecutionException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
