using System;
using System.Runtime.InteropServices;

#nullable enable

namespace HardenWindowsSecurity
{
    internal static class HResultHelper
    {
        /// <summary>
        /// Converts the given HRESULT to a corresponding .NET Exception and writes the full error message to the console.
        /// If the provided HRESULT is null, it will default to 0 and gracefully handle the case by writing that no specific exception was found.
        /// </summary>
        /// <param name="hresult">An unsigned 32-bit integer representing the HRESULT. If null, it defaults to 0.</param>
        public static void HandleHresultAndLog(uint? hresult)
        {
            // If the nullable HRESULT is null, assign it a default value of 0
            // If null is passed, it is treated as HRESULT 0, which corresponds to success (S_OK)
            uint actualHresult = hresult ?? 0;

            // Convert the HRESULT to signed form, as GetExceptionForHR expects a signed 32-bit integer
            int signedHresult = unchecked((int)actualHresult);

            // Get the Exception corresponding to the HRESULT
            Exception? exception = Marshal.GetExceptionForHR(signedHresult);

            // If an exception is found, log the message. If not, indicate no specific exception exists for the HRESULT
            if (exception is not null)
            {
                Logger.LogMessage($"{exception.Message}", LogTypeIntel.ErrorInteractionRequired);
            }
            else
            {
                // Gracefully handle HRESULT 0 or unknown HRESULTs by logging a default message
                Logger.LogMessage($"HRESULT: 0x{actualHresult:X} - No specific exception found for this HRESULT.", LogTypeIntel.ErrorInteractionRequired);
            }

            // Mark this flag as true indicating an error occurred
            BitLocker.HasErrorsOccurred = true;
        }
    }
}
