using System;

#nullable enable

namespace HardenWindowsSecurity
{
    // Custom exception class for PowerShell execution errors
    public sealed class PowerShellExecutionException : Exception
    {
        public PowerShellExecutionException(string message) : base(message)
        {
        }

        public PowerShellExecutionException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}