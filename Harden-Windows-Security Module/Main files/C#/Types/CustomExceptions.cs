using System;

namespace HardeningModule
{
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