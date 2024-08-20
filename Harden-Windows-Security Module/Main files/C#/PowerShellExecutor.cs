using System;
using System.Management.Automation;
using System.Linq;

#nullable enable

namespace HardenWindowsSecurity
{
    public class PowerShellExecutor
    {
        /// <summary>
        /// Runs a PowerShell script and displays verbose and normal output.
        /// </summary>
        /// <param name="script">PowerShell script to run</param>
        public static void ExecuteScript(string script)
        {
            using (PowerShell psInstance = PowerShell.Create())
            {
                // Set the execution policy to Bypass for the current process
                psInstance.AddScript("Set-ExecutionPolicy Bypass -Scope Process -Force");
            //    psInstance.AddScript("$verbosePreference = 'continue'");
                psInstance.AddScript(script);

                // Execute the script and capture the output
                var results = psInstance.Invoke();

                // Display normal output
                foreach (var output in results)
                {
                    HardenWindowsSecurity.Logger.LogMessage($"Output: {output}");
                }

                // Display verbose output
                foreach (var verbose in psInstance.Streams.Verbose)
                {
                    HardenWindowsSecurity.Logger.LogMessage($"Verbose: {verbose.Message}");
                }

                // Display warning output
                foreach (var warning in psInstance.Streams.Warning)
                {
                    HardenWindowsSecurity.Logger.LogMessage($"Warning: {warning.Message}");
                }

                // Handle errors, including non-terminating errors
                if (psInstance.Streams.Error.Count > 0)
                {
                    var errorDetails = psInstance.Streams.Error.Select(e =>
                        $"Error: {e.Exception.Message}\n" +
                        $"Category: {e.CategoryInfo.Category}\n" +
                        $"Target: {e.TargetObject}\n" +
                        $"Script StackTrace: {e.ScriptStackTrace}\n" +
                        $"Exception Type: {e.Exception.GetType().FullName}\n" +
                        $"StackTrace: {e.Exception.StackTrace}"
                    );

                    string errorMessage = string.Join(Environment.NewLine, errorDetails);
                    throw new InvalidOperationException($"PowerShell script execution failed: {errorMessage}");
                }
            }
        }
    }
}
