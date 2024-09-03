using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Linq;

#nullable enable

namespace HardenWindowsSecurity
{
    internal class PowerShellExecutor
    {
        /// <summary>
        /// Runs a PowerShell script and displays verbose and normal output in real-time.
        /// </summary>
        /// <param name="script">PowerShell script to run</param>
        /// <param name="returnOutput">Indicates whether to return the output of the script</param>
        /// <returns>The output of the PowerShell script if returnOutput is true; otherwise, nothing is returned</returns>
        /// <exception cref="InvalidOperationException">Thrown when the PowerShell script execution results in errors.</exception>
        internal static string? ExecuteScript(string script, bool returnOutput = false)
        {
            using (PowerShell psInstance = PowerShell.Create())
            {
                // Set the execution policy to Bypass for the current process
                psInstance.AddScript("Set-ExecutionPolicy Bypass -Scope Process -Force");
                psInstance.AddScript(script);

                // Prepare to capture output if requested
                PSDataCollection<PSObject>? outputCollection = null;
                if (returnOutput)
                {
                    outputCollection = new PSDataCollection<PSObject>();
                    outputCollection.DataAdded += (sender, args) =>
                    {
                        if (sender != null)
                        {
                            var outputStream = (PSDataCollection<PSObject>)sender;
                            var output = outputStream[args.Index]?.ToString();
                            HardenWindowsSecurity.Logger.LogMessage($"Output: {output}", LogTypeIntel.Information);
                        }
                    };
                }

                // Handle verbose output
                psInstance.Streams.Verbose.DataAdded += (sender, args) =>
                {
                    if (sender != null)
                    {
                        var verboseStream = (PSDataCollection<VerboseRecord>)sender;
                        HardenWindowsSecurity.Logger.LogMessage($"Verbose: {verboseStream[args.Index].Message}", LogTypeIntel.Information);
                    }
                };

                // Handle warning output
                psInstance.Streams.Warning.DataAdded += (sender, args) =>
                {
                    if (sender != null)
                    {
                        var warningStream = (PSDataCollection<WarningRecord>)sender;
                        HardenWindowsSecurity.Logger.LogMessage($"Warning: {warningStream[args.Index].Message}", LogTypeIntel.Warning);
                    }
                };

                // Handle error output and throw exception
                psInstance.Streams.Error.DataAdded += (sender, args) =>
                {
                    if (sender != null)
                    {
                        var errorStream = (PSDataCollection<ErrorRecord>)sender;
                        var error = errorStream[args.Index];
                        var errorMessage = $"Error: {error.Exception.Message}\n" +
                                           $"Category: {error.CategoryInfo.Category}\n" +
                                           $"Target: {error.TargetObject}\n" +
                                           $"Script StackTrace: {error.ScriptStackTrace}\n" +
                                           $"Exception Type: {error.Exception.GetType().FullName}\n" +
                                           $"StackTrace: {error.Exception.StackTrace}";

                        HardenWindowsSecurity.Logger.LogMessage(errorMessage, LogTypeIntel.Error);

                        // Throw an exception with the error details
                        throw new InvalidOperationException($"PowerShell script execution failed: {errorMessage}");
                    }
                };

                /*
                    // Handle progress updates
                    psInstance.Streams.Progress.DataAdded += (sender, args) =>
                    {
                        if (sender != null)
                        {
                            var progressStream = (PSDataCollection<ProgressRecord>)sender;
                            var progress = progressStream[args.Index];
                            HardenWindowsSecurity.Logger.LogMessage($"Progress: {progress.StatusDescription} - {progress.PercentComplete}% complete", LogTypeIntel.Information);
                        }
                    };
                */

                // Execute the script
                if (returnOutput)
                {
                    // Use Invoke to run the script and collect output
                    var results = psInstance.Invoke<PSObject>();
                    return results.Any() ? results.FirstOrDefault()?.ToString() : null;
                }
                else
                {
                    psInstance.Invoke();
                }

                return null;
            }
        }
    }
}
