using System;
using System.Collections.Generic;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class MDMClassProcessor
    {
        /// [System.Collections.Generic.Dictionary[string, [System.Collections.Generic.List[System.Collections.Generic.Dictionary[string, object]]]]]$Output = [HardenWindowsSecurity.MDM]::Get()
        /// class Result {
        ///     [string]$Name
        ///     [string]$Value
        ///     [string]$CimInstance
        ///
        ///     Result([string]$Name, [string]$Value, [string]$CimInstance) {
        ///         $this.Name = $Name
        ///         $this.Value = $Value
        ///         $this.CimInstance = $CimInstance
        ///     }
        /// }
        ///
        /// $ResultsList = [System.Collections.Generic.List[Result]]::new()
        ///
        /// foreach ($CimInstanceResult in $Output.GetEnumerator()) {
        ///
        ///     try {
        ///         # 2 GetEnumerator is necessary otherwise there won't be expected results
        ///         foreach ($Key in $CimInstanceResult.Value.GetEnumerator().GetEnumerator()) {
        ///
        ///             # Precise type of the $Key variable at this point is this
        ///             [System.Collections.Generic.KeyValuePair`2[[System.String], [System.Object]]]$Key = $Key
        ///
        ///             if ($Key.key -in ('Class', 'InstanceID', 'ParentID')) {
        ///                 continue
        ///             }
        ///             $ResultsList.Add([Result]::New(
        ///                     $Key.Key,
        ///                     $Key.Value,
        ///                     $CimInstanceResult.Key
        ///                 ))
        ///         }
        ///     }
        ///     catch {
        ///         Write-Host $_.Exception.Message
        ///     }
        /// }
        /// $ResultsList | Out-GridView -Title "$($ResultsList.Count)"
        /// Above is the PowerShell equivalent of the method below
        /// It gets the results of all of the MDM related CimInstances and processes them into a list of MDMClassProcessor objects
        public static List<MDMClassProcessor> Process()
        {
            // Get the results of all of the Intune policies from the system
            var output = MDM.Get();

            // Create a list to store the processed results and return at the end
            List<MDMClassProcessor> resultsList = [];

            // Loop over each data
            foreach (var cimInstanceResult in output)
            {
                try
                {
                    foreach (var dictionary in cimInstanceResult.Value)
                    {
                        foreach (var keyValuePair in dictionary)
                        {
                            // Filter out the items we don't need using ordinal, case-insensitive comparison
                            if (String.Equals(keyValuePair.Key, "Class", StringComparison.OrdinalIgnoreCase) ||
                                String.Equals(keyValuePair.Key, "InstanceID", StringComparison.OrdinalIgnoreCase) ||
                                String.Equals(keyValuePair.Key, "ParentID", StringComparison.OrdinalIgnoreCase))
                            {
                                continue;
                            }

                            // Add the data to the list
                            resultsList.Add(new MDMClassProcessor(
                                keyValuePair.Key,
                                keyValuePair.Value?.ToString() ?? string.Empty,
                                cimInstanceResult.Key
                            ));
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogMessage(ex.Message, LogTypeIntel.Error);
                }
            }

            return resultsList;
        }
    }
}
