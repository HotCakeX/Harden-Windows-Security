Function ConvertTo-HashtableArray ([PSCustomObject[]]$PSCustomObjectArray) {
    # Convert the [PSCustomObject[]] to System.Collections.Hashtable[]] before processing it further
    [System.Collections.Hashtable[]]$SelectedLogsHashtables = foreach ($PSObjectData in $PSCustomObjectArray) {
        [System.Collections.Hashtable]$LocalHashtable = @{}
        foreach ($ItemProperty in $PSObjectData.PSObject.Properties) {
            $LocalHashtable[$ItemProperty.Name] = $ItemProperty.Value
        }
        $LocalHashtable
    }
    return $SelectedLogsHashtables
}