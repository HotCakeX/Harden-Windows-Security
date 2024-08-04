Function ConvertTo-HashtableArray ([PSCustomObject[]]$PSCustomObjectArray) {
    [System.Collections.Hashtable[]]$SelectedLogsHashtables = foreach ($PSObjectData in $PSCustomObjectArray) {
        [System.Collections.Hashtable]$LocalHashtable = @{}
        foreach ($ItemProperty in $PSObjectData.PSObject.Properties) {
            if ($ItemProperty.Name -eq 'CorrelatedEventsData') {
                [System.Collections.Hashtable]$CorrelatedEventsDataHashtable = @{}
                foreach ($SubItemProperty in $ItemProperty.Value.GetEnumerator()) {
                    $CorrelatedEventsDataHashtable[$SubItemProperty.Name] = [System.Collections.Hashtable]$SubItemProperty.Value
                }
                $LocalHashtable[$ItemProperty.Name] = $CorrelatedEventsDataHashtable
            }
            elseif ($ItemProperty.Name -eq 'SignerInfo') {
                [System.Collections.Hashtable]$SignerInfo = @{}
                foreach ($SubItemProperty in $ItemProperty.Value.GetEnumerator()) {
                    $SignerInfo[$SubItemProperty.Name] = [System.Collections.Hashtable]$SubItemProperty.Value
                }
                $LocalHashtable[$ItemProperty.Name] = $SignerInfo
            }
            else {
                $LocalHashtable[$ItemProperty.Name] = $ItemProperty.Value
            }
        }
        $LocalHashtable
    }
    return $SelectedLogsHashtables
}