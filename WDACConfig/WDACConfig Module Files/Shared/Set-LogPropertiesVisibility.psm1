Function Set-LogPropertiesVisibility {
    <#
    .SYNOPSIS
    Sets the properties to be visible in the output of the Out-GridView cmdlet.
    .PARAMETER LogType
        The type of log file to be displayed.
    .PARAMETER EventsToDisplay
        The event objects whose properties visibility are to be configured.
    .INPUTS
        PSCustomObject[]
        System.String
    .OUTPUTS
        System.Void
    #>
    [CmdletBinding()]
    [OutputType([System.Void])]
    Param (
        [ValidateSet('Evtx/Local', 'MDEAH')]
        [Parameter(Mandatory = $true)][System.String]$LogType,
        [Parameter(Mandatory = $true)][PSCustomObject[]]$EventsToDisplay
    )
    Begin {
        Switch ($LogType) {
            'Evtx/Local' {
                [System.String[]]$PropertiesToDisplay = @('TimeCreated', 'File Name', 'Full Path', 'Process Name', 'ProductName', 'OriginalFileName', 'InternalName', 'PackageFamilyName', 'FileVersion', 'Publishers', 'PolicyName', 'SI Signing Scenario')
            }
            'MDEAH' {
                [System.String[]]$PropertiesToDisplay = @('TimeStamp', 'DeviceName', 'FileName', 'FolderPath', 'InitiatingProcessFileName', 'SignatureStatus', 'PolicyName', 'OriginalFileName', 'InternalName', 'PackageFamilyName', 'FileVersion', 'Type', 'SISigningScenario')
            }
        }
    }
    Process {
        # Create a PSPropertySet object that contains the names of the properties to be visible
        # Used for Out-GridView display
        # https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.pspropertyset
        # https://learn.microsoft.com/en-us/powershell/scripting/learn/deep-dives/everything-about-pscustomobject#using-defaultpropertyset-the-long-way
        $Visible = [System.Management.Automation.PSPropertySet]::new(
            'DefaultDisplayPropertySet', # the name of the property set
            $PropertiesToDisplay # the names of the properties to be visible
        )

        # Add the PSPropertySet object to the PSStandardMembers member set of each element of the $EventsToDisplay array
        foreach ($Element in $EventsToDisplay) {
            $Element | Add-Member -MemberType 'MemberSet' -Name 'PSStandardMembers' -Value $Visible
        }
    }
}
Export-ModuleMember -Function 'Set-LogPropertiesVisibility'
