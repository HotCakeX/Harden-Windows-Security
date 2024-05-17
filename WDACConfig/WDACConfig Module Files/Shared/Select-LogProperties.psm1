Function Select-LogProperties {
    <#
    .SYNOPSIS
        Selects, processes and sorts the properties for the Code Integrity and AppLocker logs.
    #>
    Param (
        [PSCustomObject[]]$Logs
    )
    Return $Logs | Select-Object -Property @{
        Label      = 'File Name'
        Expression = {
            # Can't use Get-Item or Get-ChildItem because the file might not exist on the disk
            # Can't use Split-Path -LiteralPath with -Leaf parameter because not supported
            [System.String]$TempPath = Split-Path -LiteralPath $_.'File Name'
            $_.'File Name'.Replace($TempPath, '').TrimStart('\')
        }
    },
    'TimeCreated',
    'PolicyName',
    'ProductName',
    'FileVersion',
    'OriginalFileName',
    'FileDescription',
    'InternalName',
    'PackageFamilyName',
    @{
        Label      = 'Full Path'
        Expression = { $_.'File Name' }
    },
    'Validated Signing Level',
    'Requested Signing Level',
    'SI Signing Scenario',
    'UserId',
    @{
        Label      = 'Publishers'
        Expression = { [System.String[]]$_.'Publishers' }
    },
    'SHA256 Hash',
    'SHA256 Flat Hash',
    'SHA1 Hash',
    'SHA1 Flat Hash',
    'PolicyGUID',
    'PolicyHash',
    'ActivityId',
    'Process Name',
    'UserWriteable',
    'PolicyID',
    'Status',
    'USN',
    'SignatureStatus',
    'SignerInfo' | Sort-Object -Property TimeCreated -Descending
}
Export-ModuleMember -Function 'Select-LogProperties'
