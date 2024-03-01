Function New-StagingArea {
    <#
    .SYNOPSIS
        Creates a staging area for a cmdlet to store temporary files
    .PARAMETER CmdletName
        The name of the cmdlet for which the staging area is created
    .INPUTS
        System.String
    .OUTPUTS
        System.IO.DirectoryInfo
    #>
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][System.String]$CmdletName
    )
    # Define a staging area for the cmdlet
    [System.IO.DirectoryInfo]$StagingArea = Join-Path -Path $UserConfigDir -ChildPath 'StagingArea' -AdditionalChildPath $CmdletName

    # Delete it if it already exists with possible content from previous runs
    if (Test-Path -PathType Container -LiteralPath $StagingArea) {
        Remove-Item -LiteralPath $StagingArea -Recurse -Force
    }
    # Create the staging area for the cmdlet
    New-Item -Path $StagingArea -ItemType Directory -Force | Out-Null
    return $StagingArea
}
Export-ModuleMember -Function 'New-StagingArea'
