Function Invoke-WDACSimulation {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)][string]$XmlFilePath,
        [ArgumentCompleter([WDACConfig.ArgCompleter.FolderPicker])]
        [Parameter(Mandatory = $false)][string[]]$FolderPath,
        [ArgumentCompleter([WDACConfig.ArgCompleter.MultipleAnyFilePathsPicker])]
        [Parameter(Mandatory = $false)][string[]]$FilePath,
        [Parameter(Mandatory = $false)][switch]$CSVOutput,
        [Parameter(Mandatory = $false)][switch]$NoCatalogScanning,
        [ArgumentCompleter([WDACConfig.ArgCompleter.FolderPicker])]
        [Parameter(Mandatory = $false)][string[]]$CatRootPath,
        [Parameter(Mandatory = $false)][System.UInt32]$ThreadsCount
    )
    Write-Host -ForegroundColor Green -Object "This function's job has been completely added to the new AppControl Manager app. It offers a complete graphical user interface (GUI) for easy usage. Please refer to this GitHub page to see how to install and use it:`nhttps://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager"
}