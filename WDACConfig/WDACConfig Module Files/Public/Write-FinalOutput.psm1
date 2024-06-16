Function Write-FinalOutput {
    <#
    .SYNOPSIS
        Writes the final output of some cmdlets
    #>
    Param ([System.IO.FileInfo[]]$Paths)
    Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force
    foreach ($Path in $Paths) {
        Write-ColorfulText -Color Lavender -InputText "The file '$($Path.Name)' has been saved in '$UserConfigDir'"
    }
}
Export-ModuleMember -Function 'Write-FinalOutput'
