Function Write-FinalOutput ([System.IO.FileInfo[]]$Paths) {
    # Writes the final output of some cmdlets
    foreach ($Path in $Paths) {
        Write-ColorfulTextWDACConfig -Color Lavender -InputText "The file '$($Path.Name)' has been saved in '$(([WDACConfig.GlobalVars]::UserConfigDir))'"
    }
}